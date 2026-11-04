"""Offline initialization/backup and sealed service startup. No secret CLI arguments."""

import argparse
import getpass
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from . import protocol as p
from .server import Server, Service, tls_context
from .store import KeyStore, synthetic_import_enabled


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--store", type=Path, required=True)
    init.add_argument("--recovery-file", type=Path)
    init.add_argument("--allow-local-recovery-synthetic", action="store_true")
    init.add_argument("--candidate-enrollment", type=Path)
    migrate = commands.add_parser("migrate-audit-candidate")
    migrate.add_argument("--source", type=Path, required=True)
    migrate.add_argument("--store", type=Path, required=True)
    migrate.add_argument("--backup-directory", type=Path, required=True)
    migrate.add_argument("--trusted-checkpoint", type=Path, required=True)
    migrate.add_argument("--enrollment", type=Path, required=True)
    audit_rotate = commands.add_parser("rotate-audit-key")
    audit_rotate.add_argument("--store", type=Path, required=True)
    audit_rotate.add_argument("--backup-directory", type=Path, required=True)
    enrollment = commands.add_parser("candidate-enrollment")
    enrollment.add_argument("--store", type=Path, required=True)
    enrollment.add_argument("--destination", type=Path, required=True)
    restore = commands.add_parser("restore")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--trusted-checkpoint", type=Path)
    restore.add_argument("--reconcile-candidate-pending", action="store_true")
    checkpoint = commands.add_parser("checkpoint")
    checkpoint.add_argument("--store", type=Path, required=True)
    checkpoint.add_argument("--destination", type=Path, required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("--store", type=Path, required=True)
    backup.add_argument("--destination", type=Path, required=True)
    verify = commands.add_parser("verify-root-recovery")
    verify.add_argument("--store", type=Path, required=True)
    verify.add_argument("--backup-directory", type=Path, required=True)
    verify.add_argument("--destination", type=Path, required=True)
    verify.add_argument("--expected-root", required=True)
    verify.add_argument("--trusted-checkpoint", type=Path)
    verify.add_argument("--off-host-backup", type=Path)
    verify.add_argument("--recovery-evidence", type=Path)
    identity = commands.add_parser("identity")
    identity.add_argument("--policy", type=Path, required=True)
    identity.add_argument("--cert", type=Path, required=True)
    identity.add_argument("--name", required=True)
    identity.add_argument("--role", choices=["custodian", "workload", "maintenance"], required=True)
    identity.add_argument("--organization", action="append", default=[])
    identity.add_argument("--days", type=int, default=30)
    serve = commands.add_parser("serve")
    serve.add_argument("--store", type=Path, required=True)
    serve.add_argument("--trusted-checkpoint", type=Path)
    serve.add_argument("--backup-directory", type=Path, required=True)
    serve.add_argument("--policy", type=Path, required=True)
    serve.add_argument("--cert", required=True)
    serve.add_argument("--key", required=True)
    serve.add_argument("--ca", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8443)
    serve.add_argument("--origin", required=True)
    serve.add_argument("--synthetic-only", action="store_true", required=True)
    serve.add_argument("--allow-classical-synthetic", action="store_true")
    serve.add_argument("--allow-http-loopback-origin", action="store_true")
    args = parser.parse_args()
    if args.command == "serve":
        escape_flags = [
            flag
            for flag, enabled in (
                ("--allow-classical-synthetic", args.allow_classical_synthetic),
                ("--allow-http-loopback-origin", args.allow_http_loopback_origin),
            )
            if enabled
        ]
        if escape_flags:
            if not (
                os.environ.get("APP_ENV", "") in {"development", "test"}
                and os.environ.get("SYNTHETIC_MODE", "").lower() == "true"
            ):
                parser.error(
                    "Synthetic escape flags require APP_ENV=development or test "
                    "and SYNTHETIC_MODE=true: " + ", ".join(escape_flags)
                )
            print(
                "WARNING: Synthetic-only security exceptions enabled: "
                + ", ".join(escape_flags)
                + ". Never use real confidential data with these exceptions.",
                file=sys.stderr,
                flush=True,
            )
        if args.allow_http_loopback_origin and args.host not in {"127.0.0.1", "localhost"}:
            parser.error("HTTP development origins require a loopback-only service bind.")
        if os.environ.get("APP_ENV", "") not in {"development", "test"}:
            if not args.trusted_checkpoint:
                parser.error("--trusted-checkpoint is required outside synthetic environments")
            parser.error(
                "Non-synthetic key-service deployment remains blocked pending independent review; "
                "a checkpoint does not authorize production use"
            )
    candidate = os.environ.get("KEY_SERVICE_AUDIT_CANDIDATE", "").lower() == "true"
    store_type = KeyStore
    if candidate:
        from .candidate_audit import CandidateKeyStore
        from .checkpoints import require_candidate

        require_candidate()
        store_type = CandidateKeyStore
        print(
            "WARNING: Unapproved synthetic audit candidate selected; no production approval.",
            file=sys.stderr,
            flush=True,
        )
    if (
        args.command in {"migrate-audit-candidate", "rotate-audit-key", "candidate-enrollment"}
        and not candidate
    ):
        parser.error("This operation requires the explicit synthetic audit candidate flag")
    if (
        args.command in {"restore", "verify-root-recovery"}
        and not candidate
        and not args.trusted_checkpoint
    ):
        parser.error("--trusted-checkpoint is required for legacy recovery")
    if args.command == "init":
        if candidate and not args.candidate_enrollment:
            parser.error(
                "Candidate initialization requires --candidate-enrollment for offline registration"
            )
        if not candidate and args.candidate_enrollment:
            parser.error("Candidate enrollment requires the candidate flag")
        if args.allow_local_recovery_synthetic and not (
            os.environ.get("SYNTHETIC_MODE", "").lower() == "true"
            and os.environ.get("APP_ENV", "") in {"development", "test"}
        ):
            parser.error(
                "Local recovery requires SYNTHETIC_MODE=true and APP_ENV=development or test"
            )
        store = args.store.resolve()
        if store.exists():
            parser.error("Refusing to overwrite a store")
        if args.recovery_file:
            if not args.allow_local_recovery_synthetic:
                parser.error(
                    "Local recovery-file generation requires --allow-local-recovery-synthetic. Use off-host custody for the normal initialization flow."
                )
            recovery = args.recovery_file.resolve()
            if recovery.is_relative_to(store.parent) or recovery.exists():
                parser.error("Recovery path must be new and outside the store directory")
            secret = secrets.token_bytes(32)
            recovery.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(
                os.open(recovery, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                "w",
                encoding="ascii",
            ) as stream:
                stream.write(p.encode(secret))
            recovery.chmod(0o600)
        else:
            encoded = getpass.getpass(
                "Secret generated and retained in off-host custody (base64, 32 bytes): "
            )
            confirmation = getpass.getpass("Confirm off-host secret: ")
            if not secrets.compare_digest(encoded, confirmation):
                parser.error("Secret confirmation failed")
            secret = p.decode(encoded, 32)
        created = store_type.initialize(store, secret)
        if candidate:
            created.export_enrollment(args.candidate_enrollment)
        print("Initialized sealed store. Keep recovery custody independent of this host.")
    elif args.command == "migrate-audit-candidate":
        secret = p.decode(getpass.getpass("Off-host v1 recovery secret: "), 32)
        migrated = store_type.migrate(
            args.source,
            args.store,
            secret,
            trusted_checkpoint=args.trusted_checkpoint,
            backup_directory=args.backup_directory,
        )
        migrated.export_enrollment(args.enrollment)
        print("Candidate COPY created. Independently enroll and pin its identity before unseal.")
    elif args.command == "candidate-enrollment":
        store_type(args.store).export_enrollment(args.destination)
    elif args.command == "rotate-audit-key":
        from .ownership import StoreOwnership

        ownership = StoreOwnership(args.store)
        store = store_type(args.store, args.backup_directory)
        try:
            store.unseal(
                p.decode(getpass.getpass("Off-host recovery secret: "), 32), "offline-custodian"
            )
            print("Rotated candidate audit key:", store.rotate_audit_key("offline-custodian"))
        finally:
            try:
                store.seal("offline-custodian")
            finally:
                ownership.close()
    elif args.command == "restore":
        if args.reconcile_candidate_pending and not candidate:
            parser.error("Pending reconciliation requires the candidate flag")
        secret = p.decode(getpass.getpass("Off-host backup recovery secret: "), 32)
        store_type.restore(
            args.backup,
            args.destination,
            secret,
            trusted_checkpoint=args.trusted_checkpoint,
            **({"reconcile_pending": args.reconcile_candidate_pending} if candidate else {}),
        )
        print("Verified backup restored to a new SEALED store; original backup preserved.")
    elif args.command == "checkpoint":
        if candidate:
            parser.error(
                "Candidate checkpoints publish automatically; use the receiver's authenticated latest endpoint"
            )
        store_type(args.store).export_checkpoint(args.destination)
        print("Checkpoint exported. Verify and retain it outside the key host trust boundary.")
    elif args.command == "backup":
        store_type(args.store).backup(args.destination)
        print("Created encrypted SQLite backup. Retain its matching recovery secret separately.")
    elif args.command == "verify-root-recovery":
        secret = p.decode(getpass.getpass("New recovery secret retrieved from custody: "), 32)
        result = store_type(
            args.store, args.backup_directory, trusted_checkpoint=args.trusted_checkpoint
        ).verify_root_recovery(
            secret,
            args.expected_root,
            args.destination,
            "offline-custodian",
            off_host_backup=args.off_host_backup,
            recovery_evidence=args.recovery_evidence,
        )
        print(json.dumps(result))
    elif args.command == "identity":
        if not 1 <= args.days <= 90:
            parser.error("Identity validity must be between 1 and 90 days.")
        cert = x509.load_pem_x509_certificate(args.cert.read_bytes())
        fp = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
        policy = json.loads(args.policy.read_text()) if args.policy.exists() else {"identities": {}}
        if fp in policy["identities"]:
            parser.error("Identity already exists; review policy changes explicitly.")
        operations = {
            "custodian": ["custody-status", "unseal", "seal", "rotate-root"]
            + (["restore-candidate"] if candidate else []),
            "workload": ["status", "versions", "wrap", "unwrap", "rewrap"],
            "maintenance": ["status", "versions", "rotate"]
            + (["import"] if synthetic_import_enabled() else []),
        }[args.role]
        entry = {
            "name": args.name,
            "role": args.role,
            "operations": operations,
            "organizations": args.organization,
            "expires_at": time.time() + args.days * 86400,
        }
        policy["identities"][fp] = entry
        args.policy.parent.mkdir(parents=True, exist_ok=True)
        # Policy changes are offline operations; do not run concurrent policy writers.
        tmp = args.policy.with_suffix(".new")
        with os.fdopen(
            os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8"
        ) as stream:
            json.dump(policy, stream, indent=2)
        tmp.chmod(0o600)
        tmp.replace(args.policy)
        print("Identity registered. Policy is reloaded on every service request.")
        if args.role == "custodian":
            print(
                "Create individual human accounts separately with python manage.py custodian create; certificate identity alone cannot sign in."
            )
    else:
        store = store_type(
            args.store, args.backup_directory, trusted_checkpoint=args.trusted_checkpoint
        )
        service = Service(
            store, args.policy, args.origin, allow_http_loopback=args.allow_http_loopback_origin
        )
        with Server(
            (args.host, args.port),
            service,
            tls_context(args.cert, args.key, args.ca),
            require_pq=not args.allow_classical_synthetic,
        ) as server:
            print(
                "Synthetic key service started SEALED. Independent review/PQ deployment approval pending."
            )
            try:
                server.serve_forever()
            finally:
                store.seal("shutdown")


if __name__ == "__main__":
    main()
