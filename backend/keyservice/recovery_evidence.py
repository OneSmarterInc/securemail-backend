"""Verify separately signed backup receipt and clean-machine restore evidence.

Trust keys and host identities are provisioned independently by operators. A
signature authenticates that issuer's statement, not physical host placement.
The key service deliberately contains no receipt/drill signing operation.
"""

import hashlib
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import protocol as p

DOMAIN = b"onesmarter:recovery-evidence:v1\0"


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_evidence(path: Path, backup: Path, root_id: str) -> dict:
    trust_path = os.environ.get("KEY_SERVICE_RECOVERY_TRUST", "")
    if not trust_path:
        raise ValueError("Independent recovery-evidence trust configuration is required")
    if path.stat().st_size > 16384 or Path(trust_path).stat().st_size > 16384:
        raise ValueError("Recovery evidence/configuration too large")
    trust = p.parse_object(Path(trust_path).read_bytes())
    bundle = p.parse_object(path.read_bytes())
    if set(bundle) != {"receipt", "restore"}:
        raise ValueError("Both remote-copy and clean-machine restore proof are required")
    records = {}
    publics = []
    now = int(time.time())
    for kind, name in (("off_host_backup", "receipt"), ("clean_machine_restore", "restore")):
        packet = bundle[name]
        if not isinstance(packet, dict) or set(packet) != {"record", "signature", "issuer"}:
            raise ValueError("Invalid recovery evidence packet")
        identity = trust["issuers"][packet["issuer"]]
        if identity["kind"] != kind:
            raise ValueError("Wrong recovery-evidence issuer role")
        public = p.decode(identity["public"], 32)
        publics.append(public)
        record = packet["record"]
        Ed25519PublicKey.from_public_bytes(public).verify(
            p.decode(packet["signature"], 64), DOMAIN + p.canonical(record)
        )
        common = {
            "v",
            "kind",
            "root_id",
            "backup_sha256",
            "backup_id",
            "source_host_id",
            "receiver_id",
            "issued_at",
            "expires_at",
        }
        fields = common | (
            {"restore_host_id", "restore_id", "documents_verified"} if name == "restore" else set()
        )
        if (
            set(record) != fields
            or type(record["v"]) is not int
            or record["v"] != 1
            or record["kind"] != kind
        ):
            raise ValueError("Invalid recovery-evidence fields")
        if record["root_id"] != root_id or record["source_host_id"] != trust["key_host_id"]:
            raise ValueError("Recovery evidence belongs to another root or host")
        if (
            record["receiver_id"] != trust["receiver_id"]
            or record["receiver_id"] == trust["key_host_id"]
        ):
            raise ValueError("Backup receiver must be independently provisioned off-host")
        if (
            type(record["issued_at"]) is not int
            or type(record["expires_at"]) is not int
            or not record["issued_at"] <= now < record["expires_at"]
        ):
            raise ValueError("Recovery evidence is expired or not yet valid")
        if not isinstance(record["backup_id"], str) or not record["backup_id"]:
            raise ValueError("Remote immutable backup identifier required")
        records[name] = record
    if publics[0] == publics[1]:
        raise ValueError(
            "Backup receiver and restore verifier must use separate signing identities"
        )
    receipt, restored = records["receipt"], records["restore"]
    for field in ("root_id", "backup_sha256", "backup_id", "source_host_id", "receiver_id"):
        if receipt[field] != restored[field]:
            raise ValueError("Receipt and restore evidence refer to different backups")
    if restored["restore_host_id"] not in trust["restore_host_ids"] or restored[
        "restore_host_id"
    ] in {trust["key_host_id"], trust["receiver_id"]}:
        raise ValueError("A separately provisioned clean-machine restore is required")
    if (
        not isinstance(restored["restore_id"], str)
        or not restored["restore_id"]
        or type(restored["documents_verified"]) is not int
        or restored["documents_verified"] < 1
    ):
        raise ValueError("Confirmed restore ID and successful document checks required")
    if (
        restored["issued_at"] < receipt["issued_at"]
        or file_digest(backup) != receipt["backup_sha256"]
    ):
        raise ValueError("Backup digest or recovery-evidence ordering mismatch")
    return {
        "bundle_sha256": file_digest(path),
        "backup_sha256": receipt["backup_sha256"],
        "backup_id": receipt["backup_id"],
        "restore_id": restored["restore_id"],
        "receiver_id": receipt["receiver_id"],
        "restore_host_id": restored["restore_host_id"],
    }
