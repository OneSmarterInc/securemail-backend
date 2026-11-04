"""Unapproved, synthetic-only RP-04/RP-05 candidate; never silently upgrades v1.

HMAC row authentication and independently pinned Ed25519 checkpoints. The
reference receiver and algorithm choices still require external review.
"""

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import protocol as p
from .checkpoints import (
    DOMAIN,
    ZERO,
    Publisher,
    configured_publisher,
    packet_hash,
    require_candidate,
    verify_packet,
)
from .ownership import StoreOwnership
from .store import KeyStore, SealedError, protect, recover

logger = logging.getLogger(__name__)
MAC_DOMAIN = b"onesmarter:keystore-audit:v2\0"


def meta_values(db) -> dict:
    return dict(db.execute("SELECT name,value FROM meta"))


def put_meta(db, name: str, value: str) -> None:
    db.execute(
        "INSERT INTO meta VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
        (name, value),
    )


def state_digest(db) -> str:
    """Bind protected key state, not just a replayable authentic audit history.

    Exclude volatile sealing state and self-referential checkpoint packets.
    Audit rows/spooled observations have their own explicit integrity rules.
    """
    excluded = {"seal_epoch", "candidate_genesis", "candidate_pending_checkpoint"}
    values = {
        "meta": sorted(
            (key, value) for key, value in meta_values(db).items() if key not in excluded
        )
    }
    for table, order in (
        ("versions", "id"),
        ("requests", "id"),
        ("mfa_current", "context"),
        ("current_deks", "context"),
    ):
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        # Table/order names above are fixed constants, never caller-controlled.
        values[table] = (
            [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY {order}")]
            if exists
            else None
        )
    return hashlib.sha256(b"onesmarter:keystore-state:v1\0" + p.canonical(values)).hexdigest()


def audit_aad(meta: dict, key_id: str, purpose: str = "audit-mac") -> bytes:
    return p.canonical({"purpose": purpose, "store_id": meta["store_id"], "key_id": key_id})


def row_mac(key: bytes, seq: int, digest: str, previous: str) -> str:
    return hmac.new(
        key,
        MAC_DOMAIN
        + str(seq).encode("ascii")
        + b"\0"
        + digest.encode("ascii")
        + b"\0"
        + previous.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


class CandidateKeyStore(KeyStore):
    def __init__(
        self,
        path: Path,
        backup_directory: Path | None = None,
        *,
        trusted_checkpoint: Path | None = None,
        publisher: Publisher | None = None,
    ):
        require_candidate()
        super().__init__(path, backup_directory, trusted_checkpoint=trusted_checkpoint)
        with closing(sqlite3.connect(path)) as db:
            meta = meta_values(db)
            prior_override = any(
                p.parse_object(row[0]).get("operation") == "integrity_override"
                for row in db.execute("SELECT body FROM audit")
            )
        if meta.get("audit_format") != "2":
            raise ValueError("Candidate requires explicit offline migration/enrollment")
        if meta.get("audit_profile") != "internal-2026-11-04-d1-d6":
            raise ValueError(
                "Older audit candidate requires explicit migration; no silent profile upgrade"
            )
        self.publisher = publisher
        if publisher is None and os.environ.get("KEY_SERVICE_CHECKPOINT_CONFIG"):
            self.publisher = configured_publisher(Path(os.environ["KEY_SERVICE_CHECKPOINT_CONFIG"]))
        self.must_publish = False
        self.state_mutation = False
        self.preserve_pending = False
        self.last_export_time = time.monotonic()
        self.last_export_seq = 0
        self.last_packet: dict | None = None
        self.export_pending = False
        self.next_export_retry = 0.0
        self.override_active = False
        self.local_snapshot_required = False
        if prior_override:
            self.audit_integrity = "unverified_override"
            self.export_pending = True
        logger.warning("UNAPPROVED synthetic audit candidate enabled; Ed25519 is not post-quantum")

    @classmethod
    def initialize(cls, path: Path, unlock_secret: bytes, *, backup_directory: Path | None = None):
        require_candidate()
        legacy = KeyStore.initialize(path, unlock_secret, backup_directory=backup_directory)
        cls._migrate_in_place(legacy, unlock_secret)
        return cls(path, backup_directory)

    @classmethod
    def migrate(
        cls,
        source: Path,
        destination: Path,
        secret: bytes,
        *,
        trusted_checkpoint: Path,
        backup_directory: Path,
    ):
        """Offline COPY migration: never modifies the original v1 store."""
        require_candidate()
        ownership = StoreOwnership(source)
        try:
            restored = KeyStore.restore(
                source, destination, secret, trusted_checkpoint=trusted_checkpoint
            )
            cls._migrate_in_place(restored, secret)
        finally:
            ownership.close()
        return cls(destination, backup_directory)

    @staticmethod
    def _migrate_in_place(legacy: KeyStore, secret: bytes) -> None:
        with legacy.transaction() as db:
            KeyStore.verify_audit(db)
            meta = meta_values(db)
            if "audit_format" in meta:
                raise ValueError("Already migrated")
            root = recover(secret, meta["wrapped_root"], 32, meta["root_id"].encode())
            store_id, audit_id, sign_id = (str(uuid.uuid4()) for _ in range(3))
            audit_key, sign_key = secrets.token_bytes(32), Ed25519PrivateKey.generate()
            head = db.execute("SELECT seq,digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            for statement in (
                "ALTER TABLE audit ADD COLUMN mac TEXT NULL",
                "ALTER TABLE audit ADD COLUMN key_id TEXT NULL",
                "ALTER TABLE audit ADD COLUMN next_mac TEXT NULL",
                "CREATE TABLE sealed_pending (seq INTEGER PRIMARY KEY, body TEXT NOT NULL)",
                "CREATE TABLE current_deks (context TEXT PRIMARY KEY, digest TEXT NOT NULL)",
            ):
                db.execute(statement)
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mfa_current'"
            ).fetchone():
                db.execute("INSERT INTO current_deks SELECT context,digest FROM mfa_current")
            meta.update(
                {"store_id": store_id, "audit_key_id": audit_id, "checkpoint_key_id": sign_id}
            )
            for name, value in {
                "audit_format": "2",
                "audit_profile": "internal-2026-11-04-d1-d6",
                "store_id": store_id,
                "audit_key_id": audit_id,
                "checkpoint_key_id": sign_id,
                "audit_keys": p.canonical(
                    {audit_id: protect(root, audit_key, audit_aad(meta, audit_id))}
                ).decode(),
                "checkpoint_key": protect(
                    root, sign_key.private_bytes_raw(), audit_aad(meta, sign_id, "checkpoint-sign")
                ),
                "checkpoint_pub": p.encode(sign_key.public_key().public_bytes_raw()),
                "wrapped_root": protect(
                    secret,
                    root,
                    p.canonical(
                        {
                            "purpose": "candidate-audit-root-v2",
                            "store_id": store_id,
                            "root_id": meta["root_id"],
                        }
                    ),
                ),
            }.items():
                put_meta(db, name, value)
            seq = (head["seq"] if head else 0) + 1
            body = p.canonical(
                {
                    "at": time.time_ns(),
                    "actor": "offline-custodian",
                    "operation": "audit_v2_genesis",
                    "organization": "",
                    "key_id": "",
                    "previous": head["digest"] if head else ZERO,
                    "audit_v": 2,
                    "store_id": store_id,
                    "state_digest": state_digest(db),
                    "details": {
                        "legacy_seq": seq - 1,
                        "legacy_digest": head["digest"] if head else ZERO,
                    },
                }
            ).decode()
            digest = hashlib.sha256(body.encode()).hexdigest()
            mac = row_mac(audit_key, seq, digest, ZERO)
            db.execute(
                "INSERT INTO audit(seq,body,digest,mac,key_id) VALUES (?,?,?,?,?)",
                (seq, body, digest, mac, audit_id),
            )
            record = {
                "v": 1,
                "sig_alg": "ed25519",
                "store_id": store_id,
                "root_id": meta["root_id"],
                "seq": seq,
                "head_digest": digest,
                "head_mac": mac,
                "audit_key_id": audit_id,
                "checkpoint_key_id": sign_id,
                "event": "audit_v2_genesis",
                "issued_at_ns": time.time_ns(),
                "previous_checkpoint_sha256": ZERO,
                "previous_root_id": None,
                "state_digest": state_digest(db),
            }
            packet = {
                "record": record,
                "signature": p.encode(sign_key.sign(DOMAIN + p.canonical(record))),
            }
            put_meta(db, "candidate_genesis", p.canonical(packet).decode())

    def export_enrollment(self, destination: Path) -> None:
        with closing(sqlite3.connect(self.path)) as db:
            meta = meta_values(db)
        packet = p.parse_object(meta["candidate_genesis"])
        verify_packet(packet, meta["store_id"], meta["checkpoint_pub"])
        with os.fdopen(
            os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
        ) as stream:
            stream.write(p.canonical({"public": meta["checkpoint_pub"], "genesis": packet}))
            stream.flush()
            os.fsync(stream.fileno())

    def _clear(self) -> None:
        self.root = self.root_id = self.seal_epoch = None
        self.override_active = False

    @staticmethod
    def _override_reason(reason: str | None) -> str | None:
        if reason is None:
            return None
        if not isinstance(reason, str) or not 20 <= len(reason.strip()) <= 500:
            raise ValueError("Custodian override reason must contain 20 to 500 characters")
        return reason.strip()

    def _record_override(self, db, actor: str, reason: str, operation: str) -> None:
        if (
            self.publisher is None
            or self.publisher.store_id != meta_values(db)["store_id"]
            or self.publisher.public != meta_values(db)["checkpoint_pub"]
        ):
            raise ValueError("Override cannot bypass independent enrollment")
        signed = db.execute(
            "SELECT seq FROM audit WHERE mac IS NOT NULL ORDER BY seq DESC LIMIT 1"
        ).fetchone()[0]
        gap = db.execute(
            "SELECT seq,digest FROM audit WHERE seq>? ORDER BY seq", (signed,)
        ).fetchall()
        if gap:
            self._audit(
                db,
                actor,
                "sealed_gap_attestation",
                details={
                    "first": gap[0]["seq"],
                    "last": gap[-1]["seq"],
                    "head_digest": gap[-1]["digest"],
                    "trusted": False,
                },
            )
        self._audit(
            db, actor, "integrity_override", details={"reason": reason, "operation": operation}
        )
        self.override_active = True
        self.export_pending = True
        self.audit_integrity = "unverified_override"
        logger.error("key_service_integrity_override_pending_export")

    @contextmanager
    def transaction(self):
        try:
            require_candidate()
        except PermissionError:
            self._clear()
            raise
        with self.lock:
            self.must_publish = False
            self.state_mutation = False
            self.local_snapshot_required = False
            self.preserve_pending = False
            try:
                with super().transaction() as db:
                    yield db
                    if self.local_snapshot_required and not self.must_publish:
                        super()._checkpoint(db)
                    if self.must_publish:
                        self._publish(db, required=True)
                    elif self.root is not None:
                        head = db.execute("SELECT MAX(seq) FROM audit").fetchone()[0] or 0
                        if time.monotonic() >= self.next_export_retry and (
                            head - self.last_export_seq >= 100
                            or time.monotonic() - self.last_export_time >= 300
                        ):
                            self._publish(db, required=False)
            except BaseException:
                self._clear()
                self.audit_integrity = "failed"
                raise

    def _root_aad(self, db, root_id: str) -> bytes:
        return p.canonical(
            {
                "purpose": "candidate-audit-root-v2",
                "store_id": meta_values(db)["store_id"],
                "root_id": root_id,
            }
        )

    def _keys(self, db, root: bytes | None = None) -> tuple[dict, dict[str, bytes]]:
        meta = meta_values(db)
        if meta.get("audit_format") != "2":
            raise ValueError("Candidate audit format changed")
        key = self.root if root is None else root
        if key is None:
            raise SealedError("Audit authentication keys unavailable while sealed")
        wrapped = p.parse_object(meta["audit_keys"])
        keys = {
            ident: recover(key, value, 32, audit_aad(meta, ident))
            for ident, value in wrapped.items()
        }
        if meta["audit_key_id"] not in keys:
            raise ValueError("Missing active audit key")
        return meta, keys

    def _rewrap_auxiliary_keys(self, db, new_root: bytes) -> None:
        meta, keys = self._keys(db)
        seed = recover(
            self.root,
            meta["checkpoint_key"],
            32,
            audit_aad(meta, meta["checkpoint_key_id"], "checkpoint-sign"),
        )
        put_meta(
            db,
            "audit_keys",
            p.canonical(
                {
                    ident: protect(new_root, raw, audit_aad(meta, ident))
                    for ident, raw in keys.items()
                }
            ).decode(),
        )
        put_meta(
            db,
            "checkpoint_key",
            protect(new_root, seed, audit_aad(meta, meta["checkpoint_key_id"], "checkpoint-sign")),
        )
        # Protected by the transaction lock. Any failure clears the provisional root.
        self.root = new_root

    @staticmethod
    def _unsigned_allowed(operation: str) -> bool:
        return operation in {"login_success", "seal"} or operation.startswith("denial_batch:")

    def verify_audit(self, db, *, check_state=True):
        KeyStore.verify_audit(db)
        meta, keys = self._keys(db)
        previous_mac, active, gap, boundary, genesis = ZERO, None, [], False, False
        previous_digest = ZERO
        last_state = None
        for row in db.execute("SELECT * FROM audit ORDER BY seq"):
            body = p.parse_object(row["body"])
            if not genesis and body.get("audit_v") != 2:
                if (
                    row["mac"] is not None
                    or row["key_id"] is not None
                    or row["next_mac"] is not None
                ):
                    raise ValueError("Invalid legacy audit row")
                previous_digest = row["digest"]
                continue
            if body.get("audit_v") != 2 or body.get("store_id") != meta["store_id"]:
                raise ValueError("Audit version/store identity mismatch")
            if not genesis:
                if body["operation"] != "audit_v2_genesis" or body.get("details") != {
                    "legacy_seq": row["seq"] - 1,
                    "legacy_digest": previous_digest,
                }:
                    raise ValueError("Invalid authenticated genesis")
                active, genesis = row["key_id"], True
            if row["mac"] is None:
                if (
                    row["key_id"] is not None
                    or row["next_mac"] is not None
                    or not boundary
                    or not self._unsigned_allowed(body["operation"])
                ):
                    raise ValueError("Missing audit MAC outside declared sealed gap")
                gap.append(row)
                continue
            if row["key_id"] != active or active not in keys:
                raise ValueError("Audit key transition missing")
            expected = row_mac(keys[active], row["seq"], row["digest"], previous_mac)
            if not hmac.compare_digest(expected, row["mac"]):
                raise ValueError("Audit MAC verification failed")
            if gap:
                if body["operation"] != "sealed_gap_attestation" or body.get("details") != {
                    "first": gap[0]["seq"],
                    "last": gap[-1]["seq"],
                    "head_digest": gap[-1]["digest"],
                    "trusted": False,
                }:
                    raise ValueError("Sealed gap attestation mismatch")
                gap = []
            elif body["operation"] == "sealed_gap_attestation":
                raise ValueError("Spurious sealed gap attestation")
            previous_mac = row["mac"]
            last_state = body.get("state_digest")
            if body["operation"] == "audit_key_rotated":
                details = body.get("details", {})
                new = details.get("new_id")
                if (
                    details.get("old_id") != active
                    or new == active
                    or new not in keys
                    or row["next_mac"] is None
                ):
                    raise ValueError("Invalid audit-key rotation")
                expected_new = row_mac(keys[new], row["seq"], row["digest"], previous_mac)
                if not hmac.compare_digest(expected_new, row["next_mac"]):
                    raise ValueError("Audit-key cross-authentication failed")
                active, previous_mac = new, row["next_mac"]
            elif row["next_mac"] is not None:
                raise ValueError("Unexpected transition MAC")
            boundary = body["operation"] in {"seal", "audit_v2_genesis"}
        if not genesis or active != meta["audit_key_id"]:
            raise ValueError("Audit genesis/current key mismatch")
        if check_state and last_state != state_digest(db):
            raise ValueError("Authenticated protected-state commitment mismatch")

    def _audit(
        self, db, actor: str, operation: str, org: str = "", ident: str = "", *, details=None
    ):
        if self.root is not None:
            self.verify_audit(
                db,
                check_state=operation
                not in {
                    "rotate",
                    "import",
                    "rotate_root",
                    "wrap",
                    "rewrap",
                    "root_recovery_verified",
                    "old_root_snapshots_retired",
                },
            )
        meta = meta_values(db)
        head = db.execute("SELECT seq,digest,mac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        signed = db.execute(
            "SELECT * FROM audit WHERE mac IS NOT NULL ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if self.root is None:
            if not self._unsigned_allowed(operation):
                raise SealedError("Cannot authenticate this operation while sealed")
            if p.parse_object(signed["body"])["operation"] not in {"seal", "audit_v2_genesis"}:
                # A crash may leave no authenticated seal boundary. Preserve these
                # explicitly untrusted observations separately until unseal.
                if db.execute("SELECT COUNT(*) FROM sealed_pending").fetchone()[0] >= 1000:
                    raise ValueError("Sealed observation queue full")
                db.execute(
                    "INSERT INTO sealed_pending(body) VALUES (?)",
                    (
                        p.canonical(
                            {"actor": actor, "operation": operation, "at": time.time_ns()}
                        ).decode(),
                    ),
                )
                return
        body = p.canonical(
            {
                "at": time.time_ns(),
                "actor": actor,
                "operation": operation,
                "organization": org,
                "key_id": ident,
                "previous": head["digest"],
                "audit_v": 2,
                "store_id": meta["store_id"],
                "state_digest": state_digest(db) if self.root is not None else None,
                **({"details": details} if details is not None else {}),
            }
        ).decode()
        digest, seq = hashlib.sha256(body.encode()).hexdigest(), head["seq"] + 1
        mac, audit_id = None, None
        if self.root is not None:
            meta, keys = self._keys(db)
            audit_id = meta["audit_key_id"]
            mac = row_mac(keys[audit_id], seq, digest, signed["next_mac"] or signed["mac"])
        db.execute(
            "INSERT INTO audit(seq,body,digest,mac,key_id) VALUES (?,?,?,?,?)",
            (seq, body, digest, mac, audit_id),
        )
        if operation in {"root_recovery_verified", "old_root_snapshots_retired"}:
            self.must_publish = True
            self.state_mutation = True

    def _remote(self, db, *, allow_transition: bool = False) -> dict:
        meta = meta_values(db)
        if (
            self.publisher is None
            or self.publisher.store_id != meta["store_id"]
            or self.publisher.public != meta["checkpoint_pub"]
        ):
            raise ValueError("Independent checkpoint enrollment/configuration required")
        packet = self.publisher.latest()
        record = verify_packet(packet, self.publisher.store_id, self.publisher.public)
        row = db.execute("SELECT * FROM audit WHERE seq=?", (record["seq"],)).fetchone()
        if (
            row is None
            or row["digest"] != record["head_digest"]
            or (row["next_mac"] or row["mac"]) != record["head_mac"]
        ):
            raise ValueError("External checkpoint detects rollback or audit rewrite")
        if record["checkpoint_key_id"] != meta["checkpoint_key_id"]:
            raise ValueError("Checkpoint signing identity mismatch")
        local_head = db.execute("SELECT MAX(seq) FROM audit").fetchone()[0]
        if (
            local_head == record["seq"]
            and not (allow_transition and self.state_mutation)
            and record["state_digest"] != state_digest(db)
        ):
            raise ValueError("External checkpoint detects protected-state rollback or splice")
        if record["audit_key_id"] != meta["audit_key_id"] and not allow_transition:
            raise ValueError("Checkpoint audit-key identity mismatch")
        if record["root_id"] != meta["root_id"]:
            head = db.execute("SELECT body FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            if not allow_transition or p.parse_object(head[0])["operation"] != "rotate_root":
                raise ValueError("External checkpoint root mismatch")
        if self.last_packet and record["seq"] < self.last_packet["record"]["seq"]:
            raise ValueError("Receiver returned a stale checkpoint")
        self.last_packet = packet
        return packet

    def _publish(self, db, *, required: bool):
        self.verify_audit(db)
        try:
            previous = self._remote(db, allow_transition=True)
        except OSError:
            if required:
                raise
            self.export_pending = True
            self.next_export_retry = time.monotonic() + 30
            logger.error("candidate_checkpoint_outage_pending")
            return
        meta = meta_values(db)
        head = db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        if head["mac"] is None:
            raise ValueError("Cannot checkpoint an unauthenticated head")
        if head["seq"] == previous["record"]["seq"]:
            if required:
                super()._checkpoint(db)
            self.last_export_seq, self.last_export_time = head["seq"], time.monotonic()
            self.export_pending = False
            if self.override_active:
                self.override_active = False
                self.audit_integrity = "candidate_mac_and_external_checkpoint_verified"
            return
        event = p.parse_object(head["body"])["operation"]
        record = {
            "v": 1,
            "sig_alg": "ed25519",
            "store_id": meta["store_id"],
            "root_id": meta["root_id"],
            "seq": head["seq"],
            "head_digest": head["digest"],
            "head_mac": head["next_mac"] or head["mac"],
            "audit_key_id": meta["audit_key_id"],
            "checkpoint_key_id": meta["checkpoint_key_id"],
            "event": event,
            "issued_at_ns": time.time_ns(),
            "previous_checkpoint_sha256": packet_hash(previous),
            "previous_root_id": previous["record"]["root_id"]
            if previous["record"]["root_id"] != meta["root_id"]
            else None,
            "state_digest": state_digest(db),
        }
        seed = recover(
            self.root,
            meta["checkpoint_key"],
            32,
            audit_aad(meta, meta["checkpoint_key_id"], "checkpoint-sign"),
        )
        packet = {
            "record": record,
            "signature": p.encode(
                Ed25519PrivateKey.from_private_bytes(seed).sign(DOMAIN + p.canonical(record))
            ),
        }
        put_meta(db, "candidate_pending_checkpoint", p.canonical(packet).decode())
        # Retain a verified encrypted recovery image BEFORE sending anything.
        super()._checkpoint(db)
        self.preserve_pending = True
        try:
            self.publisher.publish(packet)
        except OSError:
            if required:
                logger.error("candidate_checkpoint_ack_uncertain_reconciliation_required")
                raise
            self.export_pending = True
            self.next_export_retry = time.monotonic() + 30
            logger.error("candidate_checkpoint_outage_pending")
            return
        self.last_packet, self.last_export_seq = packet, head["seq"]
        self.last_export_time, self.export_pending = time.monotonic(), False
        self.override_active = False
        self.audit_integrity = "candidate_mac_and_external_checkpoint_verified"

    def _checkpoint(self, db):
        self.must_publish = True
        self.state_mutation = True

    def _ready(self, db):
        super()._ready(db)
        self.verify_audit(db)
        if self.last_packet is None:
            if self.override_active:
                return
            raise ValueError("No verified external checkpoint in this unseal session")
        record = self.last_packet["record"]
        row = db.execute(
            "SELECT digest,mac,next_mac FROM audit WHERE seq=?", (record["seq"],)
        ).fetchone()
        if (
            row is None
            or row["digest"] != record["head_digest"]
            or (row["next_mac"] or row["mac"]) != record["head_mac"]
        ):
            raise ValueError("Cached external checkpoint detects live rollback")

    @staticmethod
    def _guarded_field(context: str) -> str | None:
        kind = context.rsplit(":", 1)[-1].partition("=")[0]
        return kind if kind in {"mfa", "smtp-credential"} else None

    def _requires_dek_checkpoint(self, context: str) -> bool:
        # D3: wrap/rewrap can proceed during receiver outage. The ledger change
        # is committed in its MACed event and a local encrypted snapshot.
        return False

    @staticmethod
    def _current_digest(context: str, dek: bytes) -> str:
        # Preserve existing MFA fingerprints during explicit v1 copy migration.
        if CandidateKeyStore._guarded_field(context) == "mfa":
            return hashlib.sha256(b"mfa-dek\0" + context.encode() + dek).hexdigest()
        return hashlib.sha256(
            b"onesmarter:current-dek:v1\0" + context.encode() + b"\0" + dek
        ).hexdigest()

    def _record_mfa_dek(self, db, context: str, dek: bytes) -> None:
        super()._record_mfa_dek(db, context, dek)
        if self._guarded_field(context):
            self.local_snapshot_required = True
            db.execute(
                "INSERT INTO current_deks VALUES (?,?) ON CONFLICT(context) DO UPDATE SET digest=excluded.digest",
                (context, self._current_digest(context, dek)),
            )

    def _unwrap(self, db, org: str, context: str, wrapper: dict) -> bytes:
        dek = super()._unwrap(db, org, context, wrapper)
        if self._guarded_field(context):
            row = db.execute(
                "SELECT digest FROM current_deks WHERE context=?", (context,)
            ).fetchone()
            if row is None or not hmac.compare_digest(row[0], self._current_digest(context, dek)):
                raise ValueError(
                    "Mutable-field envelope is stale or requires trusted re-enrollment"
                )
        return dek

    def unseal(self, secret: bytes, actor: str, *, override_reason: str | None = None):
        override_reason = self._override_reason(override_reason)
        with self.transaction() as db:
            self._clear()
            meta = meta_values(db)
            root = recover(secret, meta["wrapped_root"], 32, self._root_aad(db, meta["root_id"]))
            self.root, self.root_id, self.seal_epoch = (
                root,
                meta["root_id"],
                meta.get("seal_epoch", "0"),
            )
            self.verify_audit(db)
            outage = False
            try:
                self._remote(db)
            except OSError:
                if override_reason is None:
                    raise
                outage = True
            for row in db.execute("SELECT * FROM versions"):
                p.private_keys(self._private(row))
            signed = db.execute(
                "SELECT seq FROM audit WHERE mac IS NOT NULL ORDER BY seq DESC LIMIT 1"
            ).fetchone()[0]
            gap = db.execute(
                "SELECT seq,digest FROM audit WHERE seq>? ORDER BY seq", (signed,)
            ).fetchall()
            if gap:
                self._audit(
                    db,
                    actor,
                    "sealed_gap_attestation",
                    details={
                        "first": gap[0]["seq"],
                        "last": gap[-1]["seq"],
                        "head_digest": gap[-1]["digest"],
                        "trusted": False,
                    },
                )
            pending = [
                p.parse_object(row[0])
                for row in db.execute("SELECT body FROM sealed_pending ORDER BY seq")
            ]
            if pending:
                self._audit(
                    db,
                    actor,
                    "sealed_pending_observed",
                    details={"trusted": False, "observations": pending},
                )
                db.execute("DELETE FROM sealed_pending")
            if outage:
                self._record_override(db, actor, override_reason, "unseal")
            self._audit(db, actor, "unseal")
            self.must_publish = not outage
            self.local_snapshot_required = outage
        if not self.override_active:
            self.audit_integrity = "candidate_mac_and_external_checkpoint_verified"

    def seal(self, actor: str):
        try:
            with self.transaction() as db:
                if self.root is not None:
                    self.verify_audit(db)
                    self._audit(db, actor, "seal")
                    self.must_publish = True
                else:
                    self._audit(db, actor, "seal")
                put_meta(db, "seal_epoch", str(uuid.uuid4()))
        finally:
            self._clear()

    def tick(self) -> None:
        """Server timer invokes the same bounded checkpoint policy when idle."""
        with self.transaction():
            pass

    def status(self) -> dict:
        result = super().status()
        result.update({"audit_candidate": True, "checkpoint_export_pending": self.export_pending})
        return result

    def custody_status(self) -> dict:
        result = super().custody_status()
        result.update(
            {
                "audit_candidate": True,
                "audit_integrity": self.audit_integrity,
                "checkpoint_export_pending": self.export_pending,
                "candidate_restore_enabled": bool(
                    os.environ.get("KEY_SERVICE_CANDIDATE_RESTORE_DIR")
                ),
            }
        )
        return result

    def restore_for_custodian(
        self, secret: bytes, destination_id: str, actor: str, *, override_reason=None
    ) -> dict:
        """Invoked only through the mTLS/session/CSRF-protected custodian endpoint."""
        directory = os.environ.get("KEY_SERVICE_CANDIDATE_RESTORE_DIR", "")
        if not directory or str(uuid.UUID(destination_id)) != destination_id:
            raise ValueError("Approved restore directory and UUID required")
        base = Path(directory)
        if base.is_symlink():
            raise ValueError("Restore directory cannot be a symlink")
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = base.resolve() / (destination_id + ".sqlite3")
        restored = type(self).restore(
            self.path,
            destination,
            secret,
            publisher=self.publisher,
            override_reason=override_reason,
            actor=actor,
        )
        return {
            "restored_id": destination_id,
            "sealed": True,
            "audit_integrity": restored.audit_integrity,
        }

    def rotate_audit_key(self, actor: str) -> str:
        with self.transaction() as db:
            self._ready(db)
            meta, keys = self._keys(db)
            old, new = meta["audit_key_id"], str(uuid.uuid4())
            keys[new] = secrets.token_bytes(32)
            put_meta(
                db,
                "audit_keys",
                p.canonical(
                    {
                        ident: protect(self.root, raw, audit_aad(meta, ident))
                        for ident, raw in keys.items()
                    }
                ).decode(),
            )
            put_meta(db, "audit_key_id", new)
            # Insert the dual proof together, retaining append-only triggers.
            head = db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq = head["seq"] + 1
            body = p.canonical(
                {
                    "at": time.time_ns(),
                    "actor": actor,
                    "operation": "audit_key_rotated",
                    "organization": "",
                    "key_id": "",
                    "previous": head["digest"],
                    "audit_v": 2,
                    "store_id": meta["store_id"],
                    "state_digest": state_digest(db),
                    "details": {"old_id": old, "new_id": new},
                }
            ).decode()
            digest = hashlib.sha256(body.encode()).hexdigest()
            old_mac = row_mac(keys[old], seq, digest, head["next_mac"] or head["mac"])
            new_mac = row_mac(keys[new], seq, digest, old_mac)
            db.execute(
                "INSERT INTO audit VALUES (?,?,?,?,?,?)", (seq, body, digest, old_mac, old, new_mac)
            )
            put_meta(db, "audit_key_id", new)
            self.must_publish = True
            self.state_mutation = True
        return new

    @classmethod
    def restore(
        cls,
        source: Path,
        destination: Path,
        secret: bytes,
        *,
        trusted_checkpoint: Path | None = None,
        publisher: Publisher | None = None,
        reconcile_pending: bool = False,
        override_reason: str | None = None,
        actor: str = "offline-restore-verification",
    ):
        """Verify a copy without adding events or moving the external high-water mark."""
        require_candidate()
        override_reason = cls._override_reason(override_reason)
        used_override = False
        if source.suffix == ".pending" and not reconcile_pending:
            raise ValueError("Pending checkpoint requires explicit reconciliation")
        if not source.is_file() or destination.exists():
            raise ValueError("Backup must exist and destination must be new")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".candidate-restore-{uuid.uuid4()}.sqlite3")
        with os.fdopen(os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"):
            pass
        copy = None
        try:
            with (
                closing(
                    sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
                ) as original,
                closing(sqlite3.connect(temporary)) as target,
            ):
                if original.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Backup integrity failed")
                original.backup(target)
            copy = cls(temporary, publisher=publisher)
            with closing(sqlite3.connect(temporary)) as db:
                db.row_factory = sqlite3.Row
                meta = meta_values(db)
                copy.root = recover(
                    secret, meta["wrapped_root"], 32, copy._root_aad(db, meta["root_id"])
                )
                copy.verify_audit(db)
                latest = None
                try:
                    latest = copy._remote(db)
                except OSError:
                    if override_reason is None or reconcile_pending:
                        raise
                    copy._record_override(db, actor, override_reason, "restore")
                    db.commit()
                    used_override = True
                if latest and latest["record"]["root_id"] != meta["root_id"]:
                    raise ValueError("Restore root differs from latest external checkpoint")
                if reconcile_pending:
                    pending = p.parse_object(meta["candidate_pending_checkpoint"])
                    if packet_hash(pending) != packet_hash(latest):
                        raise ValueError(
                            "Pending image is not the externally acknowledged checkpoint"
                        )
                for row in db.execute("SELECT * FROM versions"):
                    p.private_keys(copy._private(row))
            copy._clear()
            with closing(sqlite3.connect(temporary, isolation_level=None)) as db:
                if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                    raise ValueError("Restore checkpoint busy")
                db.execute("PRAGMA journal_mode=DELETE")
            with temporary.open("r+b") as stream:
                os.fsync(stream.fileno())
            if os.name == "nt":
                os.rename(temporary, destination)
            else:
                os.link(temporary, destination)
        finally:
            if copy is not None:
                copy._clear()
            temporary.unlink(missing_ok=True)
        result = cls(destination, trusted_checkpoint=trusted_checkpoint, publisher=publisher)
        if used_override:
            result.audit_integrity = "unverified_override"
            result.export_pending = True
        return result

    def export_checkpoint(self, destination: Path):
        with self.transaction() as db:
            self._ready(db)
            self.must_publish = True
        with os.fdopen(
            os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
        ) as stream:
            stream.write(p.canonical(self.last_packet))
            stream.flush()
            os.fsync(stream.fileno())

    def _recovery_restore_options(self) -> dict:
        return {"publisher": self.publisher}
