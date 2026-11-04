"""Sealed, transactional local key store. Run one service process per store.

SQLite serializes durable changes; the process lock serializes sealing and use.
Root/private secrets are never exposed by public return values. Audit chaining
detects changes relative to an independently retained checkpoint, not host root.
"""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import protocol as p


class SealedError(ValueError):
    pass


class ConflictError(ValueError):
    pass


def protect(root: bytes, value: bytes, aad: bytes) -> str:
    nonce = secrets.token_bytes(12)
    return p.encode(nonce + AESGCM(root).encrypt(nonce, value, aad))


def recover(root: bytes, value: str, size: int, aad: bytes) -> bytes:
    raw = p.decode(value, 12 + size + 16)
    return AESGCM(root).decrypt(raw[:12], raw[12:], aad)


def key_aad(org: str, ident: str) -> bytes:
    return p.canonical(
        {"purpose": "private-version", "organization": org, "id": ident, "suite": p.SUITE}
    )


def validate_new_secret(secret: bytes) -> None:
    """Reject obvious weak inputs; this cannot prove randomness.

    Generate 32 bytes with a CSPRNG. Legacy unseal remains available for rotation.
    """
    if (
        len(secret) != 32
        or len(set(secret)) < 16
        or all(32 <= byte <= 126 for byte in secret)
        or all(
            (secret[i] - secret[i - 1]) % 256 == (secret[1] - secret[0]) % 256
            for i in range(2, len(secret))
        )
    ):
        raise ValueError("Use 32 cryptographically random bytes for new recovery custody.")


def synthetic_import_enabled() -> bool:
    """Operator opt-in, never a capability selectable by an API caller."""
    return (
        os.environ.get("KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT", "").lower() == "true"
        and os.environ.get("SYNTHETIC_MODE", "").lower() == "true"
        and os.environ.get("APP_ENV", "") in {"development", "test"}
    )


def require_synthetic_import() -> None:
    if not synthetic_import_enabled():
        raise PermissionError(
            "Private-key import is disabled outside explicitly enabled synthetic mode."
        )


class KeyStore:
    def __init__(
        self,
        path: Path,
        backup_directory: Path | None = None,
        *,
        trusted_checkpoint: Path | None = None,
    ):
        if not path.is_file():
            raise ValueError("Initialize the key store before starting it.")
        if type(self) is KeyStore:
            with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
                if db.execute("SELECT 1 FROM meta WHERE name='audit_format'").fetchone():
                    raise ValueError(
                        "Candidate audit store requires the explicit candidate implementation"
                    )
        self.path = path
        self.trusted_checkpoint = trusted_checkpoint
        self.backup_directory = backup_directory
        self.lock = threading.RLock()
        self.root: bytes | None = None
        self.root_id: str | None = None
        self.seal_epoch: str | None = None
        self.audit_integrity = "unchecked"
        self.pending_snapshots: list[Path] = []

    @classmethod
    def initialize(
        cls, path: Path, unlock_secret: bytes, *, backup_directory: Path | None = None
    ) -> "KeyStore":
        validate_new_secret(unlock_secret)
        path.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"):
            pass
        path.chmod(0o600)
        root_id = str(uuid.uuid4())
        with sqlite3.connect(path) as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE versions (
                    id TEXT PRIMARY KEY, org TEXT NOT NULL, state TEXT NOT NULL
                    CHECK(state IN ('active','decrypt_only')), private TEXT NOT NULL);
                CREATE UNIQUE INDEX active_org ON versions(org) WHERE state='active';
                CREATE TABLE requests (id TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT NOT NULL);
                CREATE TABLE audit (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, digest TEXT NOT NULL);
                CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN
                    SELECT RAISE(ABORT, 'append-only audit'); END;
                CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN
                    SELECT RAISE(ABORT, 'append-only audit'); END;
            """)
            db.executemany(
                "INSERT INTO meta VALUES (?,?)",
                [
                    ("format", "1"),
                    ("root_id", root_id),
                    (
                        "wrapped_root",
                        protect(unlock_secret, secrets.token_bytes(32), root_id.encode()),
                    ),
                ],
            )
        return cls(path, backup_directory)

    @contextmanager
    def transaction(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA secure_delete=ON")
            try:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                if not getattr(self, "preserve_pending", False):
                    for snapshot in self.pending_snapshots:
                        snapshot.unlink(missing_ok=True)
                self.pending_snapshots.clear()
                raise
            else:
                # Only committed snapshots are eligible for automatic recovery.
                # A crash before publication leaves .pending files for operator review.
                try:
                    for snapshot in self.pending_snapshots:
                        snapshot.replace(snapshot.with_suffix(".sqlite3"))
                    if (
                        self.pending_snapshots
                        and not db.execute(
                            "SELECT 1 FROM meta WHERE name='root_recovery_pending'"
                        ).fetchone()
                    ):
                        current_root = db.execute(
                            "SELECT value FROM meta WHERE name='root_id'"
                        ).fetchone()[0]
                        committed = sorted(
                            path
                            for path in self.backup_directory.glob("*.sqlite3")
                            if re.fullmatch(r"[0-9]+-[0-9a-f-]{36}\.sqlite3", path.name)
                        )
                        now_ns = time.time_ns()
                        # Nothing within seven days is eligible for removal. Avoid
                        # reopening every recent database on every rotation. Once
                        # pruning is possible, preserve the full root-scoped policy.
                        pruning_possible = any(
                            now_ns - int(path.name.split("-", 1)[0]) > 7 * 86400 * 1_000_000_000
                            for path in committed
                        )
                        obsolete_paths = []
                        if pruning_possible:
                            current = [
                                path
                                for path in committed
                                if self.snapshot_root(path) == current_root
                            ]
                            obsolete_paths = self.expired_snapshots(current, now_ns)
                        for obsolete in obsolete_paths:
                            if obsolete.is_symlink():
                                raise OSError("Refusing symlink snapshot")
                            obsolete.unlink()
                        if os.name != "nt":
                            fd = os.open(self.backup_directory, os.O_RDONLY)
                            try:
                                os.fsync(fd)
                            finally:
                                os.close(fd)
                except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
                    self.root = None
                    raise OSError(
                        "Keys committed but backup publication failed; store sealed"
                    ) from exc
                finally:
                    self.pending_snapshots.clear()
            finally:
                db.close()

    def check_trusted_checkpoint(self, db):
        """Verify an independently held audit anchor; never update it from runtime.

        This detects history rollback/forks through the anchor, not arbitrary host
        compromise or loss of events newer than the last external checkpoint.
        """
        if self.trusted_checkpoint is None:
            return
        try:
            with self.trusted_checkpoint.open("rb") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError("Oversized checkpoint")
            anchor = p.parse_object(raw)
            if (
                set(anchor) != {"format", "seq", "digest"}
                or type(anchor["format"]) is not int
                or anchor["format"] != 1
                or type(anchor["seq"]) is not int
                or anchor["seq"] < 1
                or not isinstance(anchor["digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", anchor["digest"])
            ):
                raise ValueError("Invalid trusted checkpoint")
            row = db.execute(
                "SELECT body,digest FROM audit WHERE seq=?", (anchor["seq"],)
            ).fetchone()
            if (
                row is None
                or not secrets.compare_digest(row["digest"], anchor["digest"])
                or hashlib.sha256(row["body"].encode()).hexdigest() != anchor["digest"]
            ):
                raise ValueError("Key-store history predates or conflicts with trusted checkpoint")
        except (OSError, ValueError, TypeError, KeyError):
            self.root = self.root_id = self.seal_epoch = None
            self.audit_integrity = "failed"
            raise

    def export_checkpoint(self, destination: Path):
        """Offline capture only; operator must independently protect the result."""
        with self.transaction() as db:
            self.verify_audit(db)
            self.check_trusted_checkpoint(db)
            row = db.execute("SELECT seq,digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            if row is None:
                raise ValueError("An empty audit history cannot establish a checkpoint")
            encoded = p.canonical({"format": 1, "seq": row["seq"], "digest": row["digest"]})
            with os.fdopen(
                os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())

    def _refresh_seal(self, db):
        self.check_trusted_checkpoint(db)
        current = db.execute("SELECT value FROM meta WHERE name='root_id'").fetchone()[0]
        epoch = db.execute("SELECT value FROM meta WHERE name='seal_epoch'").fetchone()
        epoch = epoch[0] if epoch else "0"
        if self.root_id != current or self.seal_epoch != epoch:
            self.root = None
            self.root_id = None
            self.seal_epoch = None

    def _ready(self, db):
        self._refresh_seal(db)
        if self.root is None:
            raise SealedError("Key store is sealed.")

    @staticmethod
    def verify_audit(db):
        """Check local consistency; external checkpoints are required for rollback detection."""
        previous = "0" * 64
        expected_seq = 1
        for row in db.execute("SELECT seq,body,digest FROM audit ORDER BY seq"):
            body = p.parse_object(row["body"])
            if (
                row["seq"] != expected_seq
                or body.get("previous") != previous
                or hashlib.sha256(row["body"].encode()).hexdigest() != row["digest"]
            ):
                raise ValueError("Key-store audit integrity verification failed.")
            previous = row["digest"]
            expected_seq += 1

    @staticmethod
    def _audit(db, actor: str, operation: str, org: str = "", ident: str = "", *, details=None):
        previous = db.execute("SELECT digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        body = p.canonical(
            {
                "at": time.time_ns(),
                "actor": actor,
                "operation": operation,
                "organization": org,
                "key_id": ident,
                "previous": previous[0] if previous else "0" * 64,
                **({"details": details} if details is not None else {}),
            }
        ).decode()
        db.execute(
            "INSERT INTO audit(body,digest) VALUES (?,?)",
            (body, hashlib.sha256(body.encode()).hexdigest()),
        )

    def record_event(self, actor: str, operation: str):
        """Call only with server-selected event names and provisioned actor names."""
        with self.transaction() as db:
            self._audit(db, actor, operation)

    def unseal(self, secret: bytes, actor: str):
        with self.lock:
            with self.transaction() as db:
                try:
                    self.verify_audit(db)
                    self.check_trusted_checkpoint(db)
                except (ValueError, TypeError):
                    self.root = self.root_id = self.seal_epoch = None
                    self.audit_integrity = "failed"
                    raise
                meta = dict(db.execute("SELECT name,value FROM meta"))
                if meta["format"] != "1":
                    raise ValueError("Unsupported store format.")
                root = recover(secret, meta["wrapped_root"], 32, meta["root_id"].encode())
                # Verify every stored private record before admitting use.
                for row in db.execute("SELECT * FROM versions"):
                    p.private_keys(
                        recover(root, row["private"], 96, key_aad(row["org"], row["id"]))
                    )
                self._audit(db, actor, "unseal")
            with self.lock:
                self.root, self.root_id = root, meta["root_id"]
                self.seal_epoch = meta.get("seal_epoch", "0")
                self.audit_integrity = "verified_at_unseal"

    def seal(self, actor: str):
        # Clear first, even when recording the event fails.
        with self.lock:
            self.root = self.root_id = self.seal_epoch = None
            with self.transaction() as db:
                db.execute(
                    "INSERT INTO meta(name,value) VALUES ('seal_epoch',?) "
                    "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                    (str(uuid.uuid4()),),
                )
                self._audit(db, actor, "seal")

    def status(self) -> dict:
        with self.transaction() as db:
            self._refresh_seal(db)
            head = db.execute("SELECT seq,digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            return {
                "sealed": self.root is None,
                "suite": p.SUITE,
                "audit_checkpoint": dict(head) if head else None,
                "audit_integrity": self.audit_integrity,
            }

    def _private(self, row) -> bytes:
        return recover(self.root, row["private"], 96, key_aad(row["org"], row["id"]))

    def _metadata(self, row) -> dict:
        return {
            "id": row["id"],
            "organization": row["org"],
            "state": row["state"],
            "suite": p.SUITE,
            **p.public(self._private(row)),
        }

    def list_versions(self, org: str, *, active: bool = False, after: str = "") -> list:
        if type(active) is not bool or not isinstance(after, str):
            raise ValueError("Invalid version query.")
        if after and (active or str(uuid.UUID(after)) != after):
            raise ValueError("Invalid version cursor.")
        with self.transaction() as db:
            self._ready(db)
            return [
                self._metadata(row)
                for row in db.execute(
                    "SELECT * FROM versions WHERE org=? AND id>? "
                    "AND (?=0 OR state='active') ORDER BY id LIMIT 100",
                    (org, after, int(active)),
                )
            ]

    def rotate(self, org: str, expected: str | None, request_id: str, actor: str) -> dict:
        org, request_id = str(uuid.UUID(org)), str(uuid.UUID(request_id))
        digest = hashlib.sha256(
            p.canonical({"org": org, "expected": expected, "actor": actor})
        ).hexdigest()
        with self.transaction() as db:
            self._ready(db)
            previous = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
            if previous:
                if previous["digest"] != digest:
                    raise ConflictError("Request identifier was already used.")
                original = json.loads(previous["result"])
                # A later rotation may have retired this operation's key. Replay
                # must never publish stale "active" metadata to the application.
                return self._metadata(
                    db.execute(
                        "SELECT * FROM versions WHERE id=? AND org=?", (original["id"], org)
                    ).fetchone()
                )
            active = db.execute(
                "SELECT id FROM versions WHERE org=? AND state='active'", (org,)
            ).fetchone()
            if (active[0] if active else None) != expected:
                raise ConflictError("Active version changed; refresh before rotating.")
            ident, raw = str(uuid.uuid4()), p.generate()
            encrypted = protect(self.root, raw, key_aad(org, ident))
            if recover(self.root, encrypted, 96, key_aad(org, ident)) != raw:
                raise ValueError("Private record verification failed.")
            db.execute(
                "UPDATE versions SET state='decrypt_only' WHERE org=? AND state='active'", (org,)
            )
            db.execute("INSERT INTO versions VALUES (?,?,?,?)", (ident, org, "active", encrypted))
            result = self._metadata(
                db.execute("SELECT * FROM versions WHERE id=?", (ident,)).fetchone()
            )
            db.execute(
                "INSERT INTO requests VALUES (?,?,?)",
                (request_id, digest, p.canonical(result).decode()),
            )
            self._audit(db, actor, "rotate", org, ident)
            self._checkpoint(db)
            return result

    def import_version(self, org: str, ident: str, raw: bytes, actor: str) -> dict:
        """Opt-in synthetic migration only; imports are never automatically activated."""
        require_synthetic_import()
        org, ident = str(uuid.UUID(org)), str(uuid.UUID(ident))
        p.private_keys(raw)
        with self.transaction() as db:
            self._ready(db)
            existing = db.execute("SELECT * FROM versions WHERE id=?", (ident,)).fetchone()
            if existing:
                if existing["org"] != org or not secrets.compare_digest(
                    self._private(existing), raw
                ):
                    raise ConflictError("Conflicting import.")
                return self._metadata(existing)
            db.execute(
                "INSERT INTO versions VALUES (?,?,?,?)",
                (ident, org, "decrypt_only", protect(self.root, raw, key_aad(org, ident))),
            )
            self._audit(db, actor, "import", org, ident)
            self._checkpoint(db)
            return self._metadata(
                db.execute("SELECT * FROM versions WHERE id=?", (ident,)).fetchone()
            )

    def _record_mfa_dek(self, db, context: str, dek: bytes) -> None:
        if ":mfa=" not in context:
            return
        db.execute(
            "CREATE TABLE IF NOT EXISTS mfa_current (context TEXT PRIMARY KEY, digest TEXT NOT NULL)"
        )
        fingerprint = hashlib.sha256(b"mfa-dek\0" + context.encode() + dek).hexdigest()
        db.execute(
            "INSERT INTO mfa_current VALUES (?,?) ON CONFLICT(context) DO UPDATE SET digest=excluded.digest",
            (context, fingerprint),
        )

    def _requires_dek_checkpoint(self, context: str) -> bool:
        return ":mfa=" in context

    def wrap(self, org: str, context: str, dek: bytes, expected: str, actor: str) -> dict:
        with self.transaction() as db:
            self._ready(db)
            if p.organization(context) != org:
                raise ValueError("Wrong context scope.")
            row = db.execute(
                "SELECT * FROM versions WHERE org=? AND state='active'", (org,)
            ).fetchone()
            if row is None or row["id"] != expected:
                raise ConflictError("Active version changed.")
            result = p.wrap(dek, context, row["id"], self._private(row))
            self._record_mfa_dek(db, context, dek)
            self._audit(db, actor, "wrap", org, row["id"])
            if self._requires_dek_checkpoint(context):
                self._checkpoint(db)
            return result

    def _unwrap(self, db, org: str, context: str, wrapper: dict) -> bytes:
        if p.organization(context) != org:
            raise ValueError("Wrong context scope.")
        p.validate(wrapper)
        row = db.execute(
            "SELECT * FROM versions WHERE id=? AND org=?", (wrapper["key_id"], org)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown version.")
        dek = p.unwrap(wrapper, context, self._private(row))
        if ":mfa=" in context:
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mfa_current'"
            ).fetchone():
                raise ValueError("MFA envelope needs trusted re-enrollment")
            current = db.execute(
                "SELECT digest FROM mfa_current WHERE context=?", (context,)
            ).fetchone()
            if current is None or not secrets.compare_digest(
                current[0], hashlib.sha256(b"mfa-dek\0" + context.encode() + dek).hexdigest()
            ):
                raise ValueError("MFA enrollment is stale or unregistered")
        return dek

    def unwrap(self, org: str, context: str, wrapper: dict, actor: str) -> bytes:
        with self.transaction() as db:
            self._ready(db)
            dek = self._unwrap(db, org, context, wrapper)
            self._audit(db, actor, "unwrap", org, wrapper["key_id"])
            return dek

    def unwrap_batch(self, org: str, items: list, actor: str) -> list[bytes]:
        if not isinstance(items, list) or not 1 <= len(items) <= 25:
            raise ValueError("Batch must contain 1 to 25 envelopes")
        with self.transaction() as db:
            self._ready(db)
            results = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {"context", "wrapper"}:
                    raise ValueError("Invalid batch item")
                results.append(self._unwrap(db, org, item["context"], item["wrapper"]))
            self._audit(
                db,
                actor,
                "unwrap_batch",
                org,
                details={
                    "count": len(items),
                    "key_ids": sorted({item["wrapper"]["key_id"] for item in items}),
                    "request_sha256": hashlib.sha256(p.canonical(items)).hexdigest(),
                },
            )
            return results

    def rewrap(self, org: str, context: str, wrapper: dict, expected: str, actor: str) -> dict:
        with self.transaction() as db:
            self._ready(db)
            dek = self._unwrap(db, org, context, wrapper)
            row = db.execute(
                "SELECT * FROM versions WHERE org=? AND state='active'", (org,)
            ).fetchone()
            if row is None or row["id"] != expected:
                raise ConflictError("Active version changed.")
            result = p.wrap(dek, context, row["id"], self._private(row))
            self._record_mfa_dek(db, context, dek)
            self._audit(db, actor, "rewrap", org, row["id"])
            if self._requires_dek_checkpoint(context):
                self._checkpoint(db)
            return result

    def rotate_root(self, new_secret: bytes, expected: str, actor: str) -> dict:
        """Atomic root rotation: interruption rolls back all ciphertext and header changes."""
        validate_new_secret(new_secret)
        with self.lock:
            if self.backup_directory is None:
                raise ValueError(
                    "Configure an explicit independent backup destination before rotation"
                )
            # Publish a recoverable old-root checkpoint before changing any keys.
            with self.transaction() as db:
                self._ready(db)
                if self.root_id != expected:
                    raise ConflictError("Root changed; verify status before rotating.")
                if db.execute("SELECT 1 FROM meta WHERE name='root_recovery_pending'").fetchone():
                    raise ConflictError("Verify recovery of the previous root rotation first.")
                self._checkpoint(db)
            with self.transaction() as db:
                self._ready(db)
                if self.root_id != expected:
                    raise ConflictError("Root changed; verify status before rotating.")
                root, ident = secrets.token_bytes(32), str(uuid.uuid4())
                rows = db.execute("SELECT * FROM versions").fetchall()
                for row in rows:
                    raw = self._private(row)
                    p.private_keys(raw)
                    encrypted = protect(root, raw, key_aad(row["org"], row["id"]))
                    if recover(root, encrypted, 96, key_aad(row["org"], row["id"])) != raw:
                        raise ValueError("Root migration verification failed.")
                    db.execute("UPDATE versions SET private=? WHERE id=?", (encrypted, row["id"]))
                self._rewrap_auxiliary_keys(db, root)
                db.execute("UPDATE meta SET value=? WHERE name='root_id'", (ident,))
                db.execute(
                    "UPDATE meta SET value=? WHERE name='wrapped_root'",
                    (protect(new_secret, root, self._root_aad(db, ident)),),
                )
                db.execute(
                    "INSERT INTO meta(name,value) VALUES ('root_recovery_pending',?)", (ident,)
                )
                self._audit(db, actor, "rotate_root", ident=ident)
                self._checkpoint(db)
            self.root, self.root_id = root, ident
            # Retain old-root and pending files until explicit recovery verification.
            # Rotation is committed. Report cleanup independently; never imply rollback.
            sanitized = False
            try:
                with closing(sqlite3.connect(self.path, timeout=10, isolation_level=None)) as clean:
                    clean.execute("PRAGMA secure_delete=ON")
                    checkpoint = clean.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    if checkpoint[0] == 0:
                        clean.execute("VACUUM")
                        sanitized = (
                            clean.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
                        )
            except sqlite3.Error:
                pass
            return {
                "root_id": ident,
                "storage_cleanup_complete": sanitized,
                "snapshot_cleanup_complete": False,
                "recovery_verification_required": True,
            }

    def _root_aad(self, db, root_id: str) -> bytes:
        return root_id.encode()

    def _rewrap_auxiliary_keys(self, db, new_root: bytes) -> None:
        """Extension point for explicitly selected candidate audit-key custody."""

    @staticmethod
    def snapshot_root(path: Path) -> str:
        if path.is_symlink():
            raise ValueError("Refusing symlink snapshot")
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            return db.execute("SELECT value FROM meta WHERE name='root_id'").fetchone()[0]

    def verify_root_recovery(
        self,
        secret: bytes,
        expected: str,
        destination: Path,
        actor: str,
        *,
        off_host_backup: Path | None = None,
        recovery_evidence: Path | None = None,
    ) -> dict:
        """Recovery drill is offline and excludes a running service owner."""
        from .ownership import StoreOwnership

        ownership = StoreOwnership(self.path)
        try:
            return self._verify_root_recovery(
                secret,
                expected,
                destination,
                actor,
                off_host_backup=off_host_backup,
                recovery_evidence=recovery_evidence,
            )
        finally:
            ownership.close()

    def _verify_root_recovery(
        self,
        secret: bytes,
        expected: str,
        destination: Path,
        actor: str,
        *,
        off_host_backup: Path | None = None,
        recovery_evidence: Path | None = None,
    ) -> dict:
        with self.lock:
            if self.backup_directory is None:
                raise ValueError("Explicit backup directory required")
            try:
                evidence = None
                if bool(off_host_backup) != bool(recovery_evidence):
                    raise ValueError(
                        "Both an off-host backup copy and recovery evidence are required"
                    )
                if recovery_evidence is not None:
                    from .recovery_evidence import verify_evidence

                    evidence = verify_evidence(recovery_evidence, off_host_backup, expected)
                    # Verify the independently restored copy before unseal advances
                    # the candidate's external audit checkpoint.
                    restored = self.restore(
                        off_host_backup,
                        destination,
                        secret,
                        trusted_checkpoint=self.trusted_checkpoint,
                        **self._recovery_restore_options(),
                    )
                self.unseal(secret, actor)
                if self.root_id != expected:
                    raise ConflictError("Root changed; recovery verification refused")
                if evidence is None:
                    self.backup_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                    proof = self.backup_directory / f"recovery-proof-{uuid.uuid4()}.sqlite3"
                    self.backup(proof)
                    # Uses the actual restore path: integrity, audit, root and every
                    # private key are verified, then a standalone sealed DB is published.
                    restored = self.restore(
                        proof,
                        destination,
                        secret,
                        trusted_checkpoint=self.trusted_checkpoint,
                        **self._recovery_restore_options(),
                    )
                if self.snapshot_root(restored.path) != expected:
                    raise ConflictError("Restored root differs from the live root")
                if evidence is None:
                    self.record_event(actor, "same_host_recovery_drill_completed")
                    return {
                        "root_id": expected,
                        "retired_snapshots": 0,
                        "restored_store": str(destination),
                        "retirement_authorized": False,
                        "off_host_evidence_required": True,
                    }
                with self.transaction() as db:
                    self._ready(db)
                    with closing(sqlite3.connect(restored.path)) as verified:
                        live_keys = db.execute(
                            "SELECT id,org,private FROM versions ORDER BY id"
                        ).fetchall()
                        copied_keys = verified.execute(
                            "SELECT id,org,private FROM versions ORDER BY id"
                        ).fetchall()
                        if [tuple(row) for row in live_keys] != copied_keys:
                            raise ValueError(
                                "Remote recovery copy does not cover all current private keys"
                            )
                    db.execute("DELETE FROM meta WHERE name='root_recovery_pending'")
                    db.execute(
                        "INSERT OR REPLACE INTO meta(name,value) VALUES ('root_recovery_verified',?)",
                        (expected,),
                    )
                    self._audit(
                        db, actor, "root_recovery_verified", ident=expected, details=evidence
                    )
                retired = 0
                for path in self.backup_directory.glob("*.sqlite3"):
                    if re.fullmatch(r"[0-9]+-[0-9a-f-]{36}\.sqlite3", path.name):
                        if self.snapshot_root(path) != expected:
                            path.unlink()
                            retired += 1
                self.record_event(actor, "old_root_snapshots_retired")
                return {
                    "root_id": expected,
                    "retired_snapshots": retired,
                    "restored_store": str(destination),
                    "retirement_authorized": True,
                }
            finally:
                self.seal("offline-recovery-verification-complete")

    def custody_status(self) -> dict:
        with self.transaction() as db:
            self._refresh_seal(db)
            return {
                "root_id": db.execute("SELECT value FROM meta WHERE name='root_id'").fetchone()[0],
                "sealed": self.root is None,
                "suite": p.SUITE,
                "recovery_verification_required": bool(
                    db.execute("SELECT 1 FROM meta WHERE name='root_recovery_pending'").fetchone()
                ),
            }

    def _recovery_restore_options(self) -> dict:
        return {}

    @staticmethod
    def expired_snapshots(paths: list[Path], now_ns: int) -> list[Path]:
        """Keep 7 days in full, one daily anchor through 30 days, and newest 3."""
        day = 86400 * 1_000_000_000
        ordered = sorted(paths, key=lambda path: int(path.name.split("-", 1)[0]))
        keep = set(ordered[-3:])
        daily = set()
        for path in ordered:
            timestamp = int(path.name.split("-", 1)[0])
            age = now_ns - timestamp
            if age <= 7 * day:
                keep.add(path)  # Also preserve future timestamps after clock rollback.
            elif age <= 30 * day and timestamp // day not in daily:
                keep.add(path)  # Earliest available snapshot per UTC day.
                daily.add(timestamp // day)
        return [path for path in ordered if path not in keep]

    def _checkpoint(self, db):
        """Durable snapshot of pending keys BEFORE the live transaction can commit."""
        try:
            self.verify_audit(db)
        except (ValueError, TypeError):
            self.root = self.root_id = self.seal_epoch = None
            self.audit_integrity = "failed"
            raise
        if self.backup_directory is None:
            raise ValueError(
                "Configure an explicit independent backup destination before changing keys"
            )
        if self.backup_directory.is_symlink() or self.path.resolve().is_relative_to(
            self.backup_directory.resolve()
        ):
            raise ValueError(
                "Backup destination must be a dedicated directory separate from the live store"
            )
        self.backup_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt" and self.backup_directory.stat().st_mode & 0o077:
            raise ValueError("Backup directory permissions must be restricted to its owner (0700)")
        destination = self.backup_directory / f"{time.time_ns()}-{uuid.uuid4()}.pending"
        with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"):
            pass
        destination.chmod(0o600)
        try:
            with closing(sqlite3.connect(destination)) as target:
                target.row_factory = sqlite3.Row
                target.execute("PRAGMA synchronous=FULL")
                # Dump from this transaction sees its uncommitted rotation. Opening
                # another source connection would silently omit the pending key.
                target.executescript("\n".join(db.iterdump()))
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Backup verification failed")
                self.verify_audit(target)
            with destination.open("r+b") as stream:
                os.fsync(stream.fileno())
            if os.name != "nt":
                fd = os.open(self.backup_directory, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        self.pending_snapshots.append(destination)

    @classmethod
    def restore(
        cls,
        source: Path,
        destination: Path,
        secret: bytes,
        *,
        trusted_checkpoint: Path | None = None,
    ):
        """Restore only to a new path, verifying custody and every private record."""
        if source.suffix == ".pending":
            raise ValueError("Uncommitted snapshot requires reconciliation; restore refused")
        if not source.is_file() or destination.exists():
            raise ValueError("Backup must exist and restore destination must be new")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".restore-{uuid.uuid4()}.sqlite3")
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"):
            pass
        temporary.chmod(0o600)
        try:
            with (
                closing(sqlite3.connect(source)) as original,
                closing(sqlite3.connect(temporary)) as target,
            ):
                if original.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Backup integrity failed")
                original.backup(target)
            recovered = cls(temporary, trusted_checkpoint=trusted_checkpoint)
            recovered.unseal(secret, "offline-restore-verification")
            recovered.seal("offline-restore-complete")
            # Publish a standalone database, never a main file with pending WAL.
            with closing(sqlite3.connect(temporary, isolation_level=None)) as checkpoint:
                if checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                    raise ValueError("Restore checkpoint was busy")
                checkpoint.execute("PRAGMA journal_mode=DELETE")
            with temporary.open("r+b") as stream:
                os.fsync(stream.fileno())
            # Atomic non-overwriting publication on the same filesystem.
            if os.name == "nt":
                os.rename(temporary, destination)  # Windows refuses an existing destination.
            else:
                os.link(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return cls(destination, trusted_checkpoint=trusted_checkpoint)

    def backup(self, destination: Path):
        """Offline CLI operation; backup is encrypted and never returned over runtime API."""
        with self.lock:
            with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"):
                pass
            destination.chmod(0o600)
            with (
                closing(sqlite3.connect(self.path)) as source,
                closing(sqlite3.connect(destination)) as target,
            ):
                source.backup(target)
