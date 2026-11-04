"""CANDIDATE ONLY: signed checkpoint protocol and independent log storage.

Ed25519 is a classical signature. Algorithm/custody/PQ review is outstanding.
Receiver enrollment is offline; a key-host request cannot enroll a public key.
"""

import hashlib
import os
import re
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from backend.transport.recovery import checkpoint_request

from . import protocol as p

DOMAIN = b"onesmarter:keystore-checkpoint:v1\0"
ZERO = "0" * 64
FIELDS = {
    "v",
    "store_id",
    "root_id",
    "seq",
    "head_digest",
    "head_mac",
    "audit_key_id",
    "checkpoint_key_id",
    "event",
    "issued_at_ns",
    "previous_checkpoint_sha256",
    "previous_root_id",
    "state_digest",
    "sig_alg",
}


def require_candidate() -> None:
    if not (
        os.environ.get("KEY_SERVICE_AUDIT_CANDIDATE", "").lower() == "true"
        and os.environ.get("APP_ENV") in {"development", "test"}
        and os.environ.get("SYNTHETIC_MODE", "").lower() == "true"
    ):
        raise PermissionError(
            "Unapproved audit candidate requires KEY_SERVICE_AUDIT_CANDIDATE=true, "
            "APP_ENV=development or test and SYNTHETIC_MODE=true"
        )


def packet_hash(packet: dict) -> str:
    return hashlib.sha256(p.canonical(packet)).hexdigest()


def verify_packet(packet: dict, store_id: str, public: str) -> dict:
    if not isinstance(packet, dict) or set(packet) != {"record", "signature"}:
        raise ValueError("Invalid checkpoint envelope")
    record = packet["record"]
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise ValueError("Invalid checkpoint fields")
    if (
        type(record["v"]) is not int
        or record["v"] != 1
        or record["sig_alg"] != "ed25519"
        or record["store_id"] != store_id
        or type(record["seq"]) is not int
        or record["seq"] < 1
        or type(record["issued_at_ns"]) is not int
        or record["issued_at_ns"] < 1
        or not isinstance(record["event"], str)
        or not 1 <= len(record["event"]) <= 100
    ):
        raise ValueError("Invalid checkpoint identity/sequence")
    for name in ("store_id", "root_id", "audit_key_id", "checkpoint_key_id"):
        if str(uuid.UUID(record[name])) != record[name]:
            raise ValueError("Invalid checkpoint UUID")
    if record["previous_root_id"] is not None:
        if str(uuid.UUID(record["previous_root_id"])) != record["previous_root_id"]:
            raise ValueError("Invalid previous root")
    for name in ("head_digest", "head_mac", "previous_checkpoint_sha256", "state_digest"):
        if not isinstance(record[name], str) or not re.fullmatch(r"[0-9a-f]{64}", record[name]):
            raise ValueError("Invalid checkpoint digest")
    Ed25519PublicKey.from_public_bytes(p.decode(public, 32)).verify(
        p.decode(packet["signature"], 64), DOMAIN + p.canonical(record)
    )
    return record


class Publisher(Protocol):
    store_id: str
    public: str

    def latest(self) -> dict: ...

    def publish(self, packet: dict) -> None: ...


def configured_publisher(path: Path) -> Publisher:
    value = p.parse_object(path.read_bytes())
    if value.get("provider") != "s3":
        return RemotePublisher(path)
    import boto3
    from botocore.config import Config

    from .s3_checkpoints import S3Publisher

    fields = {
        "provider",
        "writer_profile",
        "reader_profile",
        "region",
        "bucket",
        "receiver_account",
        "application_account",
        "public",
        "genesis",
    }
    if (
        set(value) != fields
        or not value["writer_profile"]
        or not value["reader_profile"]
        or value["writer_profile"] == value["reader_profile"]
    ):
        raise ValueError("Independent S3 write/read role profiles required")
    config = Config(
        connect_timeout=5, read_timeout=10, retries={"max_attempts": 1, "mode": "standard"}
    )
    writer = boto3.Session(profile_name=value["writer_profile"]).client(
        "s3", region_name=value["region"], config=config
    )
    reader = boto3.Session(profile_name=value["reader_profile"]).client(
        "s3", region_name=value["region"], config=config
    )
    return S3Publisher(
        writer=writer,
        reader=reader,
        **{
            name: value[name]
            for name in ("bucket", "receiver_account", "application_account", "public", "genesis")
        },
    )


class RemotePublisher:
    """Pinned identity from an independently provisioned custodian configuration."""

    def __init__(self, config: Path):
        require_candidate()
        value = p.parse_object(config.read_bytes())
        if set(value) != {"store_id", "public", "url", "ca", "cert", "key"}:
            raise ValueError("Invalid candidate receiver configuration")
        self.store_id, self.public = value["store_id"], value["public"]
        self.url, self.ca, self.cert, self.key = (value[n] for n in ("url", "ca", "cert", "key"))
        p.decode(self.public, 32)
        if not self.url.endswith("/v1/checkpoints/" + self.store_id):
            raise ValueError("Receiver URL must name the pinned store")

    def latest(self) -> dict:
        raw = checkpoint_request("GET", self.url, self.ca, self.cert, self.key)
        packet = p.parse_object(raw)
        verify_packet(packet, self.store_id, self.public)
        return packet

    def publish(self, packet: dict) -> None:
        verify_packet(packet, self.store_id, self.public)
        raw = checkpoint_request("PUT", self.url, self.ca, self.cert, self.key, p.canonical(packet))
        if p.parse_object(raw) != {"accepted_sha256": packet_hash(packet)}:
            raise OSError("Checkpoint acknowledgement mismatch; reconcile before retry")


class CheckpointLog:
    """Separate-admin reference receiver, NOT host-admin-proof/WORM storage.

    The service process only appends. OS/admin separation and retained backups
    must be deployed and independently verified; local tests do not prove them.
    """

    def __init__(self, path: Path):
        require_candidate()
        if os.environ.get("APP_ENV") != "test":
            raise PermissionError(
                "Local checkpoint log is a test fixture only; use the approved off-host receiver"
            )
        self.path = path

    @classmethod
    def initialize(cls, path: Path) -> "CheckpointLog":
        require_candidate()
        if os.environ.get("APP_ENV") != "test":
            raise PermissionError("Local checkpoint log is a test fixture only")
        path.parent.mkdir(parents=True, exist_ok=True)
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"):
            pass
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""
                PRAGMA synchronous=FULL;
                CREATE TABLE enrollment(store_id TEXT PRIMARY KEY, public TEXT NOT NULL);
                CREATE TABLE checkpoints(store_id TEXT NOT NULL, seq INTEGER NOT NULL,
                    digest TEXT NOT NULL UNIQUE, packet TEXT NOT NULL,
                    PRIMARY KEY(store_id, seq), FOREIGN KEY(store_id) REFERENCES enrollment(store_id));
                CREATE TRIGGER checkpoint_no_update BEFORE UPDATE ON checkpoints
                    BEGIN SELECT RAISE(ABORT, 'append-only checkpoints'); END;
                CREATE TRIGGER checkpoint_no_delete BEFORE DELETE ON checkpoints
                    BEGIN SELECT RAISE(ABORT, 'append-only checkpoints'); END;
                CREATE TRIGGER enrollment_no_update BEFORE UPDATE ON enrollment
                    BEGIN SELECT RAISE(ABORT, 'offline enrollment is immutable'); END;
                CREATE TRIGGER enrollment_no_delete BEFORE DELETE ON enrollment
                    BEGIN SELECT RAISE(ABORT, 'offline enrollment is immutable'); END;
            """)
        return cls(path)

    def enroll(self, public: str, genesis: dict) -> None:
        """Offline custodian operation, deliberately not an HTTP endpoint."""
        record = verify_packet(genesis, genesis["record"]["store_id"], public)
        if record["previous_checkpoint_sha256"] != ZERO or record["event"] != "audit_v2_genesis":
            raise ValueError("Enrollment requires the independently approved genesis")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("INSERT INTO enrollment VALUES (?,?)", (record["store_id"], public))
            db.execute(
                "INSERT INTO checkpoints VALUES (?,?,?,?)",
                (
                    record["store_id"],
                    record["seq"],
                    packet_hash(genesis),
                    p.canonical(genesis).decode(),
                ),
            )

    def latest(self, store_id: str) -> dict:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute(
                "SELECT packet FROM checkpoints WHERE store_id=? ORDER BY seq DESC LIMIT 1",
                (store_id,),
            ).fetchone()
        if row is None:
            raise ValueError("Unknown checkpoint enrollment")
        return p.parse_object(row[0])

    def accept(self, store_id: str, packet: dict) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            identity = db.execute(
                "SELECT public FROM enrollment WHERE store_id=?", (store_id,)
            ).fetchone()
            if identity is None:
                raise ValueError("Unenrolled store")
            record = verify_packet(packet, store_id, identity[0])
            last = p.parse_object(
                db.execute(
                    "SELECT packet FROM checkpoints WHERE store_id=? ORDER BY seq DESC LIMIT 1",
                    (store_id,),
                ).fetchone()[0]
            )
            if packet_hash(packet) == packet_hash(last):
                return  # Exact idempotent retry only; never accept an old fork.
            previous = last["record"]
            if record["seq"] <= previous["seq"] or record[
                "previous_checkpoint_sha256"
            ] != packet_hash(last):
                raise ValueError("Checkpoint rollback or fork")
            if record["checkpoint_key_id"] != previous["checkpoint_key_id"]:
                raise ValueError(
                    "Signing-key rotation requires a separately approved enrollment protocol"
                )
            if record["root_id"] != previous["root_id"]:
                if (
                    record["event"] != "rotate_root"
                    or record["previous_root_id"] != previous["root_id"]
                ):
                    raise ValueError("Unexplained root rotation")
            elif record["previous_root_id"] is not None:
                raise ValueError("Unexpected root transition")
            db.execute(
                "INSERT INTO checkpoints VALUES (?,?,?,?)",
                (
                    store_id,
                    record["seq"],
                    packet_hash(packet),
                    p.canonical(packet).decode(),
                ),
            )
