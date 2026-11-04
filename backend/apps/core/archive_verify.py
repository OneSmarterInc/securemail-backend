"""Version-specific archive verification and independent searchable projection.

Trust requires a separately protected manifest. Hashes alone do not authenticate
an attacker-controlled manifest. Never alter canonical application audit events.
"""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from django.utils.dateparse import parse_datetime
from django.utils.timezone import is_naive

from backend.keyservice.protocol import parse_object

MAX_EVENT_BYTES = 16 * 1024 * 1024


def read_object_verified(client, bucket: str, entry: dict) -> dict:
    until = parse_datetime(entry["retain_until"])
    if until is None or is_naive(until):
        raise ValueError("Invalid retention timestamp.")
    args = {"Bucket": bucket, "Key": entry["object_key"], "VersionId": entry["version_id"]}
    retention = client.get_object_retention(**args)["Retention"]
    if retention.get("Mode") != "COMPLIANCE" or retention.get("RetainUntilDate") < until:
        raise ValueError("Archive retention mismatch.")
    result = client.get_object(**args)
    stream = result["Body"]
    try:
        raw = stream.read(MAX_EVENT_BYTES + 1)
    finally:
        stream.close()
    if len(raw) > MAX_EVENT_BYTES or hashlib.sha256(raw).hexdigest() != entry["digest"]:
        raise ValueError("Archive digest mismatch.")
    value = parse_object(raw)
    if value.get("organization") != entry["organization"]:
        raise ValueError("Archive organization mismatch.")
    return value


def read_batch_verified(client, bucket: str, entry: dict) -> dict:
    value = read_object_verified(client, bucket, entry)
    validate_batch(value, entry)
    return value


def validate_batch(value: dict, entry: dict) -> None:
    events = value.get("events", [])
    if value.get("schema") != 2 or not 1 <= len(events) <= 1000:
        raise ValueError("Invalid archive batch.")
    for field in ("batch_id", "batch_sequence", "previous_digest"):
        if field in entry and value.get(field) != entry[field]:
            raise ValueError("Archive batch chain mismatch.")
    sequences = [e["sequence"] for e in events]
    if sequences != sorted(set(sequences)) or len({e["id"] for e in events}) != len(events):
        raise ValueError("Duplicate or unordered archive events.")


def read_verified(client, bucket: str, entry: dict, *, value=None) -> dict:
    if value is None:
        value = read_object_verified(client, bucket, entry)
    if value.get("schema") == 2:
        validate_batch(value, entry)
        event = next((e for e in value["events"] if e["id"] == entry["event_id"]), {})
    elif value.get("schema") == 1:
        event = value.get("event", {})
    else:
        raise ValueError("Unsupported archive schema.")
    if event.get("id") != entry["event_id"] or event.get("sequence") != entry["sequence"]:
        raise ValueError("Archive event identity mismatch.")
    return {"organization": value["organization"], "event": event}


def rebuild_projection(client, bucket: str, entries: list[dict], destination: Path) -> int:
    """Create a new queryable projection atomically; never overwrite existing evidence."""
    with destination.open("xb"):
        pass
    destination.chmod(0o600)
    try:
        with closing(sqlite3.connect(destination)) as db, db:
            db.execute(
                "CREATE TABLE events (id TEXT PRIMARY KEY, organization TEXT NOT NULL, "
                "sequence INTEGER NOT NULL, action TEXT NOT NULL, body TEXT NOT NULL)"
            )
            db.execute("CREATE UNIQUE INDEX event_order ON events(organization, sequence)")
            # Verify a complete exported manifest's cross-batch chain, then use
            # a single-object cache so a 1000-event batch costs only two reads.
            chains = {}
            for entry in entries:
                if entry.get("batch_id"):
                    key = (entry["organization"], entry["batch_sequence"])
                    link = (entry["previous_digest"], entry["digest"])
                    if key in chains and chains[key] != link:
                        raise ValueError("Conflicting batch manifest entries.")
                    chains[key] = link
            heads = {}
            for (org, sequence), (previous, digest) in sorted(chains.items()):
                prior_sequence, prior_digest = heads.get(org, (0, "0" * 64))
                if sequence != prior_sequence + 1 or previous != prior_digest:
                    raise ValueError("Incomplete or broken archive chain.")
                heads[org] = (sequence, digest)
            cache_key, cached = None, None
            for entry in sorted(entries, key=lambda e: (e["organization"], e["sequence"])):
                object_key = (
                    entry["object_key"],
                    entry["version_id"],
                    entry["digest"],
                    entry["retain_until"],
                )
                if object_key != cache_key:
                    cached = read_object_verified(client, bucket, entry)
                    cache_key = object_key
                value = read_verified(client, bucket, entry, value=cached)
                event = value["event"]
                db.execute(
                    "INSERT INTO events VALUES (?,?,?,?,?)",
                    (
                        event["id"],
                        value["organization"],
                        event["sequence"],
                        event["action"],
                        json.dumps(event, sort_keys=True),
                    ),
                )
        return len(entries)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
