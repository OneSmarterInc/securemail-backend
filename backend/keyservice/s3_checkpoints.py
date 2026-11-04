"""Candidate D4/D5 adapter: separate-account S3 COMPLIANCE, SSE-S3, no KMS.

Only tests use injected fixtures. Provisioning, independent identities and
actual AWS enforcement remain owner actions. This module never changes bucket
policy, retention, credentials or enrollment.
"""

from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from . import protocol as p
from .checkpoints import packet_hash, require_candidate, verify_packet


def six_years_after(timestamp_ns: int) -> datetime:
    value = datetime.fromtimestamp(timestamp_ns / 1_000_000_000, timezone.utc)
    try:
        return value.replace(year=value.year + 6)
    except ValueError:  # Leap-day anniversary; retain through the next day.
        return value.replace(year=value.year + 6, month=3, day=1)


class S3Publisher:
    @staticmethod
    def _request(client, operation: str, **kwargs):
        try:
            return getattr(client, operation)(**kwargs)
        except BotoCoreError as exc:
            raise OSError("Checkpoint receiver transport unavailable") from exc

    def __init__(
        self,
        *,
        writer,
        reader,
        bucket: str,
        receiver_account: str,
        application_account: str,
        public: str,
        genesis: dict,
    ):
        require_candidate()
        if writer is reader or receiver_account == application_account:
            raise ValueError(
                "Separate receiver account and separate write/read identities required"
            )
        if not all(
            len(value) == 12 and value.isdigit()
            for value in (receiver_account, application_account)
        ):
            raise ValueError("Explicit AWS account IDs required")
        self.writer, self.reader, self.bucket = writer, reader, bucket
        self.account, self.public = receiver_account, public
        self.store_id = genesis["record"]["store_id"]
        verify_packet(genesis, self.store_id, public)
        self.genesis = genesis
        self.prefix = "key-checkpoints/" + self.store_id + "/"

    def _read(self, key: str) -> dict | None:
        try:
            response = self._request(
                self.reader,
                "get_object",
                Bucket=self.bucket,
                Key=key,
                ExpectedBucketOwner=self.account,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchKey":
                return None
            raise OSError("Checkpoint storage read failed") from exc
        stream = response["Body"]
        try:
            raw = stream.read(16385)
        finally:
            stream.close()
        if (
            len(raw) > 16384
            or not response.get("VersionId")
            or response.get("ServerSideEncryption") != "AES256"
        ):
            raise ValueError("Checkpoint object lacks expected size/version/SSE-S3 evidence")
        packet = p.parse_object(raw)
        record = verify_packet(packet, self.store_id, self.public)
        retention = self._request(
            self.reader,
            "get_object_retention",
            Bucket=self.bucket,
            Key=key,
            VersionId=response["VersionId"],
            ExpectedBucketOwner=self.account,
        )["Retention"]
        if retention.get("Mode") != "COMPLIANCE" or retention["RetainUntilDate"] < six_years_after(
            record["issued_at_ns"]
        ):
            raise ValueError("Checkpoint lacks six-year COMPLIANCE retention")
        return packet

    @staticmethod
    def successor(previous: dict, packet: dict) -> None:
        old, new = previous["record"], packet["record"]
        if new["seq"] <= old["seq"] or new["previous_checkpoint_sha256"] != packet_hash(previous):
            raise ValueError("Checkpoint rollback/fork")
        if new["checkpoint_key_id"] != old["checkpoint_key_id"]:
            raise ValueError("Unapproved signing-key transition")
        if new["root_id"] != old["root_id"]:
            if new["event"] != "rotate_root" or new["previous_root_id"] != old["root_id"]:
                raise ValueError("Unexplained root transition")
        elif new["previous_root_id"] is not None:
            raise ValueError("Unexpected root transition")

    def latest(self) -> dict:
        # Receiver administrators provision this genesis out of band. No automatic enrollment.
        head = self._read(self.prefix + "genesis.json")
        if head is None or packet_hash(head) != packet_hash(self.genesis):
            raise ValueError("Pinned checkpoint enrollment missing or changed")
        for _ in range(100000):
            successor = self._read(self.prefix + "after/" + packet_hash(head) + ".json")
            if successor is None:
                return head
            self.successor(head, successor)
            head = successor
        raise ValueError("Checkpoint history exceeds candidate traversal limit; review required")

    def publish(self, packet: dict) -> None:
        verify_packet(packet, self.store_id, self.public)
        previous = self.latest()
        if packet_hash(previous) == packet_hash(packet):
            return
        self.successor(previous, packet)
        config = self._request(
            self.reader,
            "get_object_lock_configuration",
            Bucket=self.bucket,
            ExpectedBucketOwner=self.account,
        )["ObjectLockConfiguration"]
        retention = config.get("Rule", {}).get("DefaultRetention", {})
        if (
            config.get("ObjectLockEnabled") != "Enabled"
            or retention.get("Mode") != "COMPLIANCE"
            or retention.get("Years", 0) < 6
        ):
            raise ValueError("Receiver bucket must provide six-year default COMPLIANCE retention")
        # One immutable successor key per prior head prevents two different-sequence
        # writers from creating competing branches. No mutable 'latest' object.
        key = self.prefix + "after/" + packet_hash(previous) + ".json"
        try:
            self._request(
                self.writer,
                "put_object",
                Bucket=self.bucket,
                Key=key,
                Body=p.canonical(packet),
                ContentType="application/json",
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
                ExpectedBucketOwner=self.account,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "PreconditionFailed":
                raise OSError("Checkpoint write acknowledgement uncertain") from exc
        accepted = self._read(key)
        if accepted is None or packet_hash(accepted) != packet_hash(packet):
            raise ValueError("Checkpoint acceptance conflict")
