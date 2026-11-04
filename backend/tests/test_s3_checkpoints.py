"""No AWS calls: assert candidate S3 request and immutable-chain contracts."""

import copy
import io
import sqlite3
from contextlib import closing

import pytest
from botocore.exceptions import ClientError

from backend.keyservice import protocol as p
from backend.keyservice.candidate_audit import meta_values
from backend.keyservice.checkpoints import packet_hash
from backend.keyservice.s3_checkpoints import S3Publisher, six_years_after
from backend.tests.test_candidate_audit import candidate_env as candidate_env
from backend.tests.test_candidate_audit import vault as vault


class Reader:
    def __init__(self, objects):
        self.objects = objects
        self.mode = "COMPLIANCE"
        self.years = 6
        self.sse = "AES256"

    def get_object(self, **kwargs):
        assert kwargs["ExpectedBucketOwner"] == "222222222222"
        if kwargs["Key"] not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {
            "Body": io.BytesIO(p.canonical(self.objects[kwargs["Key"]])),
            "VersionId": "immutable-version",
            "ServerSideEncryption": self.sse,
        }

    def get_object_retention(self, **kwargs):
        assert kwargs["VersionId"] == "immutable-version"
        record = self.objects[kwargs["Key"]]["record"]
        until = six_years_after(record["issued_at_ns"])
        if self.years < 6:
            until = until.replace(year=until.year - 1)
        return {"Retention": {"Mode": self.mode, "RetainUntilDate": until}}

    def get_object_lock_configuration(self, **kwargs):
        return {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": self.mode, "Years": self.years}},
            }
        }


class Writer:
    def __init__(self, objects):
        self.objects, self.calls = objects, []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        assert kwargs["IfNoneMatch"] == "*"
        assert kwargs["ServerSideEncryption"] == "AES256"
        assert kwargs["ExpectedBucketOwner"] == "222222222222"
        assert "SSEKMSKeyId" not in kwargs and "ObjectLockRetainUntilDate" not in kwargs
        if kwargs["Key"] in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[kwargs["Key"]] = p.parse_object(kwargs["Body"])


@pytest.fixture
def s3(vault):
    store, _, publisher, *_ = vault
    with closing(sqlite3.connect(store.path)) as db:
        meta = meta_values(db)
    genesis = p.parse_object(meta["candidate_genesis"])
    objects = {f"key-checkpoints/{meta['store_id']}/genesis.json": genesis}
    reader, writer = Reader(objects), Writer(objects)
    adapter = S3Publisher(
        writer=writer,
        reader=reader,
        bucket="synthetic-bucket",
        receiver_account="222222222222",
        application_account="111111111111",
        public=publisher.public,
        genesis=genesis,
    )
    with closing(sqlite3.connect(publisher.log.path)) as db:
        packets = [
            p.parse_object(row[0])
            for row in db.execute("SELECT packet FROM checkpoints ORDER BY seq")
        ]
    return adapter, reader, writer, packets


def test_append_only_sse_s3_roundtrip_and_retry(s3):
    adapter, _, writer, packets = s3
    for packet in packets[1:]:
        adapter.publish(packet)
    assert packet_hash(adapter.latest()) == packet_hash(packets[-1])
    count = len(writer.calls)
    adapter.publish(packets[-1])
    assert len(writer.calls) == count
    with pytest.raises(ValueError, match="rollback/fork"):
        adapter.publish(packets[0])


@pytest.mark.parametrize("field,value", [("mode", "GOVERNANCE"), ("years", 5), ("sse", "aws:kms")])
def test_retention_and_no_kms_enforced(s3, field, value):
    adapter, reader, writer, packets = s3
    setattr(reader, field, value)
    with pytest.raises(ValueError):
        adapter.publish(packets[1])
    assert not writer.calls


def test_unknown_algorithm_and_unsigned_edit_rejected(s3):
    adapter, _, writer, packets = s3
    packet = copy.deepcopy(packets[1])
    packet["record"]["sig_alg"] = "unknown"
    with pytest.raises(ValueError):
        adapter.publish(packet)
    assert not writer.calls
