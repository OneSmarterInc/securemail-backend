"""Explicit opt-in AWS drill. Creates a synthetic object locked for ONE DAY.

Never target a production bucket. Live credentials and retention authorization
must be provided separately; ordinary test/CI runs skip this module.
"""

import os
import uuid
from datetime import timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from django.utils import timezone

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_AWS_ARCHIVE_INTEGRATION") != "1",
    reason="Requires an explicitly authorized disposable AWS Object Lock test bucket",
)


def test_live_compliance_delete_and_retention_shortening_denied():
    bucket = os.environ["AUDIT_TEST_BUCKET"]
    if not bucket.startswith("onesmarter-readiness-"):
        pytest.fail("Use a dedicated bucket named onesmarter-readiness-...")
    client = boto3.client("s3", region_name=os.environ["AWS_REGION"])
    lock = client.get_object_lock_configuration(Bucket=bucket)["ObjectLockConfiguration"]
    assert lock["ObjectLockEnabled"] == "Enabled"
    # A default rule would also retain the control; require an empty drill bucket configuration.
    assert not lock.get("Rule"), "Use a dedicated test bucket without default retention"
    prefix = "synthetic-drill/" + str(uuid.uuid4())
    control = client.put_object(
        Bucket=bucket,
        Key=prefix + "-control",
        Body=b"synthetic control",
        ServerSideEncryption="AES256",
    )
    client.delete_object(Bucket=bucket, Key=prefix + "-control", VersionId=control["VersionId"])
    until = (timezone.now() + timedelta(days=1)).replace(microsecond=0)
    result = client.put_object(
        Bucket=bucket,
        Key=prefix,
        Body=b"synthetic retained evidence",
        ServerSideEncryption="AES256",
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=until,
    )
    args = {"Bucket": bucket, "Key": prefix, "VersionId": result["VersionId"]}
    assert client.get_object_retention(**args)["Retention"]["Mode"] == "COMPLIANCE"
    with pytest.raises(ClientError) as denied:
        client.delete_object(**args)
    assert denied.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
    with pytest.raises(ClientError) as denied:
        client.put_object_retention(
            **args, Retention={"Mode": "COMPLIANCE", "RetainUntilDate": until - timedelta(hours=12)}
        )
    assert denied.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
    # A new version must not overwrite the retained version's bytes.
    newer = client.put_object(
        Bucket=bucket, Key=prefix, Body=b"new synthetic version", ServerSideEncryption="AES256"
    )
    stream = client.get_object(**args)["Body"]
    try:
        assert stream.read() == b"synthetic retained evidence"
    finally:
        stream.close()
    client.delete_object(Bucket=bucket, Key=prefix, VersionId=newer["VersionId"])
