import hashlib
import os
import tempfile
from pathlib import Path

import boto3
from django.conf import settings

from backend.performance import timed

from .http import Problem


@timed("storage_write")
def put(key: str, value: bytes):
    if settings.STORAGE_PROVIDER == "s3":
        boto3.client("s3", region_name=settings.AWS_REGION).put_object(
            Bucket=settings.S3_BUCKET,
            Key=key,
            Body=value,
            ServerSideEncryption="AES256",
            ContentType="application/octet-stream",
        )
    elif settings.STORAGE_PROVIDER == "local":
        path = settings.RUNTIME_DIR / "objects" / hashlib.sha256(key.encode()).hexdigest()
        path.parent.mkdir(parents=True, exist_ok=True)
        # Never expose a partially written ciphertext after a failed write.
        descriptor, temporary = tempfile.mkstemp(prefix=".upload-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    else:
        raise Problem("Private storage is unavailable.", "storage_unavailable", 503)


@timed("storage_read")
def get(key: str) -> bytes:
    # Object keys are generated internally, never accepted from API callers.
    if settings.STORAGE_PROVIDER == "s3":
        return (
            boto3.client("s3", region_name=settings.AWS_REGION)
            .get_object(Bucket=settings.S3_BUCKET, Key=key)["Body"]
            .read()
        )
    if settings.STORAGE_PROVIDER == "local":
        return (
            settings.RUNTIME_DIR / "objects" / hashlib.sha256(key.encode()).hexdigest()
        ).read_bytes()
    raise Problem("Private storage is unavailable.", "storage_unavailable", 503)


def remove(key: str):
    if settings.STORAGE_PROVIDER == "s3":
        boto3.client("s3", region_name=settings.AWS_REGION).delete_object(
            Bucket=settings.S3_BUCKET, Key=key
        )
    elif settings.STORAGE_PROVIDER == "local":
        (settings.RUNTIME_DIR / "objects" / hashlib.sha256(key.encode()).hexdigest()).unlink(
            missing_ok=True
        )


def validate_file(name: str, data: bytes) -> tuple[str, str]:
    clean = Path(name.replace("\\", "/")).name
    if not clean or len(clean) > 180 or any(ord(c) < 32 for c in clean):
        raise Problem("Choose a file with a valid filename.")
    suffix = Path(clean).suffix.lower()
    expected = {
        ".pdf": (b"%PDF-", "application/pdf"),
        ".png": (b"\x89PNG\r\n\x1a\n", "image/png"),
        ".jpg": (b"\xff\xd8\xff", "image/jpeg"),
        ".jpeg": (b"\xff\xd8\xff", "image/jpeg"),
    }
    if suffix == ".txt":
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Problem("Text files must use UTF-8.") from exc
        if b"\x00" in data:
            raise Problem("Invalid text file.")
        return clean, "text/plain"
    if suffix not in expected or not data.startswith(expected[suffix][0]):
        raise Problem(
            "Supported files: PDF, PNG, JPEG and UTF-8 text with matching content.",
            "file_type_rejected",
        )
    return clean, expected[suffix][1]
