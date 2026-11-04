import json
from io import StringIO

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from backend.apps.core import crypto, keyring, storage
from backend.apps.core.key_migration import migrate
from backend.apps.core.models import Attachment, DeliveryJob
from backend.tests.test_flows import compose

pytestmark = pytest.mark.django_db


def test_rejected_mfa_does_not_block_later_records_or_repeat_batches(
    staff_client, staff, org, monkeypatch
):
    context = crypto.context(org.pk, "mfa", staff.pk)
    staff.mfa_secret = crypto.encrypt(b"synthetic MFA seed", context)
    staff.save(update_fields=["mfa_secret"])
    original = staff.mfa_secret
    compose(staff_client)
    job = DeliveryJob.objects.get()
    active = keyring.rotate(org)
    real_rewrap = crypto.rewrap

    def reject_mfa(value, purpose):
        if purpose == context:
            raise crypto.CryptoUnavailable("Missing MFA pin")
        return real_rewrap(value, purpose)

    monkeypatch.setattr(crypto, "rewrap", reject_mfa)
    # A skipped MFA must not consume the batch allowance and starve delivery rows.
    for _ in range(4):
        migrate(org, apply=True, limit=1)
    staff.refresh_from_db()
    job.refresh_from_db()
    assert staff.mfa_secret == original
    assert json.loads(job.payload_ciphertext)["key_id"] == str(active.pk)
    result = migrate(org, apply=True)
    assert result["updated"] == result["candidates"] == 0
    assert result["skipped_crypto_unavailable"] == 1
    output = StringIO()
    call_command("rewrap_keys", organization=str(org.pk), apply=True, stdout=output)
    assert "skipped crypto unavailable: 1" in output.getvalue()
    assert "Migration incomplete" in output.getvalue()
    assert original not in output.getvalue()
    monkeypatch.setattr(crypto, "rewrap", real_rewrap)
    assert migrate(org, apply=True)["updated"] == 1
    staff.refresh_from_db()
    assert crypto.decrypt(staff.mfa_secret, context) == b"synthetic MFA seed"


def test_failed_attachment_rewrap_preserves_all_fields_and_original_object(
    staff_client, org, monkeypatch
):
    response = staff_client.post(
        "/api/attachments", {"file": SimpleUploadedFile("sample.txt", b"test bytes")}
    )
    assert response.status_code == 201
    attachment = Attachment.objects.get(pk=response.json()["id"])
    before = (attachment.name_ciphertext, attachment.object_key, attachment.stored_size)
    original_file = storage.get(attachment.object_key)
    keyring.rotate(org)
    real_rewrap = crypto.rewrap
    put = storage.put
    writes = []

    def track_put(*args):
        writes.append(args[0])
        return put(*args)

    def reject_file(value, context):
        if value == original_file.decode():
            raise crypto.CryptoUnavailable("Key service rejected file")
        return real_rewrap(value, context)

    monkeypatch.setattr(storage, "put", track_put)
    monkeypatch.setattr(crypto, "rewrap", reject_file)
    result = migrate(org, apply=True)
    assert result["skipped_crypto_unavailable"] == 1
    attachment.refresh_from_db()
    assert (attachment.name_ciphertext, attachment.object_key, attachment.stored_size) == before
    assert storage.get(attachment.object_key) == original_file
    assert writes == []
    monkeypatch.setattr(crypto, "rewrap", real_rewrap)
    assert migrate(org, apply=True)["updated"] == 1


def test_dry_run_does_not_claim_unwrap_verification(staff_client, org, monkeypatch):
    compose(staff_client)
    keyring.rotate(org)

    def unavailable(*args):
        raise AssertionError("Dry run must not rewrap")

    monkeypatch.setattr(crypto, "rewrap", unavailable)
    result = migrate(org)
    assert result["candidates"] > 0
    assert result["skipped_crypto_unavailable"] == 0
    output = StringIO()
    call_command("rewrap_keys", organization=str(org.pk), stdout=output)
    assert "Dry runs do not verify service unwrap eligibility" in output.getvalue()
