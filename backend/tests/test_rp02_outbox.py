"""Poison-job isolation and fail-closed, retryable custody outages."""

import json
from datetime import timedelta
from unittest.mock import Mock

import pytest
from django.test import Client
from django.utils import timezone

from backend.apps.core import crypto, document_service, mail
from backend.apps.core.models import DeliveryJob
from backend.apps.core.services import queue_mail
from backend.tests.test_flows import compose, post

pytestmark = pytest.mark.django_db


def queued(staff):
    return queue_mail(
        staff.organization,
        {"to": "recipient@example.test", "subject": "Synthetic notice", "body": "Private fixture"},
        actor=staff,
    )


@pytest.mark.parametrize("damage", ["tamper", "invalid_json", "non_object"])
def test_rp02_poison_outbox_job_must_not_block_later_jobs(staff, staff_client, damage):
    poison = queued(staff)
    if damage == "tamper":
        envelope = json.loads(poison.payload_ciphertext)
        envelope["data"] = crypto.b64(b"tampered authenticated ciphertext")
        ciphertext = json.dumps(envelope)
    else:
        ciphertext = crypto.encrypt(
            b"not-json" if damage == "invalid_json" else b"[]",
            crypto.context(poison.organization_id, "delivery", poison.pk),
        )
    DeliveryJob.objects.filter(pk=poison.pk).update(
        payload_ciphertext=ciphertext, next_attempt=timezone.now() - timedelta(minutes=1)
    )
    queued(staff)
    response = compose(staff_client)
    assert response.status_code == 201
    invitation = DeliveryJob.objects.get(conversation_id=response.json()["id"])
    token = mail.payload(invitation)["link"].split("/")[-1]
    assert post(Client(), "/recipient/code", {"token": token}).status_code == 200
    later = list(DeliveryJob.objects.exclude(pk=poison.pk))
    assert any(mail.payload(job).get("challenge_id") for job in later)
    mail.process_pending()
    poison.refresh_from_db()
    assert poison.state == "failed" and poison.error_code == "payload_unverifiable"
    assert poison.attempts == 0
    assert DeliveryJob.objects.filter(
        pk__in=[job.pk for job in later], state="development_delivered"
    ).count() == len(later)
    mail.process_pending()
    poison.refresh_from_db()
    assert poison.attempts == 0


@pytest.mark.parametrize("batch", [False, True])
def test_rp02_sealed_non_conversation_jobs_retry_without_smtp(staff, settings, monkeypatch, batch):
    jobs = [queued(staff), queued(staff)]
    originals = [job.payload_ciphertext for job in jobs]
    settings.MAIL_PROVIDER = "smtp"
    status = Mock(return_value={"sealed": True})
    monkeypatch.setattr(document_service, "read_status", status)
    connection = Mock(side_effect=AssertionError("SMTP must not be created while sealed"))
    monkeypatch.setattr(mail.smtp_settings, "connection", connection)
    monkeypatch.setattr(mail.smtp_settings, "otp_connection", connection)
    original_payload = mail.payload
    decrypt = Mock(side_effect=AssertionError("Do not decrypt when readiness is false"))
    monkeypatch.setattr(mail, "payload", decrypt)
    before = timezone.now()
    if batch:
        mail.process_pending()
    else:
        for job in jobs:
            mail.process_job(job.pk)
    for job, original in zip(jobs, originals, strict=True):
        job.refresh_from_db()
        assert job.state in {"queued", "retry"}
        assert job.error_code == "service_disabled"
        assert job.next_attempt >= before + timedelta(seconds=15)
        assert job.attempts == 0 and job.payload_ciphertext == original
    assert status.call_count == 2
    connection.assert_not_called()
    decrypt.assert_not_called()
    # Unseal and release the backoff: the same retained jobs can complete.
    status.return_value = {"sealed": False, "suite": document_service.SUITE}
    monkeypatch.setattr(mail, "payload", original_payload)
    settings.MAIL_PROVIDER = "development"
    DeliveryJob.objects.filter(pk__in=[job.pk for job in jobs]).update(next_attempt=timezone.now())
    mail.process_pending()
    assert (
        DeliveryJob.objects.filter(
            pk__in=[job.pk for job in jobs], state="development_delivered"
        ).count()
        == 2
    )


def test_rp02_seal_between_admission_and_decryption_retries(staff, monkeypatch):
    job = queued(staff)
    monkeypatch.setattr(document_service, "ready", Mock(side_effect=[True, False]))
    monkeypatch.setattr(mail, "payload", Mock(side_effect=crypto.CryptoUnavailable("sealed")))
    connection = Mock()
    monkeypatch.setattr(mail.smtp_settings, "connection", connection)
    mail.process_job(job.pk)
    job.refresh_from_db()
    assert job.state in {"queued", "retry"} and job.error_code == "service_disabled"
    assert job.next_attempt > timezone.now() and job.attempts == 0
    connection.assert_not_called()


@pytest.mark.parametrize("stage", ["credential_decryption", "before_open"])
def test_rp02_seal_after_payload_does_not_open_smtp(staff, sender_profile, monkeypatch, stage):
    job = queued(staff)
    monkeypatch.setattr(document_service, "ready", Mock(side_effect=[True, False]))
    backend = Mock()
    connection = Mock(return_value=(staff.email, backend))
    if stage == "credential_decryption":
        connection.side_effect = crypto.CryptoUnavailable("sealed during credentials")
    monkeypatch.setattr(mail.smtp_settings, "connection", connection)
    send = Mock(return_value=1)
    monkeypatch.setattr(mail.EmailMultiAlternatives, "send", send)
    mail.process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "retry" and job.error_code == "service_disabled"
    assert job.next_attempt > timezone.now()
    backend.open.assert_not_called()
    send.assert_not_called()


def test_rp02_sealing_mid_batch_defers_later_job(staff, monkeypatch):
    first, second = queued(staff), queued(staff)
    monkeypatch.setattr(document_service, "ready", Mock(side_effect=[True, False]))
    mail.process_pending()
    first.refresh_from_db()
    second.refresh_from_db()
    assert first.state == "development_delivered"
    assert second.state == "queued" and second.error_code == "service_disabled"


@pytest.mark.parametrize("claimed", [False, True])
def test_rp02_unexpected_failure_is_isolated_without_unsafe_resend(
    staff, monkeypatch, caplog, claimed
):
    poison, later = queued(staff), queued(staff)
    original = mail.process_job

    def process(ident):
        if ident == poison.pk:
            if claimed:
                DeliveryJob.objects.filter(pk=ident).update(state="sending")
            raise RuntimeError("PRIVATE-PAYLOAD-AND-TOKEN-MUST-NOT-BE-LOGGED")
        original(ident)

    monkeypatch.setattr(mail, "process_job", process)
    mail.process_pending()
    poison.refresh_from_db()
    later.refresh_from_db()
    assert later.state == "development_delivered"
    if claimed:
        assert poison.state == "sending"  # Existing stale-job recovery marks this uncertain.
    else:
        assert poison.state == "queued" and poison.error_code == "job_processing_failed"
        assert poison.next_attempt > timezone.now()
    assert str(poison.pk) in caplog.text
    assert "PRIVATE-PAYLOAD" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
