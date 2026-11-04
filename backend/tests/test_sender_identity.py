from email.utils import parseaddr

import pytest
from django.core import mail

from backend.apps.core.mail import process_job
from backend.apps.core.models import DeliveryJob
from backend.tests.test_flows import compose


@pytest.mark.django_db
def test_global_notification_sender_is_ignored(staff_client, sender_profile, settings, monkeypatch):
    compose(staff_client)
    settings.DEFAULT_FROM_EMAIL = "info@kormic.ai"
    calls = []
    job = DeliveryJob.objects.get()
    process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "provider_accepted"
    assert parseaddr(mail.outbox[-1].from_email)[1] == "staff@onesmarter.com"
    assert not calls


@pytest.mark.django_db
def test_normal_sender_authority_rechecked(staff_client, staff, sender_profile):
    staff.can_nophi = True
    staff.save(update_fields=["can_nophi"])
    assert (
        compose(
            staff_client,
            mode="ordinary",
            body="Synthetic test",
            to=["colleague@onesmarter.com"],
            nophi_override=True,
            nophi_acknowledged=True,
        ).status_code
        == 201
    )
    staff.sender_addresses = []
    staff.save(update_fields=["sender_addresses"])
    job = DeliveryJob.objects.get()
    process_job(job.pk)
    job.refresh_from_db()
    assert job.error_code == "sender_not_configured"
    assert not mail.outbox


@pytest.mark.django_db
def test_normal_mail_uses_approved_sender(staff_client, staff, sender_profile):
    staff.can_nophi = True
    staff.save(update_fields=["can_nophi"])
    assert (
        compose(
            staff_client,
            mode="ordinary",
            body="Synthetic test",
            to=["colleague@onesmarter.com"],
            nophi_override=True,
            nophi_acknowledged=True,
        ).status_code
        == 201
    )
    job = DeliveryJob.objects.get()
    process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "provider_accepted"
    assert parseaddr(mail.outbox[0].from_email)[1] == "staff@onesmarter.com"
