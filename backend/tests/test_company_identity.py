import json
from email.utils import parseaddr

import pytest
from django.core import mail as django_mail

from backend.apps.core import mail
from backend.apps.core.company_identity import is_company_address
from backend.apps.core.models import DeliveryJob
from backend.apps.core.services import queue_mail
from backend.tests.test_flows import compose, post


@pytest.fixture(autouse=True)
def approved_address(settings):
    settings.COMPANY_EMAIL_ALLOWLIST = frozenset({"info@kormic.ai"})


@pytest.mark.parametrize(
    "value,expected",
    [
        ("info@kormic.ai", True),
        ("INFO@KORMIC.AI", True),
        ("staff@onesmarter.com", True),
        ("other@kormic.ai", False),
        ("info@kormic.ai.attacker.test", False),
        (" info@kormic.ai", False),
        ("info@kormic.ai\r\nBcc: x@test.com", False),
    ],
)
def test_exact_company_exception(value, expected):
    assert is_company_address(value) is expected
    assert not is_company_address("info@kormic.ai", "other-tenant.test")


@pytest.mark.django_db
def test_admin_can_create_exact_address_but_not_whole_domain(admin_client):
    data = {"name": "Notification Operator", "email": "info@kormic.ai", "role": "admin"}
    assert post(admin_client, "/admin/accounts", data).status_code == 201
    assert (
        post(admin_client, "/admin/accounts", {**data, "email": "other@kormic.ai"}).status_code
        == 400
    )


@pytest.mark.django_db
def test_exception_staff_session_and_sender(staff_client, staff):
    staff.email = staff.username = "info@kormic.ai"
    staff.sender_addresses = ["info@kormic.ai"]
    staff.save()
    assert staff_client.get("/api/dashboard").status_code == 200
    assert (
        compose(staff_client, sender="info@kormic.ai", mode="ordinary", body="Test").status_code
        == 201
    )


@pytest.mark.django_db
def test_notification_uses_staff_profile_not_global(org, sender_profile, settings, staff):
    settings.DEFAULT_FROM_EMAIL = "info@kormic.ai"
    sender_profile["info@kormic.ai"] = {
        **sender_profile["secure@onesmarter.com"],
        "username": "info@kormic.ai",
    }
    from pathlib import Path

    Path(settings.SMTP_SENDER_PROFILES_FILE).write_text(json.dumps(sender_profile))
    job = queue_mail(
        org, {"to": "test@example.test", "subject": "SMTP test", "body": "Fixture"}, actor=staff
    )
    mail.process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "provider_accepted"
    assert job.payload_ciphertext == ""
    assert parseaddr(django_mail.outbox[-1].from_email)[1] == staff.email
    assert django_mail.outbox[-1].alternatives
    assert DeliveryJob.objects.count() == 1
