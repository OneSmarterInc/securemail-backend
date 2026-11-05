import pytest
from django.core import mail

from backend.apps.core.email_templates import notification_content, notification_html
from backend.apps.core.mail import process_job
from backend.apps.core.models import DeliveryJob
from backend.tests.test_flows import compose


def test_email_html_escapes_text_and_link():
    html = notification_html(
        {
            "subject": "<script>alert(1)</script>",
            "body": "<img src=x onerror=alert(1)>",
            "link": 'https://example.test/recipient/#/invite/a?x="bad"',
        },
        protected=True,
    )
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "&quot;bad&quot;" in html
    assert "Open secure portal" in html


def test_email_rejects_active_link():
    with pytest.raises(ValueError):
        notification_html(
            {"subject": "test", "body": "test", "link": "javascript:alert(1)"}, protected=True
        )


@pytest.mark.parametrize("kind", ["otp", "booking", "update"])
def test_selfpay_notifications_share_brand_and_escape_content(kind):
    data = {
        "subject": "MySelfPay <script>notification</script>",
        "body": "Dear <img src=x onerror=alert(1)>\nKind regards,\nOneSmarter Support\nSupporting MySelfPay communications",
        "link": "https://example.test/recipient/inbox?source=selfpay#thread/synthetic",
    }
    if kind == "otp":
        data.update(portal_challenge_id="synthetic", body="Your one-time code is 123456.")
        data.pop("link")
    elif kind == "booking":
        data["notification_kind"] = "selfpay_clinic_request"
    original = dict(data)
    html = notification_html(data, protected=False, source="selfpay")
    assert "MySelf" in html and "Patient Care" in html
    assert "#b01b23" in html and "#087f80" not in html
    assert "OneSmarter Support" not in html
    assert "<script>" not in html and "<img src=x" not in html
    assert "About MySelfPay" in html
    assert "reply securely" not in html
    if kind == "otp":
        assert html.count("123456") == 1
        assert "Your MySelfPay verification code" in html
    else:
        assert "&lt;img" in html
    assert data == original
    assert "OneSmarter Support" not in notification_content(data, source="selfpay")["body"]


def test_payload_brand_hint_cannot_change_other_notification_theme():
    html = notification_html(
        {"subject": "Other notification", "body": "Body", "portal_source": "selfpay"},
        protected=False,
    )
    assert "#087f80" in html
    assert "About MySelfPay" not in html


def test_selfpay_rejects_active_link():
    with pytest.raises(ValueError):
        notification_html(
            {"subject": "test", "body": "test", "link": "javascript:alert(1)"},
            protected=False,
            source="selfpay",
        )


@pytest.mark.django_db
def test_notification_has_plain_text_and_html_without_document_contents(
    staff_client, settings, sender_profile
):
    settings.MAIL_PROVIDER = "smtp"
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    settings.EMAIL_HOST_USER = "test-only"
    settings.EMAIL_HOST_PASSWORD = "test-only"
    response = compose(
        staff_client,
        subject="Private subject must stay in portal",
        body="Private body must stay in portal",
    )
    job = DeliveryJob.objects.get(conversation_id=response.json()["id"])
    process_job(job.pk)
    message = mail.outbox[0]
    assert "http" in message.body
    assert len(message.alternatives) == 1
    assert message.alternatives[0].mimetype == "text/html"
    rendered = message.message().as_string()
    assert "Private subject must stay in portal" not in rendered
    assert "Private body must stay in portal" not in rendered
    assert not message.attachments
    job.refresh_from_db()
    assert job.state == "provider_accepted"
