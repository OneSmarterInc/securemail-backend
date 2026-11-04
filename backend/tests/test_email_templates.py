import pytest
from django.core import mail

from backend.apps.core.email_templates import notification_html
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
