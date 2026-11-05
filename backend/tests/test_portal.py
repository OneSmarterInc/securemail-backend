import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from backend.apps.core import mail, portal
from backend.apps.core.models import DeliveryJob
from backend.apps.core.portal_models import (
    PortalChallenge,
    PortalMailbox,
    PortalMessage,
    PortalParticipant,
    PortalSession,
    PortalThread,
)

pytestmark = pytest.mark.django_db
SECRET = "synthetic-integration-secret-for-isolated-tests-only"


@pytest.fixture
def configured(settings, staff):
    settings.SECURE_MAIL_INTEGRATIONS = {
        "selfpay": {
            "enabled": True,
            "secret": SECRET,
            "owner_id": staff.pk,
            "name": "MySelfPay",
            "suppress_provider_notifications": True,
        }
    }
    return staff


def payload(ident="MSP-SYNTHETIC", patient="patient@example.test", provider="clinic@example.test"):
    return {
        "external_id": ident,
        "subject": "Appointment · Synthetic Clinic",
        "body": "Patient requests three preferred dates. Synthetic data only.",
        "participants": [
            {"email": patient, "name": "Synthetic Jamie", "role": "requester"},
            {"email": provider, "name": "Synthetic Clinic", "role": "provider"},
        ],
    }


def signed(client, data, *, nonce=None, stamp=None, signature=None):
    body = json.dumps(data).encode()
    nonce = nonce or uuid.uuid4().hex
    stamp = stamp or str(int(time.time()))
    path = "/api/integrations/threads"
    canonical = "\n".join(["POST", path, "selfpay", stamp, nonce, hashlib.sha256(body).hexdigest()])
    digest = signature or hmac.new(SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return client.post(
        path,
        body,
        content_type="application/json",
        HTTP_X_INTEGRATION_KEY="selfpay",
        HTTP_X_INTEGRATION_TIME=stamp,
        HTTP_X_INTEGRATION_NONCE=nonce,
        HTTP_X_INTEGRATION_SIGNATURE=digest,
    )


def browser():
    client = Client(enforce_csrf_checks=True)
    result = client.get("/recipient-api/inbox/session")
    assert result.status_code == 200
    return client


def post(client, path, data=None, **headers):
    return client.post(
        "/recipient-api/inbox/" + path,
        json.dumps(data or {}),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value,
        **headers,
    )


def login(address, client=None):
    client = client or browser()
    response = post(client, "code", {"email": address, "source": "selfpay"})
    assert response.status_code == 200, response.content
    challenge_id = response.json()["challenge_id"]
    jobs = [mail.payload(job) for job in DeliveryJob.objects.all()]
    job = next(item for item in jobs if item.get("portal_challenge_id") == challenge_id)
    code = re.search(r"code is (\d{6})", job["body"])[1]
    result = post(client, "verify", {"code": code})
    assert result.status_code == 200, result.content
    return client, code


def test_service_auth_replay_idempotency_and_ciphertext(configured):
    client = Client(enforce_csrf_checks=True)
    nonce = uuid.uuid4().hex
    assert signed(client, payload(), signature="bad").status_code == 401
    assert signed(client, payload(), stamp=str(int(time.time()) - 600)).status_code == 401
    response = signed(client, payload(), nonce=nonce)
    assert response.status_code == 201, response.content
    assert signed(client, payload(), nonce=nonce).status_code == 409
    assert signed(client, payload()).json()["id"] == response.json()["id"]
    changed = payload()
    changed["body"] = "Changed"
    assert signed(client, changed).status_code == 409
    assert PortalThread.objects.count() == 1
    assert "Jamie" not in PortalThread.objects.get().metadata_ciphertext
    assert all("Synthetic" not in m.body_ciphertext for m in PortalMessage.objects.all())
    assert all(
        "@" not in value
        for value in PortalMailbox.objects.values_list("email_ciphertext", flat=True)
    )
    # The clinic is suppressed; the patient receives their own generic invitation.
    assert mail.payload(DeliveryJob.objects.get())["to"] == "patient@example.test"


def test_patient_clinic_inboxes_replies_search_unread_and_isolation(configured):
    service = Client()
    first = signed(service, payload()).json()["id"]
    second = signed(service, payload("MSP-SECOND", provider="otherclinic@example.test")).json()[
        "id"
    ]
    foreign = signed(
        service,
        payload(
            "MSP-FOREIGN", patient="otherpatient@example.test", provider="otherclinic@example.test"
        ),
    ).json()["id"]
    patient, _ = login("patient@example.test")
    clinic, _ = login("clinic@example.test")

    def inbox(c, query=""):
        return c.get("/recipient-api/inbox/threads", {"q": query}).json()["results"]

    assert {row["id"] for row in inbox(patient)} == {first, second}
    assert [row["id"] for row in inbox(clinic)] == [first]
    assert inbox(patient, "does not exist") == []
    assert inbox(patient, "synthetic clinic")
    assert patient.get("/recipient-api/inbox/threads/" + foreign).status_code == 404
    assert clinic.get("/recipient-api/inbox/threads/" + second).status_code == 404
    assert (
        post(
            clinic,
            "threads/" + second,
            {"body": "intrusion"},
            HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
        ).status_code
        == 404
    )
    assert inbox(patient)[0]["unread"]
    assert patient.get("/recipient-api/inbox/threads/" + first).status_code == 200
    assert not next(row for row in inbox(patient) if row["id"] == first)["unread"]
    key = uuid.uuid4().hex
    response = post(
        clinic,
        "threads/" + first,
        {"body": "We can arrange your appointment."},
        HTTP_IDEMPOTENCY_KEY=key,
    )
    assert response.status_code == 201, response.content
    assert (
        post(
            clinic,
            "threads/" + first,
            {"body": "We can arrange your appointment."},
            HTTP_IDEMPOTENCY_KEY=key,
        ).status_code
        == 200
    )
    assert (
        post(
            clinic, "threads/" + first, {"body": "Different"}, HTTP_IDEMPOTENCY_KEY=key
        ).status_code
        == 409
    )
    assert inbox(patient)[0]["id"] == first and inbox(patient)[0]["unread"]
    detail = patient.get("/recipient-api/inbox/threads/" + first).json()
    assert detail["messages"][-1]["sender"] == "Synthetic Clinic"
    assert not detail["messages"][-1]["mine"]
    assert (
        post(
            patient,
            "threads/" + first,
            {"body": "Thank you"},
            HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
        ).status_code
        == 201
    )
    assert not any(
        mail.payload(job).get("portal_thread") and mail.payload(job)["to"] == "clinic@example.test"
        for job in DeliveryJob.objects.all()
    )


def test_otp_browser_binding_single_use_attempt_limit_and_unknown_mailbox(configured):
    signed(Client(), payload())
    patient, code = login("patient@example.test")
    assert post(patient, "verify", {"code": code}).status_code == 400
    attacker = browser()
    assert post(attacker, "verify", {"code": code}).status_code == 400
    assert attacker.get("/recipient-api/inbox/threads").status_code == 401
    count = DeliveryJob.objects.count()
    assert (
        post(attacker, "code", {"source": "selfpay", "email": "unknown@example.test"}).status_code
        == 200
    )
    assert DeliveryJob.objects.count() == count
    assert post(attacker, "verify", {"code": "000000"}).status_code == 400
    another = browser()
    issued = post(another, "code", {"source": "selfpay", "email": "clinic@example.test"}).json()
    for _ in range(5):
        assert post(another, "verify", {"code": "xxxxxx"}).status_code == 400
    challenge = PortalChallenge.objects.get(pk=issued["challenge_id"])
    challenge.verifier = portal.keyed(f"portal:{challenge.pk}:123456", purpose="otp")
    challenge.save()
    for _ in range(5):
        assert post(another, "verify", {"code": "654321"}).status_code == 400
    assert post(another, "verify", {"code": "123456"}).status_code == 400


def test_session_expiry_revocation_csrf_and_no_poll_renewal(configured):
    ident = signed(Client(), payload()).json()["id"]
    patient, _ = login("patient@example.test")
    session = PortalSession.objects.get()
    before = session.expires_at
    assert patient.get("/recipient-api/inbox/threads").status_code == 200
    session.refresh_from_db()
    assert session.expires_at == before
    assert (
        patient.post("/recipient-api/inbox/threads/" + ident, {"body": "bad csrf"}).status_code
        == 403
    )
    member = PortalParticipant.objects.get(mailbox=session.mailbox)
    member.revoked_at = timezone.now()
    member.save()
    assert patient.get("/recipient-api/inbox/threads/" + ident).status_code == 404
    session.expires_at = timezone.now() - timedelta(seconds=1)
    session.save()
    assert patient.get("/recipient-api/inbox/threads").status_code == 401
    assert post(patient, "activity").status_code == 401


def test_delayed_worker_checks_suppression_revocation_and_otp(configured, settings):
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["suppress_provider_notifications"] = False
    ident = signed(Client(), payload()).json()["id"]
    job = next(
        j for j in DeliveryJob.objects.all() if mail.payload(j)["to"] == "clinic@example.test"
    )
    data = mail.payload(job)
    assert portal.delivery_allowed(data, job)
    thread = PortalThread.objects.get(pk=ident)
    thread.revoked_at = timezone.now()
    thread.save()
    assert not portal.delivery_allowed(data, job)
    thread.revoked_at = None
    thread.save()
    client, _ = login("patient@example.test")
    otp_job = next(
        j for j in DeliveryJob.objects.all() if mail.payload(j).get("portal_challenge_id")
    )
    assert not portal.delivery_allowed(mail.payload(otp_job), otp_job)
    assert post(client, "logout").status_code == 200
    assert client.get("/recipient-api/inbox/threads").status_code == 401


def test_disabled_integration_and_cross_tenant(configured, settings, org):
    from backend.apps.core.models import Organization, StaffUser

    signed(Client(), payload())
    other_org = Organization.objects.create(name="Other organization", domain="other.test")
    owner = StaffUser.objects.create_user(
        username="other",
        email="staff@other.test",
        organization=other_org,
        status="active",
        mfa_confirmed=True,
    )
    settings.SECURE_MAIL_INTEGRATIONS["other"] = {
        **settings.SECURE_MAIL_INTEGRATIONS["selfpay"],
        "owner_id": owner.pk,
    }
    client = browser()
    before = DeliveryJob.objects.count()
    assert (
        post(client, "code", {"email": "patient@example.test", "source": "other"}).status_code
        == 200
    )
    assert DeliveryJob.objects.count() == before
    patient, _ = login("patient@example.test")
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["enabled"] = False
    assert patient.get("/recipient-api/inbox/threads").json()["results"] == []


def test_encryption_unavailable_fails_closed(configured, monkeypatch):
    signed(Client(), payload())
    patient, _ = login("patient@example.test")

    def sealed(*args, **kwargs):
        raise portal.crypto.CryptoUnavailable("Synthetic sealed key service")

    monkeypatch.setattr(portal.crypto, "decrypt", sealed)
    response = patient.get("/recipient-api/inbox/threads")
    assert response.status_code == 503
    assert "Synthetic Jamie" not in response.content.decode()
    assert "Synthetic Clinic" not in response.content.decode()


def test_message_history_pagination_and_eight_hour_limit(configured):
    ident = signed(Client(), payload()).json()["id"]
    patient, _ = login("patient@example.test")
    thread = PortalThread.objects.get(pk=ident)
    mailbox = PortalSession.objects.get().mailbox
    for number in range(52):
        message = PortalMessage(
            thread=thread,
            sender=mailbox,
            submission_key=f"synthetic-{number}",
            fingerprint="synthetic",
        )
        message.body_ciphertext = portal.encrypt(
            f"Message {number}", thread.organization_id, "portal-message", message.pk
        )
        message.save()
    current = patient.get("/recipient-api/inbox/threads/" + ident).json()
    assert len(current["messages"]) == 50 and current["next_before"]
    older = patient.get(
        "/recipient-api/inbox/threads/" + ident, {"before": current["next_before"]}
    ).json()
    assert len(older["messages"]) == 3
    assert not {m["id"] for m in current["messages"]} & {m["id"] for m in older["messages"]}
    PortalSession.objects.update(
        created_at=timezone.now() - timedelta(hours=9),
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    assert patient.get("/recipient-api/inbox/threads").status_code == 401


def test_confirmation_action_is_clinic_only_and_not_in_notifications(configured, settings):
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["provider_action_origins"] = [
        "https://selfpay.example.test"
    ]
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["suppress_provider_notifications"] = False
    data = payload("MSP-CONFIRM")
    action = {
        "url": "https://selfpay.example.test/#clinic/MSP-CONFIRM/private-test-token",
        "expires_at": time.time() + 3600,
    }
    data["provider_action"] = action
    response = signed(Client(), data)
    assert response.status_code == 201, response.content
    ident = response.json()["id"]
    assert signed(Client(), data).json()["id"] == ident
    assert all(
        "private-test-token" not in json.dumps(mail.payload(job))
        for job in DeliveryJob.objects.all()
    )
    assert "private-test-token" not in PortalThread.objects.get(pk=ident).metadata_ciphertext
    patient, _ = login("patient@example.test")
    clinic, _ = login("clinic@example.test")
    patient_detail = patient.get("/recipient-api/inbox/threads/" + ident)
    assert patient_detail.status_code == 200
    assert patient_detail.json()["provider_action"] is None
    assert "private-test-token" not in patient_detail.content.decode()
    assert clinic.get("/recipient-api/inbox/threads/" + ident).json()["provider_action"] == action
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["provider_action_origins"] = []
    assert clinic.get("/recipient-api/inbox/threads/" + ident).json()["provider_action"] is None


def test_confirmation_action_requires_allowed_origin(configured, settings):
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["provider_action_origins"] = [
        "https://selfpay.example.test"
    ]
    for url in [
        "https://untrusted.example.test/confirm",
        "javascript:alert(1)",
        "https://user:pass@selfpay.example.test/confirm",
    ]:
        data = payload()
        data["provider_action"] = {"url": url, "expires_at": time.time() + 3600}
        assert signed(Client(), data).status_code == 400
    assert PortalThread.objects.count() == 0


@pytest.mark.parametrize("dedicated", [False, True])
@pytest.mark.parametrize(
    "kind", ["invitation", "clinic_invitation", "otp", "reply", "confirmation"]
)
def test_selfpay_notifications_use_environment_smtp(
    configured, settings, monkeypatch, kind, dedicated
):
    from email.utils import parseaddr
    from unittest.mock import Mock

    from backend.apps.core import smtp_settings
    from backend.apps.core.models import OrganizationSMTP, StaffSMTP

    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["suppress_provider_notifications"] = False
    response = signed(Client(), payload())
    assert response.status_code == 201
    thread_id = response.json()["id"]
    if kind == "otp":
        client = browser()
        assert (
            post(client, "code", {"email": "patient@example.test", "source": "selfpay"}).status_code
            == 200
        )
        job = next(
            j for j in DeliveryJob.objects.all() if mail.payload(j).get("portal_challenge_id")
        )
    elif kind == "confirmation":
        assert (
            signed(
                Client(),
                {
                    "event_type": "booking_confirmed",
                    "external_id": "MSP-SYNTHETIC",
                    "event_id": "smtp-test-confirmation",
                    "body": "Synthetic confirmation",
                },
            ).status_code
            == 201
        )
        job = DeliveryJob.objects.latest("created_at")
    elif kind == "clinic_invitation":
        job = next(
            j for j in DeliveryJob.objects.all() if mail.payload(j)["to"] == "clinic@example.test"
        )
    elif kind == "reply":
        client, _ = login("patient@example.test")
        assert (
            post(
                client,
                "threads/" + thread_id,
                {"body": "Synthetic reply"},
                HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex,
            ).status_code
            == 201
        )
        job = next(
            j
            for j in DeliveryJob.objects.all()
            if mail.payload(j)["subject"] == "New secure message"
        )
    else:
        job = DeliveryJob.objects.order_by("created_at").first()
    assert not OrganizationSMTP.objects.exists()
    assert not StaffSMTP.objects.exists()
    settings.MAIL_PROVIDER = "smtp"
    settings.EMAIL_HOST = "smtp.example.test"
    settings.EMAIL_PORT = 465
    settings.EMAIL_USE_TLS = False
    settings.EMAIL_USE_SSL = True
    settings.EMAIL_HOST_USER = "environment-login@example.test"
    settings.EMAIL_HOST_PASSWORD = "synthetic-environment-password"
    settings.SELFPAY_SMTP_ENABLED = dedicated
    settings.SELFPAY_EMAIL_HOST = "smtp.ionos.com"
    settings.SELFPAY_EMAIL_PORT = 587
    settings.SELFPAY_EMAIL_USE_TLS = True
    settings.SELFPAY_EMAIL_USE_SSL = False
    settings.SELFPAY_EMAIL_HOST_USER = "patientcare@onesmarterhealthweb.com"
    settings.SELFPAY_EMAIL_HOST_PASSWORD = "synthetic-selfpay-password"
    settings.SELFPAY_FROM_EMAIL = "patientcare@onesmarterhealthweb.com"
    transport = Mock()
    transport.send_messages.return_value = 1
    factory = Mock(return_value=transport)
    monkeypatch.setattr(smtp_settings, "SMTPBackend", factory)
    mail.process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "provider_accepted"
    assert factory.call_args.kwargs["host"] == (
        settings.SELFPAY_EMAIL_HOST if dedicated else settings.EMAIL_HOST
    )
    assert factory.call_args.kwargs["username"] == (
        settings.SELFPAY_EMAIL_HOST_USER if dedicated else settings.EMAIL_HOST_USER
    )
    assert factory.call_args.kwargs["password"] == (
        settings.SELFPAY_EMAIL_HOST_PASSWORD if dedicated else settings.EMAIL_HOST_PASSWORD
    )
    assert factory.call_args.kwargs["use_ssl"] is (not dedicated)
    assert factory.call_args.kwargs["use_tls"] is dedicated
    message = transport.send_messages.call_args.args[0][0]
    expected_sender = (
        "patientcare@onesmarterhealthweb.com" if dedicated else "support@onesmarter.com"
    )
    assert parseaddr(message.from_email)[1] == expected_sender
    assert parseaddr(message.from_email)[0] == "Patient Care"
    assert message.reply_to == [expected_sender]
    assert message.alternatives[0].mimetype == "text/html"
    assert "#b01b23" in message.alternatives[0].content
    assert "About MySelfPay" in message.alternatives[0].content
    assert "OneSmarter Support" not in message.body


def test_queued_portal_smtp_source_is_scoped_and_legacy_otp_supported(configured):
    from types import SimpleNamespace

    signed(Client(), payload())
    client = browser()
    assert (
        post(client, "code", {"email": "patient@example.test", "source": "selfpay"}).status_code
        == 200
    )
    job = next(j for j in DeliveryJob.objects.all() if mail.payload(j).get("portal_challenge_id"))
    data = mail.payload(job)
    assert data["portal_source"] == "selfpay"
    assert portal.notification_source(data, job) == "selfpay"
    del data["portal_source"]
    assert portal.notification_source(data, job) == "selfpay"
    assert portal.notification_source(data, SimpleNamespace(organization_id=uuid.uuid4())) is None
    assert (
        portal.notification_source({"subject": "SelfPay", "to": "patient@example.test"}, job)
        is None
    )


def test_private_booking_confirmation_visibility_and_retry(configured, settings):
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"].update(
        suppress_provider_notifications=False,
        provider_action_origins=["https://myselfpay.example.test"],
    )
    service = Client()
    ident = signed(service, payload()).json()["id"]
    assert {mail.payload(j)["to"] for j in DeliveryJob.objects.all()} == {
        "clinic@example.test",
        "patient@example.test",
    }
    patient, _ = login("patient@example.test")
    clinic, _ = login("clinic@example.test")
    path = "/recipient-api/inbox/threads/" + ident
    assert "MSP-SYNTHETIC" in patient.get(path).json()["request_summary"]
    assert patient.get(path).json()["booking_status"] == "requested"
    assert payload()["body"] not in patient.get(path).json()["request_summary"]
    assert clinic.get(path).json()["request_summary"] == payload()["body"]
    event = {
        "event_type": "booking_confirmed",
        "external_id": "MSP-SYNTHETIC",
        "event_id": "booking-confirmed-v1",
        "body": "Private confirmation",
        "actions": [
            {
                "label": "View my booking",
                "url": "https://myselfpay.example.test/#request/test/private-token",
                "expires_at": time.time() + 3600,
            }
        ],
    }
    count = DeliveryJob.objects.count()
    result = signed(service, event)
    assert result.status_code == 201, result.content
    assert DeliveryJob.objects.count() == count + 1
    job = mail.payload(DeliveryJob.objects.latest("created_at"))
    assert job["to"] == "patient@example.test"
    assert "private-token" not in str(job) and "Private confirmation" not in str(job)
    assert signed(service, event).status_code == 200
    assert DeliveryJob.objects.count() == count + 1
    assert signed(service, {**event, "body": "Changed"}).status_code == 409
    patient_data = patient.get(path).json()
    assert patient_data["messages"][-1]["body"] == "Private confirmation"
    assert patient_data["messages"][-1]["actions"] == event["actions"]
    clinic_data = clinic.get(path).json()
    assert patient_data["booking_status"] == clinic_data["booking_status"] == "approved"
    assert "Private confirmation" not in str(clinic_data)
    assert "private-token" not in str(clinic_data)
    assert clinic.get(path, {"before": result.json()["id"]}).status_code == 400
    event["event_id"] = "bad-origin"
    event["actions"][0]["url"] = "https://attacker.example/request"
    assert signed(service, event).status_code == 400


def test_legacy_booking_is_hidden_from_requester(configured):
    from backend.apps.core.portal import encrypt

    ident = signed(Client(), payload()).json()["id"]
    PortalMessage.objects.filter(submission_key="initial_requester").delete()
    message = PortalMessage.objects.get(submission_key="initial")
    message.audience = "all"
    message.body_ciphertext = encrypt(
        payload()["body"], message.thread.organization_id, "portal-message", message.pk
    )
    message.save()
    patient, _ = login("patient@example.test")
    result = patient.get("/recipient-api/inbox/threads/" + ident).json()
    assert not result["messages"] and not result["request_summary"]


def test_clinic_invitation_copy_excludes_timing_and_escapes_names(configured, settings):
    from backend.apps.core.email_templates import notification_html

    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["suppress_provider_notifications"] = False
    data = payload()
    data["participants"][0]["name"] = "Jamie <script>alert(1)</script>"
    data["body"] = "Requested time: Tuesday 09:00. Confidential exam details."
    result = signed(Client(), data)
    assert result.status_code == 201
    job = next(
        mail.payload(j)
        for j in DeliveryJob.objects.all()
        if mail.payload(j)["to"] == "clinic@example.test"
    )
    assert job["to"] == "clinic@example.test"
    assert job["subject"] == "New appointment request via MySelfPay"
    assert "Dear Synthetic Clinic Team" in job["body"]
    assert data["participants"][0]["name"] in job["body"]
    assert "MySelfPay booking reference: MSP-SYNTHETIC" in job["body"]
    assert "self-pay healthcare services" in job["body"]
    assert "one-time code" in job["body"]
    assert "Tuesday" not in job["body"] and "09:00" not in job["body"]
    assert "Confidential exam details" not in job["body"]
    assert "patient@example.test" not in job["body"]
    html = notification_html(job, protected=True)
    assert "Review appointment request" in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert signed(Client(), data).status_code == 200
    assert DeliveryJob.objects.count() == 2


def test_selfpay_center_only_delivery_has_no_patient_mailbox_or_replies(configured, settings):
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"].update(
        suppress_provider_notifications=False,
        provider_action_origins=["https://selfpay.example.test"],
    )
    data = payload("MSP-CENTER-ONLY")
    data["delivery_mode"] = "provider_only"
    data["participants"] = [data["participants"][1]]
    action = {
        "url": "https://selfpay.example.test/#clinic/MSP-CENTER-ONLY/private-token",
        "expires_at": time.time() + 3600,
    }
    data["provider_action"] = action
    response = signed(Client(), data)
    assert response.status_code == 201, response.content
    ident = response.json()["id"]
    assert response.json()["provider_notification"] == "queued"
    assert signed(Client(), data).json()["id"] == ident
    assert PortalParticipant.objects.count() == 1
    assert PortalMailbox.objects.count() == 1
    assert PortalMessage.objects.count() == 1
    assert PortalParticipant.objects.get().role == "provider"
    jobs = [mail.payload(job) for job in DeliveryJob.objects.all()]
    assert len(jobs) == 1 and jobs[0]["to"] == "clinic@example.test"
    assert "private-token" not in json.dumps(jobs)
    assert "patient@example.test" not in json.dumps(jobs)
    center, _ = login("clinic@example.test")
    detail = center.get("/recipient-api/inbox/threads/" + ident)
    assert detail.status_code == 200
    assert detail.json()["provider_action"] == action
    assert detail.json()["read_only"] is True
    assert (
        post(
            center,
            "threads/" + ident,
            {"body": "No reply should be accepted"},
            HTTP_IDEMPOTENCY_KEY="synthetic-reply-12345",
        ).status_code
        == 403
    )
    assert PortalMessage.objects.count() == 1
    outsider = browser()
    assert outsider.get("/recipient-api/inbox/threads/" + ident).status_code == 401


@pytest.mark.parametrize("variant", ["requester", "two_people", "no_action", "bad_mode"])
def test_center_only_rejects_invalid_contract(configured, variant):
    data = payload("MSP-REJECT-CENTER")
    data["delivery_mode"] = "provider_only"
    data["participants"] = [data["participants"][1]]
    if variant == "requester":
        data["participants"][0]["role"] = "requester"
    elif variant == "two_people":
        data["participants"] = payload()["participants"]
    elif variant == "bad_mode":
        data["delivery_mode"] = "unknown"
    assert signed(Client(), data).status_code == 400
    assert PortalThread.objects.count() == 0
    assert DeliveryJob.objects.count() == 0
