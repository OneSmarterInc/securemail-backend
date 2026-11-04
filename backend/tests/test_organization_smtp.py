import smtplib
import socket
import ssl
from datetime import timedelta
from email.utils import parseaddr
from unittest.mock import Mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from backend.apps.core import crypto, mail, smtp_settings
from backend.apps.core.models import (
    Attachment,
    Conversation,
    DeliveryJob,
    DirectChat,
    OrganizationSMTP,
    StaffSMTP,
)
from backend.tests.test_flows import compose, post, recipient_access

pytestmark = pytest.mark.django_db


def personal(client, email):
    return post(
        client, "/settings/smtp/personal", {"email": email, "password": "mailbox-test-secret"}
    )


def test_admin_transport_and_private_credentials(admin_client, staff_client, staff):
    config = {"host": "smtp.example.com", "port": 587, "security": "starttls", "enabled": True}
    assert post(staff_client, "/settings/smtp/organization", config).status_code == 403
    assert post(admin_client, "/settings/smtp/organization", config).status_code == 200
    result = personal(staff_client, staff.email)
    assert result.status_code == 200, result.content
    assert b"mailbox-test-secret" not in result.content
    value = StaffSMTP.objects.get(user=staff)
    assert "mailbox-test-secret" not in value.password_ciphertext
    assert (
        crypto.decrypt(value.password_ciphertext, smtp_settings.secret_context(staff))
        == b"mailbox-test-secret"
    )
    assert admin_client.get("/api/settings/smtp").json()["personal"]["password_set"] is False
    assert personal(staff_client, "admin@onesmarter.com").status_code == 403
    assert (
        post(
            staff_client, "/settings/smtp/personal", {"email": staff.email, "password": ""}
        ).status_code
        == 200
    )
    value.refresh_from_db()
    assert (
        crypto.decrypt(value.password_ciphertext, smtp_settings.secret_context(staff))
        == b"mailbox-test-secret"
    )


def test_sealed_credentials_fail_closed(staff_client, staff, monkeypatch):
    OrganizationSMTP.objects.create(organization=staff.organization, host="smtp.example.com")

    def unavailable(*args):
        raise crypto.CryptoUnavailable()

    monkeypatch.setattr(crypto, "encrypt", unavailable)
    assert personal(staff_client, staff.email).status_code == 503
    assert not StaffSMTP.objects.exists()


def test_transport_validation_and_network_boundary(admin_client, monkeypatch):
    for host, port, security in [
        ("127.0.0.1", 587, "starttls"),
        ("https://smtp.example.com", 587, "starttls"),
        ("smtp.example.com", 465, "starttls"),
    ]:
        assert (
            post(
                admin_client,
                "/settings/smtp/organization",
                {"host": host, "port": port, "security": security},
            ).status_code
            == 400
        )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 587))],
    )
    with pytest.raises(OSError):
        smtp_settings.public_socket("smtp.example.com", 587, 1)


def test_secure_send_and_otp_use_owners_credentials(staff_client, staff, settings, monkeypatch):
    OrganizationSMTP.objects.create(organization=staff.organization, host="smtp.example.com")
    assert personal(staff_client, staff.email).status_code == 200
    _, conversation, _, _ = recipient_access(staff_client)
    settings.MAIL_PROVIDER = "smtp"
    transport = Mock()
    transport.send_messages.return_value = 1
    factory = Mock(return_value=transport)
    monkeypatch.setattr(smtp_settings, "SMTPBackend", factory)
    for job in DeliveryJob.objects.filter(conversation=conversation):
        mail.process_job(job.pk)
    assert factory.called
    assert factory.call_args.kwargs["username"] == staff.email
    assert factory.call_args.kwargs["password"] == "mailbox-test-secret"
    sent = transport.send_messages.call_args.args[0][0]
    assert parseaddr(sent.from_email)[1] == staff.email
    assert sent.reply_to == [staff.email]
    assert "Document request" not in sent.body


def test_no_environment_sender_fallback(staff_client, settings):
    created = compose(staff_client)
    settings.MAIL_PROVIDER = "smtp"
    job = DeliveryJob.objects.get(conversation_id=created.json()["id"])
    mail.process_job(job.pk)
    job.refresh_from_db()
    assert job.state == "failed" and job.error_code == "sender_not_configured"


def test_single_pair_continues_and_groups_are_separate(staff_client):
    first = compose(staff_client).json()["id"]
    second = compose(staff_client, subject="Another request", body="New instructions").json()["id"]
    assert first == second
    assert Conversation.objects.get(pk=first).messages.count() == 2
    response = compose(staff_client, to=["sara@example.com", "other@example.com"]).json()
    assert response["conversation_ids"][0] != first
    assert len(response["conversation_ids"]) == 1
    assert DirectChat.objects.count() == 1
    assert sorted(c.grants.count() for c in Conversation.objects.all()) == [1, 2]


def test_different_staff_do_not_share_chat(staff_client, admin_client):
    first = compose(staff_client).json()["id"]
    other = compose(admin_client, sender="admin@onesmarter.com").json()["id"]
    assert first != other
    assert admin_client.get("/api/conversations/" + first).status_code == 404


def test_old_invite_is_still_delivered_after_new_request(staff_client):
    first = compose(staff_client).json()["id"]
    compose(staff_client)
    for job in DeliveryJob.objects.filter(conversation_id=first):
        mail.process_job(job.pk)
    assert DeliveryJob.objects.filter(state="development_delivered").count() == 2


def test_historical_deadline_does_not_expire_original_link(staff_client):
    first = compose(staff_client).json()["id"]
    conversation = Conversation.objects.get(pk=first)
    old = mail.payload(DeliveryJob.objects.get(conversation=conversation))["link"].rsplit("/", 1)[
        -1
    ]
    conversation.expires_at = timezone.now() - timedelta(days=1)
    conversation.save()
    assert compose(staff_client).json()["id"] == first
    assert post(staff_client, "/recipient/code", {"token": old}).status_code == 200


def test_private_attachment_copies(staff_client):
    uploaded = staff_client.post(
        "/api/attachments",
        {
            "file": SimpleUploadedFile("hello.txt", b"private test", content_type="text/plain"),
            "source_url": "https://example.com/hello.txt",
            "downloaded_at": "2026-01-01T12:00:00Z",
        },
    )
    assert uploaded.status_code == 201, uploaded.content
    response = compose(
        staff_client,
        to=["a@example.com", "b@example.com"],
        bcc=["blind@example.com"],
        attachments=[uploaded.json()["id"]],
    )
    assert response.status_code == 201, response.content
    files = list(Attachment.objects.filter(message__isnull=False))
    assert len(files) == 2 and files[0].object_key != files[1].object_key
    for file in files:
        assert staff_client.get("/api/attachments/" + str(file.pk)).content == b"private test"


def test_server_change_requires_explicit_password_confirmation(admin_client, staff_client, staff):
    config = {"host": "smtp.example.com", "port": 587, "security": "starttls"}
    assert post(admin_client, "/settings/smtp/organization", config).status_code == 200
    assert personal(staff_client, staff.email).status_code == 200
    config["host"] = "new.example.com"
    result = post(admin_client, "/settings/smtp/organization", config)
    assert result.status_code == 200
    assert staff_client.get("/api/settings/smtp").json()["personal"]["needs_password"]
    from backend.apps.core.senders import SenderUnavailable

    with pytest.raises(SenderUnavailable):
        smtp_settings.connection(staff)
    assert (
        post(
            staff_client, "/settings/smtp/personal", {"email": staff.email, "password": ""}
        ).status_code
        == 400
    )
    assert personal(staff_client, staff.email).status_code == 200
    assert not staff_client.get("/api/settings/smtp").json()["personal"]["needs_password"]


def test_recipient_reply_notifies_own_staff_mailbox(staff_client, staff):
    OrganizationSMTP.objects.create(organization=staff.organization, host="smtp.example.com")
    assert personal(staff_client, staff.email).status_code == 200
    recipient, conversation, _, _ = recipient_access(staff_client)
    response = post(
        recipient, "/recipient/conversation", {"body": "Recipient private reply", "attachments": []}
    )
    assert response.status_code == 201, response.content
    job = DeliveryJob.objects.filter(conversation=conversation).latest("created_at")
    data = mail.payload(job)
    assert data["to"] == staff.email
    assert "Recipient private reply" not in data["body"]
    assert "/#/messages/" in data["link"]


def test_otp_mail_uses_support_mailbox(staff_client, staff, settings, monkeypatch):
    OrganizationSMTP.objects.create(
        organization=staff.organization,
        host="smtp.example.com",
    )
    assert personal(staff_client, staff.email).status_code == 200
    ident = compose(staff_client).json()["id"]
    invite = DeliveryJob.objects.get(conversation_id=ident)
    token = mail.payload(invite)["link"].rsplit("/", 1)[-1]
    assert post(staff_client, "/recipient/code", {"token": token}).status_code == 200
    otp = DeliveryJob.objects.exclude(pk=invite.pk).get()
    settings.MAIL_PROVIDER = "smtp"
    transport = Mock()
    transport.send_messages.return_value = 1
    factory = Mock(return_value=transport)
    monkeypatch.setattr(smtp_settings, "SMTPBackend", factory)
    mail.process_job(otp.pk)
    otp.refresh_from_db()
    assert otp.state == "provider_accepted"
    assert factory.call_args.kwargs["username"] == staff.email
    assert factory.call_args.kwargs["password"] == "mailbox-test-secret"
    assert (
        parseaddr(transport.send_messages.call_args.args[0][0].from_email)[1]
        == "support@onesmarter.com"
    )
    assert transport.send_messages.call_args.args[0][0].to == ["sara@example.com"]


@pytest.mark.parametrize(
    "failure,code",
    [
        (
            smtplib.SMTPAuthenticationError(535, b"untrusted provider response"),
            "smtp_authentication_failed",
        ),
        (smtplib.SMTPServerDisconnected("untrusted provider response"), "smtp_disconnected"),
        (ssl.SSLError("untrusted provider response"), "smtp_tls_failed"),
        (OSError("untrusted provider response"), "smtp_check_failed"),
    ],
)
def test_smtp_check_reports_safe_actionable_errors(staff_client, monkeypatch, failure, code):
    transport = Mock()
    transport.open.side_effect = failure
    monkeypatch.setattr(smtp_settings, "connection", lambda user: (user.email, transport))
    response = post(staff_client, "/settings/smtp/check", {})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == code
    assert b"untrusted provider response" not in response.content
    transport.close.assert_called_once()


def test_otp_requires_owner_credentials_without_support_fallback(staff_client, staff):
    OrganizationSMTP.objects.create(
        organization=staff.organization,
        host="smtp.example.com",
    )
    from backend.apps.core.senders import SenderUnavailable

    with pytest.raises(SenderUnavailable):
        smtp_settings.otp_connection(staff)
    assert personal(staff_client, staff.email).status_code == 200
    sender, backend = smtp_settings.otp_connection(staff)
    assert sender == "support@onesmarter.com"
    assert backend.username == staff.email
    assert backend.password == "mailbox-test-secret"


def test_real_key_store_seal_blocks_smtp_and_otp(staff, settings, tmp_path, monkeypatch):
    import secrets
    import uuid

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from backend.apps.core import keyring
    from backend.keyservice.store import KeyStore

    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(
        tmp_path / "smtp-vault.sqlite3", secret, backup_directory=tmp_path / "backups"
    )
    store.unseal(secret, "test-custodian")
    org = str(staff.organization_id)
    key = store.rotate(org, None, str(uuid.uuid4()), "test-custodian")
    context = smtp_settings.secret_context(staff)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    wrapper = store.wrap(org, context, dek, key["id"], "test-workload")
    encrypted = crypto.canonical(
        {
            **wrapper,
            "nonce": crypto.b64(nonce),
            "data": crypto.b64(AESGCM(dek).encrypt(nonce, b"test-smtp-only", context.encode())),
        }
    ).decode()
    OrganizationSMTP.objects.create(organization=staff.organization, host="smtp.example.com")
    StaffSMTP.objects.create(
        user=staff,
        organization=staff.organization,
        email=staff.email,
        password_ciphertext=encrypted,
        transport_revision=1,
    )
    settings.KEY_PROTECTOR = "key-service"

    class StoreClient:
        def call(self, operation, **payload):
            assert operation == "unwrap"
            return {
                "dek": crypto.b64(
                    store.unwrap(
                        payload["organization"],
                        payload["context"],
                        payload["wrapper"],
                        "test-workload",
                    )
                )
            }

    monkeypatch.setattr(keyring, "service", lambda: StoreClient())
    assert smtp_settings.connection(staff)[1].password == "test-smtp-only"
    store.seal("test-custodian")
    factory = Mock()
    monkeypatch.setattr(smtp_settings, "SMTPBackend", factory)
    for connect in (smtp_settings.connection, smtp_settings.otp_connection):
        with pytest.raises(crypto.CryptoUnavailable):
            connect(staff)
    factory.assert_not_called()
    store.unseal(secret, "test-custodian")
    smtp_settings.connection(staff)
    assert factory.call_args.kwargs["password"] == "test-smtp-only"


def test_smtp_close_drops_password_reference():
    backend = smtp_settings.SMTPBackend(
        host="smtp.example.com", username="staff@example.com", password="test-only"
    )
    backend.close()
    assert backend.password is None
