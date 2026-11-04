import json

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client

from backend.apps.core.mail import payload
from backend.apps.core.models import Conversation, DeliveryJob, Message
from backend.tests.test_flows import compose, post

pytestmark = pytest.mark.django_db


def access(email):
    invitation = next(
        job
        for job in DeliveryJob.objects.order_by("-created_at")
        if payload(job).get("to") == email and payload(job).get("link")
    )
    token = payload(invitation)["link"].rsplit("/", 1)[-1]
    client = Client()
    assert post(client, "/recipient/code", {"token": token}).status_code == 200
    challenge = DeliveryJob.objects.latest("created_at")
    code = payload(challenge)["body"].split(" is ")[1][:6]
    assert post(client, "/recipient/verify", {"token": token, "code": code}).status_code == 200
    return client


def setup_group(staff_client):
    response = compose(
        staff_client,
        to=["a@example.com"],
        cc=["b@example.com"],
        bcc=["blind@example.com", "hidden@example.com"],
    )
    assert response.status_code == 201, response.content
    return (
        response.json()["id"],
        access("a@example.com"),
        access("b@example.com"),
        access("blind@example.com"),
    )


def test_headers_hide_bcc_and_private_copies_cannot_reply_all(staff_client):
    ident, a, b, blind = setup_group(staff_client)
    for client in [a, b]:
        response = client.get("/api/recipient/conversation")
        assert response.status_code == 200
        assert "blind@example.com" not in response.content.decode()
        assert "hidden@example.com" not in response.content.decode()
        assert response.json()["can_reply_all"]
    data = blind.get("/api/recipient/conversation").json()
    assert data["id"] != ident
    assert data["messages"][0]["headers"]["bcc"] == ["blind@example.com"]
    assert not data["can_reply_all"]
    assert "hidden@example.com" not in json.dumps(data)
    assert (
        post(blind, "/recipient/conversation", {"body": "blind", "reply_mode": "all"}).status_code
        == 400
    )
    assert Conversation.objects.get(pk=ident).grants.count() == 2


def test_reply_all_is_shared_but_sender_reply_is_private_with_files(staff_client):
    ident, a, b, blind = setup_group(staff_client)
    upload = a.post(
        "/api/recipient/attachments",
        {"file": SimpleUploadedFile("share.txt", b"shared attachment", content_type="text/plain")},
    )
    assert upload.status_code == 201, upload.content
    initial = Conversation.objects.get(pk=ident).messages.first()
    shared = post(
        a,
        "/recipient/conversation",
        {
            "body": "visible reply",
            "reply_mode": "all",
            "reply_to": str(initial.pk),
            "attachments": [upload.json()["id"]],
        },
    )
    assert shared.status_code == 201, shared.content
    message_id = shared.json()["id"]
    other = b.get("/api/recipient/conversation").json()
    assert any(m["id"] == message_id for m in other["messages"])
    assert b.get("/api/attachments/" + upload.json()["id"]).content == b"shared attachment"
    assert blind.get("/api/attachments/" + upload.json()["id"]).status_code == 404
    private_upload = b.post(
        "/api/recipient/attachments",
        {"file": SimpleUploadedFile("private.txt", b"owner only", content_type="text/plain")},
    )
    assert private_upload.status_code == 201
    private_file = private_upload.json()["id"]
    before = DeliveryJob.objects.count()
    private = post(
        b,
        "/recipient/conversation",
        {
            "body": "only staff owner",
            "reply_mode": "sender",
            "reply_to": message_id,
            "attachments": [private_file],
        },
    )
    assert private.status_code == 201, private.content
    private_id = private.json()["id"]
    assert not any(
        m["id"] == private_id for m in a.get("/api/recipient/conversation").json()["messages"]
    )
    assert any(
        m["id"] == private_id
        for m in staff_client.get("/api/conversations/" + ident).json()["messages"]
    )
    assert DeliveryJob.objects.count() == before + 1
    assert payload(DeliveryJob.objects.latest("created_at"))["to"] == "staff@onesmarter.com"
    assert Message.objects.get(pk=private_id).audience_id is None
    assert staff_client.get(f"/api/attachments/{private_file}").content == b"owner only"
    assert b.get(f"/api/attachments/{private_file}").content == b"owner only"
    assert a.get(f"/api/attachments/{private_file}").status_code == 404
    assert blind.get(f"/api/attachments/{private_file}").status_code == 404
    assert (
        post(
            blind, "/recipient/conversation", {"body": "attempt", "reply_to": message_id}
        ).status_code
        == 404
    )


def test_staff_private_reply_does_not_reach_other_recipients(staff_client):
    ident, a, b, _ = setup_group(staff_client)
    incoming = post(a, "/recipient/conversation", {"body": "private to staff"}).json()["id"]
    response = post(
        staff_client,
        f"/conversations/{ident}/messages",
        {"body": "private response", "reply_to": incoming, "reply_mode": "sender"},
    )
    assert response.status_code == 201, response.content
    assert any(
        m["id"] == response.json()["id"]
        for m in a.get("/api/recipient/conversation").json()["messages"]
    )
    assert not any(
        m["id"] == response.json()["id"]
        for m in b.get("/api/recipient/conversation").json()["messages"]
    )
    assert payload(DeliveryJob.objects.latest("created_at"))["to"] == "a@example.com"


def test_identical_group_continues_without_merging_single_thread(staff_client):
    first = compose(staff_client, to=["a@example.com"], cc=["b@example.com"]).json()["id"]
    again = compose(staff_client, to=["b@example.com"], cc=["a@example.com"]).json()["id"]
    single = compose(staff_client, to=["a@example.com"]).json()["id"]
    assert first == again and single != first
    assert Message.objects.filter(conversation_id=first).count() == 2


def test_private_reply_without_target_cannot_broadcast(staff_client):
    ident, _, _, _ = setup_group(staff_client)
    before = Message.objects.count()
    response = post(
        staff_client,
        f"/conversations/{ident}/messages",
        {"body": "private", "reply_mode": "sender"},
    )
    assert response.status_code == 400
    assert Message.objects.count() == before


@pytest.mark.parametrize("group", [False, True])
def test_links_survive_old_deadlines_and_new_messages(staff_client, group):
    from datetime import timedelta

    from django.utils import timezone

    from backend.apps.core.models import OTPChallenge, RecipientSession

    recipients = {"to": ["a@example.com"]}
    if group:
        recipients["cc"] = ["b@example.com"]
    created = compose(staff_client, **recipients)
    ident = created.json()["id"]
    conversation = Conversation.objects.get(pk=ident)
    assert conversation.expires_at is None
    token = payload(DeliveryJob.objects.filter(conversation=conversation).first())["link"].rsplit(
        "/", 1
    )[-1]
    visitor = access("a@example.com")
    Conversation.objects.filter(pk=ident).update(expires_at=timezone.now() - timedelta(days=90))
    assert visitor.get("/api/recipient/conversation").status_code == 200
    assert compose(staff_client, **recipients).json()["id"] == ident
    assert post(Client(), "/recipient/landing", {"token": token}).status_code == 200
    reply = post(
        staff_client,
        f"/conversations/{ident}/messages",
        {"body": "Still open", "reply_mode": "all" if group else "sender"},
    )
    assert reply.status_code == 201, reply.content
    RecipientSession.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert visitor.get("/api/recipient/conversation").status_code == 401
    # Respect resend cooldown while simulating a later verification.
    OTPChallenge.objects.update(created_at=timezone.now() - timedelta(minutes=1))
    # Session timeout does not invalidate the invitation; a new OTP is required.
    assert post(Client(), "/recipient/code", {"token": token}).status_code == 200
    Conversation.objects.filter(pk=ident).update(revoked_at=timezone.now())
    assert post(Client(), "/recipient/code", {"token": token}).status_code == 404


def test_owner_can_review_historical_recipient_private_messages(staff_client, admin_client):
    ident, a, b, _ = setup_group(staff_client)
    upload = a.post(
        "/api/recipient/attachments",
        {"file": SimpleUploadedFile("history.txt", b"historical file", content_type="text/plain")},
    )
    assert upload.status_code == 201
    file_id = upload.json()["id"]
    sent = post(
        a, "/recipient/conversation", {"body": "Historical private reply", "attachments": [file_id]}
    )
    assert sent.status_code == 201
    message = Message.objects.get(pk=sent.json()["id"])
    # Reproduce the historical row shape without re-enabling the old API behavior.
    message.audience = message.conversation.grants.get(email="b@example.com")
    message.save(update_fields=["audience"])
    view = staff_client.get(f"/api/conversations/{ident}")
    assert any(row["id"] == str(message.pk) for row in view.json()["messages"])
    assert staff_client.get(f"/api/attachments/{file_id}").content == b"historical file"
    assert admin_client.get(f"/api/attachments/{file_id}").status_code == 401
    assert admin_client.get(f"/api/conversations/{ident}").status_code == 404
