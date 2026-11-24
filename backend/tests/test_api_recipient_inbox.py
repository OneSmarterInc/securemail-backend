import json
import re
from datetime import timedelta

import pytest
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client
from django.utils import timezone

from backend.apps.core import mail
from backend.apps.core.models import (
    ApiMessage,
    Conversation,
    DeliveryJob,
    Message,
    RecipientGrant,
    RecipientSession,
)
from backend.tests.test_api_keys import invoke, issue
from backend.tests.test_api_presentation import post

pytestmark = pytest.mark.django_db


def send(token, admin, ref, *, to="receiver@example.test", **extra):
    result = invoke(
        token,
        "/api/v1/messages",
        "post",
        {
            "to": to,
            "sender": admin.email,
            "subject": f"Subject {ref}",
            "body": f"Private message {ref}",
            **extra,
        },
        HTTP_IDEMPOTENCY_KEY=ref,
    )
    assert result.status_code == 201, result.content
    ident = result.json()["id"]
    # Select by conversation and the associated newly inserted message, not clock ties.
    jobs = DeliveryJob.objects.filter(conversation_id=ident, grant__isnull=False).order_by(
        "created_at"
    )
    return ident, mail.payload(list(jobs)[-1])["link"].split("/invite/")[1]


def verify(token):
    visitor = Client()
    assert post(visitor, "code", {"token": token}).status_code == 200
    from backend.apps.core.conversations import token_grant

    grant = token_grant(token)
    otp = next(
        mail.payload(j)
        for j in DeliveryJob.objects.filter(grant=grant)
        if mail.payload(j).get("challenge_id")
    )
    code = re.search(r"code is (\d{6})", otp["body"])[1]
    assert post(visitor, "verify", {"token": token, "code": code}).status_code == 200
    return visitor


def test_sender_stream_reuse_and_default_read_only(admin_client, admin):
    token = issue(admin_client)["secret"]
    first, old_invitation = send(token, admin, "first")
    second, invitation = send(token, admin, "second")
    assert first == second
    assert Conversation.objects.count() == 1
    assert Message.objects.count() == 2
    assert DeliveryJob.objects.count() == 2
    assert ApiMessage.objects.get().allow_reply is False
    assert post(Client(), "landing", {"token": old_invitation}).status_code == 200
    third, _ = send(token, admin, "reply-enabled", reply=True)
    assert third == first and ApiMessage.objects.get().allow_reply is True
    send(token, admin, "default-again")
    assert ApiMessage.objects.get().allow_reply is False
    visitor = verify(invitation)  # Previous invitation still points to the same mailbox stream.
    assert len(visitor.get("/recipient-api/recipient/conversation").json()["messages"]) == 4


def test_verified_archive_is_email_scoped_and_api_keys_stay_isolated(admin_client, admin):
    first_key = issue(admin_client)["secret"]
    second_key = issue(admin_client)["secret"]
    first, invitation = send(first_key, admin, "first")
    second, _ = send(second_key, admin, "other-software")
    outsider, _ = send(second_key, admin, "other-recipient", to="someone-else@example.test")
    assert first != second
    assert invoke(first_key, f"/api/v1/messages/{second}").status_code == 404
    visitor = verify(invitation)
    result = visitor.get("/recipient-api/recipient/inbox")
    assert result.status_code == 200, result.content
    assert {row["id"] for row in result.json()["results"]} == {first, second}
    session = RecipientSession.objects.get(
        pk=SessionStore(visitor.cookies["recipient_sessionid"].value)["recipient_session"]
    )
    denied = visitor.post(
        f"/recipient-api/recipient/inbox/{outsider}/open",
        json.dumps({"email": "someone-else@example.test"}),
        content_type="application/json",
    )
    assert denied.status_code == 404
    opened = visitor.post(
        f"/recipient-api/recipient/inbox/{second}/open", {}, content_type="application/json"
    )
    assert opened.status_code == 200, opened.content
    current = RecipientSession.objects.get(
        pk=SessionStore(visitor.cookies["recipient_sessionid"].value)["recipient_session"]
    )
    assert current.created_at == session.created_at and current.expires_at == session.expires_at
    session.refresh_from_db()
    assert session.revoked_at is not None
    detail = visitor.get("/recipient-api/recipient/conversation")
    assert detail.json()["id"] == second
    assert detail.json()["messages"][0]["body"] == "Private message other-software"
    RecipientGrant.objects.filter(conversation_id=first).update(revoked_at=timezone.now())
    assert visitor.post(f"/recipient-api/recipient/inbox/{first}/open").status_code == 404
    RecipientSession.objects.filter(pk=current.pk).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert visitor.get("/recipient-api/recipient/inbox").status_code == 401
    assert Client().get("/recipient-api/recipient/inbox").status_code == 401


def test_archive_open_requires_csrf_and_cannot_start_from_legacy_grant(
    admin_client, admin, staff_client
):
    token = issue(admin_client)["secret"]
    ident, invitation = send(token, admin, "first")
    verified = verify(invitation)
    browser = Client(enforce_csrf_checks=True)
    browser.cookies = verified.cookies
    assert (
        browser.post(
            f"/recipient-api/recipient/inbox/{ident}/open", {}, content_type="application/json"
        ).status_code
        == 403
    )
    from backend.tests.test_flows import recipient_access

    legacy, _, _, _ = recipient_access(staff_client)
    legacy.cookies["recipient_sessionid"] = legacy.cookies["sessionid"].value
    assert legacy.get("/recipient-api/recipient/inbox").status_code == 404
