import json

import pytest
from django.test import Client
from django.utils import timezone

from backend.apps.core.mail import payload
from backend.apps.core.models import Conversation, DeliveryJob, StaffUser
from backend.tests.test_flows import compose, post

pytestmark = pytest.mark.django_db


def send(client, path, body):
    return client.post(path, json.dumps(body), content_type="application/json")


def test_staff_and_recipient_sessions_are_independent(staff_client, settings):
    settings.RECIPIENT_PUBLIC_URL = "https://secure.example.test/recipient"
    created = compose(staff_client, to=["sara@gmail.com"])
    conversation = Conversation.objects.get(pk=created.json()["id"])
    job = DeliveryJob.objects.get(conversation=conversation)
    link = payload(job)["link"]
    assert link.startswith(settings.RECIPIENT_PUBLIC_URL + "/#/invite/")
    token = link.rsplit("/", 1)[-1]
    staff_cookie = staff_client.cookies["sessionid"].value
    assert staff_client.get("/recipient-api/auth/session").json()["user"] is None
    assert staff_client.get("/recipient-api/admin/accounts").status_code == 404
    assert send(staff_client, "/recipient-api/recipient/code", {"token": token}).status_code == 200
    code_job = DeliveryJob.objects.filter(conversation=conversation).exclude(pk=job.pk).get()
    code = payload(code_job)["body"].split(" is ")[1][:6]
    assert (
        send(
            staff_client, "/recipient-api/recipient/verify", {"token": token, "code": code}
        ).status_code
        == 200
    )
    assert staff_client.cookies["sessionid"].value == staff_cookie
    assert staff_client.cookies["recipient_sessionid"]["path"] == "/recipient-api/"
    assert staff_client.get("/api/auth/session").json()["user"] is not None
    assert staff_client.get("/recipient-api/recipient/conversation").status_code == 200
    assert send(staff_client, "/recipient-api/recipient/logout", {}).status_code == 200
    assert staff_client.get("/api/auth/session").json()["user"] is not None
    assert staff_client.get("/recipient-api/recipient/conversation").status_code == 401


def test_recipient_cookie_cannot_authenticate_staff_api(staff_client):
    client = Client()
    client.cookies["recipient_sessionid"] = staff_client.cookies["sessionid"].value
    assert client.get("/api/conversations").status_code == 401
    assert client.get("/api/admin/accounts").status_code == 401


@pytest.mark.parametrize(
    "email", ["external@gmail.com", "spoof@onesmarter.com.evil.test", "staff@sub.onesmarter.com"]
)
def test_account_creation_requires_exact_company_domain(admin_client, email):
    response = send(admin_client, "/api/admin/accounts", {"name": "Test", "email": email})
    assert response.status_code == 400
    assert not StaffUser.objects.filter(email=email).exists()


def test_mailbox_requires_explicit_operator_opt_in(settings):
    settings.ENABLE_DEV_TOOLS = False
    assert Client().get("/api/dev/inbox").status_code == 404


def test_legacy_recipient_api_disabled_by_default(settings):
    settings.ENABLE_LEGACY_RECIPIENT_API = False
    assert Client().post("/api/recipient/code", {}).status_code == 404
    assert Client().get("/recipient-api/auth/session").status_code == 200


@pytest.mark.parametrize("restriction", ["grant", "conversation", "owner"])
def test_original_invite_survives_replies_but_not_access_revocation(staff_client, restriction):
    created = compose(staff_client)
    conversation = Conversation.objects.get(pk=created.json()["id"])
    grant = conversation.grants.get()
    original = payload(DeliveryJob.objects.get(conversation=conversation))["link"].rsplit("/", 1)[
        -1
    ]
    tokens = [original]
    for index in range(2):
        existing_jobs = list(
            DeliveryJob.objects.filter(conversation=conversation).values_list("pk", flat=True)
        )
        assert (
            post(
                staff_client,
                f"/conversations/{conversation.pk}/messages",
                {"body": f"Reply {index}"},
                key=f"reply-history-{index}",
            ).status_code
            == 201
        )
        latest = (
            DeliveryJob.objects.filter(conversation=conversation)
            .exclude(pk__in=existing_jobs)
            .get()
        )
        tokens.append(payload(latest)["link"].rsplit("/", 1)[-1])
        count = DeliveryJob.objects.filter(conversation=conversation).count()
        assert (
            post(
                staff_client,
                f"/conversations/{conversation.pk}/messages",
                {"body": f"Reply {index}"},
                key=f"reply-history-{index}",
            ).status_code
            == 201
        )
        assert DeliveryJob.objects.filter(conversation=conversation).count() == count
    assert len(set(tokens)) == 3
    assert grant.invitation_tokens.count() == 2
    # A fresh browser has no session fallback: it must resolve the original hash.
    visitor = Client()
    for token in tokens:
        assert (
            send(visitor, "/recipient-api/recipient/landing", {"token": token}).status_code == 200
        )
    existing_jobs = list(
        DeliveryJob.objects.filter(conversation=conversation).values_list("pk", flat=True)
    )
    assert send(visitor, "/recipient-api/recipient/code", {"token": original}).status_code == 200
    code_job = (
        DeliveryJob.objects.filter(conversation=conversation).exclude(pk__in=existing_jobs).get()
    )
    code = payload(code_job)["body"].split(" is ")[1][:6]
    assert (
        send(
            visitor, "/recipient-api/recipient/verify", {"token": original, "code": code}
        ).status_code
        == 200
    )
    assert visitor.get("/recipient-api/recipient/conversation").status_code == 200
    if restriction == "grant":
        grant.revoked_at = timezone.now()
        grant.save(update_fields=["revoked_at"])
    elif restriction == "conversation":
        conversation.revoked_at = timezone.now()
        conversation.save(update_fields=["revoked_at"])
    else:
        conversation.owner.status = "deactivated"
        conversation.owner.save(update_fields=["status"])
    for token in tokens:
        fresh = Client()
        assert send(fresh, "/recipient-api/recipient/landing", {"token": token}).status_code == 404
        assert send(fresh, "/recipient-api/recipient/code", {"token": token}).status_code == 404
