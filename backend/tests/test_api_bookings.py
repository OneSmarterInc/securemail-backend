import time

import pytest
from django.utils import timezone

from backend.apps.core import mail, portal
from backend.apps.core.models import ApiBooking, DeliveryJob
from backend.apps.core.portal_models import PortalParticipant, PortalThread
from backend.tests.test_api_keys import invoke, issue

pytestmark = pytest.mark.django_db


@pytest.fixture
def booking_key(settings, admin, admin_client):
    settings.SECURE_MAIL_INTEGRATIONS = {
        "selfpay": {
            "owner_id": admin.pk,
            "enabled": True,
            "name": "MySelfPay",
            "suppress_provider_notifications": False,
            "provider_action_origins": ["https://selfpay.example.test"],
        }
    }
    return issue(admin_client, ["bookings:read", "bookings:write"])["secret"]


def booking_data():
    return {
        "external_id": "MSP-SYNTHETIC",
        "subject": "Appointment request",
        "body": "Confidential synthetic appointment details",
        "participants": [
            {"email": "clinic@example.test", "name": "Synthetic Clinic", "role": "provider"}
        ],
        "provider_action": {
            "url": "https://selfpay.example.test/review/fixture",
            "expires_at": time.time() + 3600,
        },
    }


def test_booking_creation_confirmation_isolation(booking_key, admin_client):
    data = booking_data()
    created = invoke(
        booking_key, "/api/v1/bookings", "post", data, HTTP_IDEMPOTENCY_KEY="booking-1"
    )
    assert created.status_code == 201, created.content
    ident = created.json()["id"]
    path = f"/api/v1/bookings/{ident}"
    assert invoke(booking_key, path).json()["booking_status"] == "requested"
    assert list(PortalParticipant.objects.values_list("role", flat=True)) == ["provider"]
    job = DeliveryJob.objects.get()
    contents = mail.payload(job)
    assert contents["to"] == "clinic@example.test"
    assert "MSP-SYNTHETIC" in contents["body"]
    assert "Confidential synthetic" not in contents["body"]
    assert portal.notification_source(contents, job) == "selfpay"
    assert (
        invoke(
            booking_key, "/api/v1/bookings", "post", data, HTTP_IDEMPOTENCY_KEY="booking-1"
        ).status_code
        == 200
    )
    other = issue(admin_client, ["bookings:read", "bookings:write"])["secret"]
    assert invoke(other, path).status_code == 404
    event = {"event_id": "approval-1", "body": "Approved in SelfPay."}
    assert (
        invoke(
            other, path + "/confirmation", "post", event, HTTP_IDEMPOTENCY_KEY="event-1"
        ).status_code
        == 404
    )
    assert (
        invoke(
            booking_key, path + "/confirmation", "post", event, HTTP_IDEMPOTENCY_KEY="event-1"
        ).status_code
        == 201
    )
    assert (
        invoke(
            booking_key, path + "/confirmation", "post", event, HTTP_IDEMPOTENCY_KEY="event-1"
        ).status_code
        == 200
    )
    assert invoke(booking_key, path).json()["booking_status"] == "approved"
    assert DeliveryJob.objects.count() == 1
    assert set(ApiBooking.objects.get().thread.messages.values_list("audience", flat=True)) == {
        "provider"
    }
    event["body"] = "Different event"
    assert (
        invoke(
            booking_key, path + "/confirmation", "post", event, HTTP_IDEMPOTENCY_KEY="event-2"
        ).status_code
        == 409
    )
    PortalThread.objects.filter(pk=ident).update(revoked_at=timezone.now())
    assert (
        invoke(
            booking_key, "/api/v1/bookings", "post", data, HTTP_IDEMPOTENCY_KEY="booking-2"
        ).status_code
        == 404
    )


@pytest.mark.parametrize("change", ["requester", "two_party", "origin", "unknown"])
def test_booking_rejects_unsafe_inputs(booking_key, change):
    data = booking_data()
    if change == "requester":
        data["participants"][0]["role"] = "requester"
    elif change == "two_party":
        data["delivery_mode"] = "two_party"
    elif change == "origin":
        data["provider_action"]["url"] = "https://other.example.test/approve"
    else:
        data["to"] = "patient@example.test"
    result = invoke(booking_key, "/api/v1/bookings", "post", data, HTTP_IDEMPOTENCY_KEY="invalid-1")
    assert result.status_code == 400, result.content
    assert not ApiBooking.objects.exists()
    assert not DeliveryJob.objects.exists()


def test_booking_scope_and_disabled_config(booking_key, admin_client, settings):
    ordinary = issue(admin_client)["secret"]
    assert (
        invoke(
            ordinary, "/api/v1/bookings", "post", booking_data(), HTTP_IDEMPOTENCY_KEY="not-scoped"
        ).status_code
        == 403
    )
    settings.SECURE_MAIL_INTEGRATIONS["selfpay"]["enabled"] = False
    assert (
        invoke(
            booking_key, "/api/v1/bookings", "post", booking_data(), HTTP_IDEMPOTENCY_KEY="disabled"
        ).status_code
        == 503
    )
