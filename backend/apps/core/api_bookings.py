"""Explicit opt-in SelfPay bearer adapter; legacy HMAC endpoint remains unchanged."""

import hashlib
import json

from django.conf import settings
from rest_framework.response import Response

from . import document_service, portal
from .api_keys import public_endpoint
from .http import Problem
from .models import ApiBooking, IdempotencyRecord
from .portal_models import PortalMessage, PortalThread
from .services import audit, idempotency, keyed


def selfpay_config(owner):
    config = settings.SECURE_MAIL_INTEGRATIONS.get("selfpay", {})
    if not isinstance(config, dict) or str(config.get("owner_id")) != str(owner.pk):
        raise Problem(
            "Only the configured SelfPay owner can use booking API keys.",
            "integration_owner_required",
            403,
        )
    if not config.get("enabled"):
        raise Problem("SelfPay integration is disabled.", "integration_unavailable", 503)
    return config


def scoped_booking(request, ident):
    selfpay_config(request.api_owner)
    document_service.require_ready()
    booking = (
        ApiBooking.objects.select_related("thread")
        .filter(
            key=request.api_key,
            thread_id=ident,
            thread__organization=request.api_key.organization,
            thread__owner=request.api_owner,
            thread__source="selfpay",
            thread__revoked_at=None,
        )
        .first()
    )
    if not booking:
        raise Problem("Booking conversation not found.", "not_found", 404)
    return booking.thread


@public_endpoint(["POST"], "bookings:write")
def create_booking(request):
    config = selfpay_config(request.api_owner)
    document_service.require_ready()
    data = request.data
    allowed = {"external_id", "subject", "body", "participants", "provider_action", "delivery_mode"}
    if not isinstance(data, dict) or set(data) - allowed:
        raise Problem("Invalid booking fields.")
    if data.get("delivery_mode", "provider_only") != "provider_only":
        raise Problem("API bookings are clinic-only.")
    reference = portal.field(data, "external_id", 100)
    existing, record = idempotency(
        request, request.api_key.organization, f"api-key:{request.api_key.pk}", "api-booking", data
    )
    if existing:
        thread = scoped_booking(request, existing.resource_id)
        return Response({"id": str(thread.pk), "url": portal.portal_link(thread)})
    # Prevent collisions with existing HMAC bookings and other API keys.
    storage_id = (
        "api-key:" + hashlib.sha256(f"{request.api_key.pk}:{reference}".encode()).hexdigest()
    )
    prior = PortalThread.objects.filter(source="selfpay", external_id=storage_id).first()
    if prior and not ApiBooking.objects.filter(key=request.api_key, thread=prior).exists():
        raise Problem("Booking reference unavailable.", "idempotency_conflict", 409)
    if prior:
        scoped_booking(request, prior.pk)
    result = portal.create_partner_thread(
        "selfpay",
        config,
        request.api_owner,
        {**data, "external_id": storage_id, "delivery_mode": "provider_only"},
        booking_reference=reference,
    )
    thread = PortalThread.objects.get(pk=result.data["id"])
    ApiBooking.objects.get_or_create(key=request.api_key, thread=thread)
    IdempotencyRecord.objects.create(**record, resource_id=thread.pk)
    return Response({**result.data, "external_id": reference}, status=result.status_code)


@public_endpoint(["GET"], "bookings:read")
def booking_detail(request, ident):
    thread = scoped_booking(request, ident)
    return Response(
        {
            "id": str(thread.pk),
            "source": "selfpay",
            "read_only": True,
            "booking_status": "approved"
            if thread.messages.filter(
                sender=None, submission_key__startswith="confirmation:"
            ).exists()
            else "requested",
            "url": portal.portal_link(thread),
            "created_at": thread.created_at,
            "updated_at": thread.updated_at,
        }
    )


@public_endpoint(["POST"], "bookings:write")
def confirm_booking(request, ident):
    thread = scoped_booking(request, ident)
    data = request.data
    if not isinstance(data, dict) or set(data) != {"event_id", "body"}:
        raise Problem("Confirmation requires event_id and body only.")
    event_id = portal.field(data, "event_id", 80)
    body = portal.field(data, "body", 16000)
    existing, record = idempotency(
        request,
        request.api_key.organization,
        f"api-key:{request.api_key.pk}",
        f"api-booking-confirm:{thread.pk}",
        data,
    )
    if existing:
        return Response(
            {
                "id": str(existing.resource_id),
                "thread_id": str(thread.pk),
                "booking_status": "approved",
            }
        )
    submission = "confirmation:" + event_id
    fingerprint = keyed(json.dumps({"body": body}, sort_keys=True), purpose="api-booking-confirm")
    prior = thread.messages.filter(sender=None, submission_key=submission).first()
    if prior and prior.fingerprint != fingerprint:
        raise Problem("Event ID reused with different content.", "idempotency_conflict", 409)
    if prior is None:
        message = PortalMessage(
            thread=thread, audience="provider", submission_key=submission, fingerprint=fingerprint
        )
        message.body_ciphertext = portal.encrypt(
            body, thread.organization_id, "portal-message", portal.message_context_id(message)
        )
        message.save()
        thread.updated_at = message.created_at
        thread.save(update_fields=["updated_at"])
        audit(
            thread.organization,
            request.api_owner,
            "api.booking_confirmed",
            "portal_thread",
            thread.pk,
        )
    else:
        message = prior
    IdempotencyRecord.objects.create(**record, resource_id=message.pk)
    # No patient account or email is created. The clinic sees the updated portal status.
    return Response(
        {"id": str(message.pk), "thread_id": str(thread.pk), "booking_status": "approved"},
        status=200 if prior else 201,
    )
