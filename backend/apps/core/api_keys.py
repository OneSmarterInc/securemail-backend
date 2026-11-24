"""Explicit bearer-only public API; never grants staff/session administration."""

import hashlib
import json
import secrets
import uuid
from datetime import timedelta
from functools import wraps
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.db.models import F, Q
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from . import crypto, document_service
from .auth import recent_mfa, validate
from .company_identity import is_company_address
from .conversations import message_context, subject_context
from .http import Problem, endpoint
from .models import (
    ApiEmailTemplate,
    ApiKey,
    ApiMessage,
    Conversation,
    IdempotencyRecord,
    Message,
    RecipientGrant,
    RecipientInvitationToken,
    StaffUser,
)
from .services import (
    audit,
    current_staff,
    digest,
    idempotency,
    lock_organization,
    paginate,
    queue_mail,
    rate_limit,
)

SCOPES = ("status:read", "messages:read", "messages:write", "bookings:read", "bookings:write")


class CreateKey(serializers.Serializer):
    notification_profile = serializers.ChoiceField(
        choices=("securemail", "selfpay"), default="securemail"
    )
    name = serializers.CharField(max_length=80)
    scopes = serializers.ListField(
        child=serializers.ChoiceField(choices=SCOPES), allow_empty=False, max_length=len(SCOPES)
    )
    expires_in_days = serializers.IntegerField(min_value=1, max_value=365, default=90)


def key_data(key):
    return {
        "id": str(key.pk),
        "name": key.name,
        "prefix": f"osm_{key.pk.hex[:8]}…",
        "scopes": key.scopes,
        "notification_profile": key.notification_profile,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
        "revoked_at": key.revoked_at,
        "last_used_at": key.last_used_at,
        "request_count": key.request_count,
        "status": "revoked"
        if key.revoked_at
        else "expired"
        if key.expires_at <= timezone.now()
        else "active",
    }


@endpoint(["GET", "POST"], admin=True)
def keys(request):
    if request.method == "GET":
        query = ApiKey.objects.filter(organization=request.user.organization)
        state = request.query_params.get("status", "")
        scope = request.query_params.get("scope", "")
        if state not in ("", "active", "expired", "revoked") or scope not in ("", *SCOPES):
            raise Problem("Invalid key status or permission filter.", "invalid_filter", 400)
        now = timezone.now()
        if state == "active":
            query = query.filter(revoked_at__isnull=True, expires_at__gt=now)
        elif state == "expired":
            query = query.filter(revoked_at__isnull=True, expires_at__lte=now)
        elif state == "revoked":
            query = query.filter(revoked_at__isnull=False)
        if scope:
            permission_filter = Q()
            for position in range(len(SCOPES)):
                permission_filter |= Q(**{f"scopes__{position}": scope})
            query = query.filter(permission_filter)
        if request.query_params.get("q"):
            query = query.filter(name__icontains=request.query_params["q"][:80])
        rows, meta = paginate(
            query,
            request,
            ordering={"created_at": "created_at", "name": "name", "last_used_at": "last_used_at"},
            default="-created_at",
        )
        return Response({"results": [key_data(key) for key in rows], **meta})
    recent_mfa(request)
    data = validate(CreateKey, request.data)
    with transaction.atomic():
        lock_organization(request.user.organization_id)
        owner = current_staff(request)
        if owner.role != "admin" or not owner.can_manage_privileges:
            raise Problem("Privilege management permission is required.", "permission_denied", 403)
        if data["notification_profile"] == "selfpay" or any(
            scope.startswith("bookings:") for scope in data["scopes"]
        ):
            from .api_bookings import selfpay_config

            selfpay_config(owner)
        if (
            ApiKey.objects.filter(
                owner=owner, revoked_at=None, expires_at__gt=timezone.now()
            ).count()
            >= 20
        ):
            raise Problem(
                "Revoke an unused key before creating another (limit 20).", "key_limit", 409
            )
        key = ApiKey(
            organization=owner.organization,
            owner=owner,
            name=data["name"],
            owner_version=owner.session_version,
            scopes=sorted(set(data["scopes"])),
            notification_profile=data["notification_profile"],
            expires_at=timezone.now() + timedelta(days=data["expires_in_days"]),
        )
        token = f"osm_{key.pk.hex}_{secrets.token_urlsafe(32)}"
        key.digest = digest(token)
        key.save()
        audit(
            owner.organization,
            owner,
            "api_key.created",
            "api_key",
            key.pk,
            metadata={"scopes": key.scopes},
        )
    response = Response({**key_data(key), "secret": token}, status=201)
    response["Cache-Control"] = "no-store"
    return response


@endpoint(["POST"], admin=True)
def revoke_key(request, ident):
    recent_mfa(request)
    with transaction.atomic():
        lock_organization(request.user.organization_id)
        owner = current_staff(request)
        if owner.role != "admin" or not owner.can_manage_privileges:
            raise Problem("Privilege management permission is required.", "permission_denied", 403)
        key = (
            ApiKey.objects.select_for_update()
            .filter(pk=ident, organization=owner.organization)
            .first()
        )
        if not key:
            raise Problem("Key not found.", "not_found", 404)
        if not key.revoked_at:
            key.revoked_at = timezone.now()
            key.save(update_fields=["revoked_at"])
            audit(owner.organization, owner, "api_key.revoked", "api_key", key.pk)
    return Response(key_data(key))


@endpoint(["GET"], admin=True)
def guide(request):
    response = HttpResponse(
        (Path(__file__).resolve().parents[3] / "PUBLIC_API.md").read_text(encoding="utf-8"),
        content_type="text/markdown; charset=utf-8",
    )
    response["Content-Disposition"] = 'attachment; filename="OneSmarter-Public-API.md"'
    response["Cache-Control"] = "no-store"
    return response


def public_endpoint(methods, scope):
    def decorate(function):
        @api_view(methods)
        @authentication_classes([])
        @permission_classes([AllowAny])
        @wraps(function)
        def wrapped(request, *args, **kwargs):
            if not settings.SYNTHETIC_MODE and not request.is_secure():
                raise Problem("HTTPS is required.", "https_required", 403)
            rate_limit(request, "api-auth", maximum=120, seconds=60)
            value = request.headers.get("Authorization", "")
            try:
                scheme, token = value.split(" ", 1)
                parts = token.split("_", 2)
                if scheme != "Bearer" or len(value) > 200 or len(parts) != 3 or parts[0] != "osm":
                    raise ValueError
                ident = uuid.UUID(hex=parts[1])
            except (ValueError, TypeError):
                raise Problem("Invalid API key.", "invalid_api_key", 401) from None
            candidate = ApiKey.objects.filter(pk=ident).first()
            if not candidate or not secrets.compare_digest(
                candidate.digest, hashlib.sha256(token.encode()).hexdigest()
            ):
                raise Problem("Invalid API key.", "invalid_api_key", 401)
            rate_limit(request, "api-key", str(ident), maximum=60, seconds=60)
            with transaction.atomic():
                lock_organization(candidate.organization_id)
                owner = StaffUser.objects.select_for_update().get(pk=candidate.owner_id)
                key = ApiKey.objects.select_for_update().get(pk=ident)
                if (
                    key.revoked_at
                    or key.expires_at <= timezone.now()
                    or not owner.is_active
                    or owner.status != "active"
                    or not owner.mfa_confirmed
                    or owner.organization_id != key.organization_id
                    or owner.session_version != key.owner_version
                    or owner.role != "admin"
                    or not owner.can_manage_privileges
                ):
                    raise Problem("Invalid API key.", "invalid_api_key", 401)
                required = scope[request.method] if isinstance(scope, dict) else scope
                if required not in key.scopes:
                    raise Problem(
                        "This key does not have the required scope.", "insufficient_scope", 403
                    )
                request.api_key, request.api_owner = key, owner
                response = function(request, *args, **kwargs)
                ApiKey.objects.filter(pk=key.pk).update(
                    last_used_at=timezone.now(), request_count=F("request_count") + 1
                )
                audit(
                    key.organization,
                    owner,
                    "api_key.used",
                    "api_key",
                    key.pk,
                    metadata={"scope": required, "method": request.method},
                )
            response["Cache-Control"] = "no-store"
            return response

        return wrapped

    return decorate


@public_endpoint(["GET"], "status:read")
def status(request):
    return Response({"ready": document_service.ready(), "api_version": "v1"})


class SendMessage(serializers.Serializer):
    reply = serializers.BooleanField(default=False)
    template_id = serializers.UUIDField(required=False)
    to = serializers.EmailField(max_length=254)
    sender = serializers.EmailField(max_length=254)
    subject = serializers.CharField(max_length=180)
    body = serializers.CharField(max_length=100000)

    def validate(self, data):
        if "reply" in self.initial_data and not isinstance(self.initial_data["reply"], bool):
            raise serializers.ValidationError("reply must be a JSON boolean.")
        if set(self.initial_data) - set(self.fields) or any(c in data["subject"] for c in "\r\n"):
            raise serializers.ValidationError("Unexpected fields or invalid subject.")
        data["to"], data["sender"] = data["to"].lower(), data["sender"].lower()
        return data


def message_data(conversation, *, full=False):
    from .api_presentation import replies_allowed

    result = {
        "id": str(conversation.pk),
        "state": conversation.state,
        "protected": True,
        "reply": replies_allowed(conversation),
        "created_at": conversation.created_at,
        "revoked": bool(conversation.revoked_at),
    }
    if full:
        result["subject"] = crypto.decrypt(
            conversation.subject_ciphertext, subject_context(conversation)
        ).decode()
        recent_messages = list(conversation.messages.order_by("-created_at", "-pk")[:101])
        result["messages_truncated"] = len(recent_messages) > 100
        result["messages"] = [
            {
                "id": str(m.pk),
                "body": crypto.decrypt(m.body_ciphertext, message_context(m)).decode(),
                "created_at": m.created_at,
                "sender_type": "staff" if m.staff_id else "recipient",
            }
            for m in reversed(recent_messages[:100])
        ]
        result["delivery"] = list(
            conversation.delivery_jobs.order_by("-created_at").values("state", "error_code")[:20]
        )
    return result


@public_endpoint(["GET", "POST"], {"GET": "messages:read", "POST": "messages:write"})
def messages(request):
    key, owner = request.api_key, request.api_owner
    document_service.require_ready()
    if request.method == "GET":
        query = Conversation.objects.filter(
            apimessage__key=key, organization=key.organization, owner=owner
        ).select_related("apimessage")
        rows, meta = paginate(
            query, request, ordering={"created_at": "created_at"}, default="-created_at"
        )
        return Response({"results": [message_data(c) for c in rows], **meta})
    data = validate(SendMessage, request.data)
    if key.notification_profile == "selfpay":
        from .api_bookings import selfpay_config

        selfpay_config(owner)
        if data.get("template_id"):
            raise Problem(
                "SelfPay uses its established templates; custom templates are not supported."
            )
    if "template_id" in data:
        data["template_id"] = str(data["template_id"])
    template = None
    if data.get("template_id"):
        template = template_content(request, data["template_id"])
    if data["sender"] not in owner.sender_addresses or not is_company_address(
        data["sender"], owner.organization.domain
    ):
        raise Problem("Sender is not authorized for the key owner.", "sender_denied", 403)
    existing, record = idempotency(
        request, owner.organization, f"api-key:{key.pk}", "api-message", data
    )
    if existing:
        return Response({"id": str(existing.resource_id)}, status=200)
    # The outer handler holds the organization lock, serializing stream creation.
    binding = (
        ApiMessage.objects.select_related("conversation")
        .filter(
            key=key,
            conversation__owner=owner,
            conversation__organization=owner.organization,
            conversation__sender=data["sender"],
            conversation__revoked_at=None,
            conversation__protected=True,
            conversation__grants__email=data["to"],
            conversation__grants__revoked_at=None,
        )
        .order_by("-conversation__created_at")
        .first()
    )
    conversation = (
        binding.conversation
        if binding
        else Conversation(
            organization=owner.organization,
            owner=owner,
            sender=data["sender"],
            protected=True,
            routing_reason="api_secure",
            policy_version="api-v1",
        )
    )
    conversation.subject_ciphertext = crypto.encrypt(
        data["subject"].encode(), subject_context(conversation)
    )
    conversation.updated_at = timezone.now()
    conversation.save()
    message = Message(
        conversation=conversation,
        staff=owner,
        mail_headers={
            "from_name": owner.display_name,
            "from_email": data["sender"],
            "to": [data["to"]],
            "cc": [],
            "bcc": [],
        },
    )
    message.body_ciphertext = crypto.encrypt(data["body"].encode(), message_context(message))
    message.save()
    token = secrets.token_urlsafe(32)
    if binding:
        grant = RecipientGrant.objects.get(conversation=conversation, email=data["to"])
        RecipientInvitationToken.objects.get_or_create(grant=grant, token_hash=grant.token_hash)
        grant.token_hash = digest(token)
        grant.save(update_fields=["token_hash"])
    else:
        grant = RecipientGrant.objects.create(
            conversation=conversation, email=data["to"], kind="to", token_hash=digest(token)
        )
    from .api_presentation import presentation as existing_presentation
    from .api_presentation import validate_theme

    presentation = template or (existing_presentation(conversation) if binding else {})
    if key.notification_profile == "selfpay":
        presentation = {
            "theme": validate_theme(
                {"name": "MySelfPay", "primary": "#172b3c", "background": "#faf9f6"}
            )
        }
    binding = binding or ApiMessage(key=key, conversation=conversation)
    binding.allow_reply = data["reply"]
    binding.presentation_ciphertext = crypto.encrypt(
        json.dumps(presentation).encode(),
        crypto.context(owner.organization_id, "api-presentation", conversation.pk),
    )
    binding.save()
    queue_mail(
        owner.organization,
        {
            "to": data["to"],
            "subject": "You have a new secure message",
            "body": "Open the secure portal and verify your email to read your message.",
            "link": f"{settings.RECIPIENT_PUBLIC_URL}/#/invite/{token}",
            "api_notification_template": presentation,
        },
        actor=owner,
        conversation=conversation,
        grant=grant,
    )
    IdempotencyRecord.objects.create(**record, resource_id=conversation.pk)
    audit(
        owner.organization,
        owner,
        "api.message_created",
        "conversation",
        conversation.pk,
        metadata={"api_key_id": str(key.pk)},
    )
    return Response({"id": str(conversation.pk)}, status=201)


@public_endpoint(["GET"], "messages:read")
def message_detail(request, ident):
    document_service.require_ready()
    conversation = Conversation.objects.filter(
        pk=ident,
        organization=request.api_key.organization,
        owner=request.api_owner,
        apimessage__key=request.api_key,
    ).first()
    if not conversation:
        raise Problem("Message not found.", "not_found", 404)
    return Response(message_data(conversation, full=True))


class TemplateInput(serializers.Serializer):
    name = serializers.CharField(max_length=80)
    html = serializers.CharField(max_length=20000)
    css = serializers.CharField(max_length=2000, required=False, allow_blank=True, default="")
    text = serializers.CharField(max_length=10000)
    otp_html = serializers.CharField(max_length=20000, required=False)
    otp_css = serializers.CharField(max_length=2000, required=False, allow_blank=True, default="")
    otp_text = serializers.CharField(max_length=10000, required=False)
    theme = serializers.JSONField(required=False)

    def validate(self, data):
        from .api_email_templates import validate_markup

        if set(self.initial_data) - set(self.fields):
            raise serializers.ValidationError("Unknown template fields.")
        try:
            validate_markup(data["html"], data["css"])
            if any(name in self.initial_data for name in ("otp_html", "otp_css", "otp_text")):
                if not data.get("otp_html") or not data.get("otp_text"):
                    raise ValueError("Custom OTP requires both otp_html and otp_text.")
                validate_markup(data["otp_html"], data.get("otp_css", ""))
            if "theme" in data:
                from .api_presentation import validate_theme

                data["theme"] = validate_theme(data["theme"])
        except ValueError as error:
            raise serializers.ValidationError(str(error)) from error
        return data


def template_content(request, ident):
    template = ApiEmailTemplate.objects.filter(pk=ident, key=request.api_key).first()
    if not template:
        raise Problem("Template not found.", "not_found", 404)
    return json.loads(
        crypto.decrypt(
            template.content_ciphertext,
            crypto.context(request.api_key.organization_id, "api-template", template.pk),
        )
    )


@public_endpoint(["GET", "POST"], {"GET": "messages:read", "POST": "messages:write"})
def templates(request):
    document_service.require_ready()
    if request.method == "GET":
        rows, meta = paginate(
            ApiEmailTemplate.objects.filter(key=request.api_key),
            request,
            ordering={"created_at": "created_at"},
            default="-created_at",
        )
        return Response(
            {
                "results": [
                    {"id": str(row.pk), "name": row.name, "created_at": row.created_at}
                    for row in rows
                ],
                **meta,
            }
        )
    data = validate(TemplateInput, request.data)
    existing, record = idempotency(
        request, request.api_key.organization, f"api-key:{request.api_key.pk}", "api-template", data
    )
    if existing:
        return Response({"id": str(existing.resource_id)})
    if ApiEmailTemplate.objects.filter(key=request.api_key).count() >= 100:
        raise Problem("Template limit reached (100 per key).", "template_limit", 409)
    template = ApiEmailTemplate(key=request.api_key, name=data["name"])
    template.content_ciphertext = crypto.encrypt(
        json.dumps(data).encode(),
        crypto.context(request.api_key.organization_id, "api-template", template.pk),
    )
    template.save()
    IdempotencyRecord.objects.create(**record, resource_id=template.pk)
    return Response({"id": str(template.pk)}, status=201)


@public_endpoint(["POST"], "messages:write")
def preview_template(request):
    from .api_email_templates import render_notification, render_otp

    data = validate(TemplateInput, request.data)
    return Response(
        {
            "html": render_notification(data, "https://example.invalid/preview"),
            "text": data["text"],
            "preview_only": True,
            "otp_html": render_otp(data, "000000") if data.get("otp_html") else None,
            "otp_text": data.get("otp_text", "")
            + "\nPreview code: 000000. Not a real verification code.",
            "theme": data.get("theme"),
        }
    )


@public_endpoint(["GET"], "messages:read")
def template_detail(request, ident):
    document_service.require_ready()
    return Response({"id": str(ident), **template_content(request, ident)})
