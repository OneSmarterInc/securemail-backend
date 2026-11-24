"""Mailbox browsing after OTP, isolated from partner API credentials."""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone
from rest_framework.response import Response

from . import crypto, document_service
from .conversations import active_grant, recipient, subject_context
from .http import Problem, endpoint
from .models import ApiMessage, RecipientGrant, RecipientSession
from .services import audit, paginate, rate_limit


def mailbox_grants(request):
    grant = recipient(request)
    if not ApiMessage.objects.filter(conversation=grant.conversation).exists():
        raise Problem("This invitation does not use the API recipient inbox.", "not_found", 404)
    document_service.require_ready()
    return grant, RecipientGrant.objects.filter(
        email=grant.email,
        revoked_at=None,
        conversation__revoked_at=None,
        conversation__protected=True,
        conversation__owner__is_active=True,
        conversation__owner__status="active",
        conversation__apimessage__isnull=False,
    ).select_related(
        "conversation__owner", "conversation__organization", "conversation__apimessage"
    )


@endpoint(["GET"])
def inbox(request):
    current, query = mailbox_grants(request)
    rate_limit(request, "api-recipient-inbox", current.email, maximum=60, seconds=60)
    search = request.query_params.get("q", "").strip()
    if len(search) > 200:
        raise Problem("Search is limited to 200 characters.")
    if search:
        query = query.filter(conversation__sender__icontains=search)
    rows, meta = paginate(
        query,
        request,
        ordering={"updated_at": "conversation__updated_at", "sender": "conversation__sender"},
        default="-updated_at",
    )
    rows = list(rows)
    subjects = crypto.decrypt_many(
        [(r.conversation.subject_ciphertext, subject_context(r.conversation)) for r in rows]
    )
    audit(
        current.conversation.organization_id,
        current.pk,
        "recipient.api_inbox_viewed",
        "recipient_grant",
        current.pk,
    )
    return Response(
        {
            "results": [
                {
                    "id": str(row.conversation_id),
                    "sender": row.conversation.sender,
                    "subject": subject.decode(),
                    "state": row.conversation.state,
                    "updated_at": row.conversation.updated_at,
                    "can_reply": row.conversation.apimessage.allow_reply,
                    "current": row.pk == current.pk,
                }
                for row, subject in zip(rows, subjects, strict=True)
            ],
            **meta,
        }
    )


@endpoint(["POST"])
def open_conversation(request, ident):
    with transaction.atomic():
        current, query = mailbox_grants(request)
        rate_limit(request, "api-recipient-open", current.email, maximum=60, seconds=60)
        target = query.filter(conversation_id=ident).first()
        if not target:
            raise Problem("Conversation not found.", "not_found", 404)
        active_grant(target)
        original = (
            RecipientSession.objects.select_for_update()
            .filter(
                pk=request.session["recipient_session"],
                revoked_at=None,
                expires_at__gt=timezone.now(),
                created_at__gt=timezone.now() - timedelta(hours=8),
            )
            .first()
        )
        if not original:
            raise Problem("Verify your email again.", "recipient_session_expired", 401)
        # Preserve absolute and idle deadlines. Switching is not new OTP verification.
        access = RecipientSession.objects.create(
            grant=target, created_at=original.created_at, expires_at=original.expires_at
        )
        original.revoked_at = timezone.now()
        original.save(update_fields=["revoked_at"])
        request.session["recipient_session"] = str(access.pk)
        audit(
            target.conversation.organization_id,
            target.pk,
            "recipient.api_conversation_opened",
            "conversation",
            target.conversation_id,
        )
    return Response({"id": str(target.conversation_id)})
