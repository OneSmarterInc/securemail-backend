"""Private, continuing secure chats, one per staff member and recipient."""

import secrets

from django.conf import settings
from django.db.models import Count
from django.utils import timezone

from . import crypto, storage
from .http import Problem
from .models import (
    Attachment,
    Conversation,
    DirectChat,
    IdempotencyRecord,
    Message,
    RecipientGrant,
    RecipientInvitationToken,
)
from .services import audit, digest, queue_mail


def compose_private(
    user,
    data,
    decision,
    record,
    *,
    finalize=True,
    original_headers=None,
    source_message=None,
    prepared=None,
):
    # Called under the existing organisation transaction/lock. The unique pair
    # constraint additionally prevents two competing workers creating duplicate chats.
    from .conversations import attach_files, attachment_context, message_context, subject_context

    kinds = {email.lower(): kind for kind in ("bcc", "cc", "to") for email in data[kind]}
    recipients = list(
        dict.fromkeys(email.lower() for kind in ("to", "cc", "bcc") for email in data[kind])
    )
    ids = []
    first_message = source_message
    for email in recipients:
        pair = (
            DirectChat.objects.select_related("conversation")
            .filter(owner=user, recipient_email=email)
            .first()
        )
        conversation = pair.conversation if pair else None
        if conversation is None:
            # Reuse only a private, readable-era thread; never merge group histories
            # or reparent ciphertext whose authenticated context contains its IDs.
            candidates = (
                Conversation.objects.filter(
                    owner=user, organization=user.organization, protected=True, revoked_at=None
                )
                .annotate(recipient_count=Count("grants"))
                .filter(recipient_count=1, grants__email=email, grants__revoked_at=None)
                .order_by("created_at")
            )
            import json

            conversation = next(
                (c for c in candidates if "auth" in json.loads(c.subject_ciphertext)), None
            )
        if conversation is None:
            conversation = Conversation(
                organization=user.organization,
                owner=user,
                sender=data["sender"].lower(),
                mode=data["mode"],
                protected=True,
                routing_reason=decision.reason,
                policy_version="2026-10-31-private-chat",
                expires_at=None,
            )
            conversation.subject_ciphertext = crypto.encrypt(
                (data["subject"] or "Secure information request").encode(),
                subject_context(conversation),
            )
            conversation.save()
        if not pair:
            DirectChat.objects.create(
                organization=user.organization,
                owner=user,
                recipient_email=email,
                conversation=conversation,
            )
        if conversation.revoked_at:
            raise Problem(
                "Access to this chat was revoked. An administrator must review it before reuse.",
                status=409,
            )
        grant = conversation.grants.first()
        if grant and grant.revoked_at:
            raise Problem("Recipient access was revoked for this chat.", status=409)
        token = secrets.token_urlsafe(32)
        if grant:
            RecipientInvitationToken.objects.get_or_create(grant=grant, token_hash=grant.token_hash)
            grant.token_hash = digest(token)
            grant.save(update_fields=["token_hash"])
        else:
            grant = RecipientGrant.objects.create(
                conversation=conversation, email=email, kind=kinds[email], token_hash=digest(token)
            )
        conversation.updated_at = timezone.now()
        conversation.state = "awaiting_recipient"
        conversation.save(update_fields=["updated_at", "state"])
        message = Message(
            conversation=conversation,
            staff=user,
            mail_headers=original_headers or headers(user, data),
        )
        body = data["body"]
        if data["subject"]:
            body = data["subject"] + ("\n\n" + body if body else "")
        message.body_ciphertext = crypto.encrypt(body.encode(), message_context(message))
        message.save()
        if first_message is None:
            attach_files(message, data["attachments"], user=user, prepared=prepared)
            first_message = message
        else:
            # Each private chat owns an independently encrypted attachment; one
            # recipient's authorization never grants another chat's object access.
            for original in first_message.attachments.all():
                plaintext = crypto.decrypt(
                    storage.get(original.object_key).decode(), attachment_context(original)
                )
                name = crypto.decrypt(
                    original.name_ciphertext,
                    crypto.context(user.organization_id, "filename", original.pk),
                )
                clone = Attachment(
                    organization=user.organization,
                    message=message,
                    uploader=user,
                    size=original.size,
                    media_type=original.media_type,
                    state=original.state,
                    sha256=original.sha256,
                    evidence_capture=original.evidence_capture,
                )
                clone.name_ciphertext = crypto.encrypt(
                    name, crypto.context(user.organization_id, "filename", clone.pk)
                )
                clone.object_key = f"{user.organization_id}/messages/{message.pk}/{clone.pk}"
                encrypted = crypto.encrypt(plaintext, attachment_context(clone)).encode()
                storage.put(clone.object_key, encrypted)
                clone.stored_size = len(encrypted)
                clone.save()
        queue_mail(
            user.organization,
            {
                "to": email,
                "subject": "You have a new secure message",
                "body": f"You have a new secure message ({kinds[email].upper()}). Open the link and verify your email to read it and reply. Do not reply to this email.",
                "link": f"{settings.RECIPIENT_PUBLIC_URL}/#/invite/{token}",
            },
            actor=user,
            conversation=conversation,
            grant=grant,
        )
        audit(
            user.organization,
            user,
            "message.submitted",
            "conversation",
            conversation.pk,
            metadata={"private_chat": True},
        )
        ids.append(str(conversation.pk))
    if finalize:
        IdempotencyRecord.objects.create(**record, resource_id=ids[0])
    return {"id": ids[0], "conversation_ids": ids}


def headers(user, data):
    return {
        "from_name": user.display_name,
        "from_email": data["sender"].lower(),
        "to": list(dict.fromkeys(x.lower() for x in data["to"])),
        "cc": list(
            dict.fromkeys(
                x.lower() for x in data["cc"] if x.lower() not in {a.lower() for a in data["to"]}
            )
        ),
        "bcc": list(
            dict.fromkeys(
                x.lower()
                for x in data["bcc"]
                if x.lower() not in {a.lower() for a in data["to"] + data["cc"]}
            )
        ),
    }


def compose_secure(user, data, decision, record, *, prepared=None):
    import hashlib

    from .conversations import attach_files, message_context, subject_context
    from .models import GroupChat

    header = headers(user, data)
    visible = header["to"] + header["cc"]
    if len(visible) <= 1:
        return compose_private(
            user, data, decision, record, original_headers=header, prepared=prepared
        )
    group_hash = hashlib.sha256("\0".join(sorted(visible)).encode()).hexdigest()
    group = (
        GroupChat.objects.select_related("conversation")
        .filter(owner=user, participants_hash=group_hash)
        .first()
    )
    if group:
        conversation = group.conversation
        if conversation.revoked_at or conversation.grants.filter(revoked_at__isnull=False).exists():
            raise Problem(
                "This group has revoked access. Review access before sending again.", status=409
            )
    else:
        conversation = Conversation(
            organization=user.organization,
            owner=user,
            sender=data["sender"].lower(),
            mode=data["mode"],
            protected=True,
            routing_reason=decision.reason,
            policy_version="2026-10-31-shared-chat",
            expires_at=None,
        )
        conversation.subject_ciphertext = crypto.encrypt(
            (data["subject"] or "Secure information request").encode(),
            subject_context(conversation),
        )
        conversation.save()
        GroupChat.objects.create(
            owner=user, participants_hash=group_hash, conversation=conversation
        )
    conversation.updated_at = timezone.now()
    conversation.state = "awaiting_recipient"
    conversation.save(update_fields=["updated_at", "state"])
    message = Message(conversation=conversation, staff=user, shared=True, mail_headers=header)
    message.body_ciphertext = crypto.encrypt(
        (data["subject"] + "\n\n" + data["body"]).strip().encode(), message_context(message)
    )
    message.save()
    attach_files(message, data["attachments"], user=user, prepared=prepared)
    for email in visible:
        token = secrets.token_urlsafe(32)
        kind = "to" if email in header["to"] else "cc"
        grant = conversation.grants.filter(email=email).first()
        if grant:
            RecipientInvitationToken.objects.get_or_create(grant=grant, token_hash=grant.token_hash)
            grant.token_hash = digest(token)
            grant.kind = kind
            grant.save(update_fields=["token_hash", "kind"])
        else:
            grant = RecipientGrant.objects.create(
                conversation=conversation, email=email, kind=kind, token_hash=digest(token)
            )
        queue_mail(
            user.organization,
            {
                "to": email,
                "subject": "You have a new secure message",
                "body": f"You received a secure message ({kind.upper()}). Open the portal and verify your email to read it. Do not reply to this email.",
                "link": f"{settings.RECIPIENT_PUBLIC_URL}/#/invite/{token}",
            },
            actor=user,
            conversation=conversation,
            grant=grant,
        )
    ids = [str(conversation.pk)]
    if header["bcc"]:
        copies = compose_private(
            user,
            {**data, "to": [], "cc": [], "bcc": header["bcc"]},
            decision,
            record,
            finalize=False,
            original_headers=header,
            source_message=message,
        )
        ids.extend(copies["conversation_ids"])
    IdempotencyRecord.objects.create(**record, resource_id=conversation.pk)
    audit(
        user.organization,
        user,
        "message.submitted",
        "conversation",
        conversation.pk,
        metadata={"shared_to_cc": True, "blind_copies": len(header["bcc"])},
    )
    return {"id": str(conversation.pk), "conversation_ids": ids}
