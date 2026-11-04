import secrets
from datetime import timedelta

from django.conf import settings
from django.core import signing
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from django.utils.http import content_disposition_header
from rest_framework import serializers
from rest_framework.response import Response

from secure_mail import decide_delivery

from . import crypto, document_service, storage
from .auth import validate
from .company_identity import is_company_address
from .http import Problem, endpoint, unavailable
from .models import (
    Attachment,
    Conversation,
    IdempotencyRecord,
    Message,
    OTPChallenge,
    RecipientGrant,
    RecipientInvitationToken,
    RecipientSession,
)
from .services import (
    audit,
    current_staff,
    digest,
    idempotency,
    keyed,
    lock_organization,
    paginate,
    queue_mail,
    rate_limit,
    verifier_matches,
)


class Compose(serializers.Serializer):
    sender = serializers.EmailField()
    to = serializers.ListField(child=serializers.EmailField(), allow_empty=False, max_length=50)
    cc = serializers.ListField(child=serializers.EmailField(), default=list, max_length=50)
    bcc = serializers.ListField(child=serializers.EmailField(), default=list, max_length=50)
    subject = serializers.CharField(max_length=180, allow_blank=True, default="")
    body = serializers.CharField(max_length=100000, allow_blank=True, default="")
    mode = serializers.ChoiceField(choices=["ordinary", "secure_request"], default="ordinary")
    nophi_override = serializers.BooleanField(default=False)
    nophi_acknowledged = serializers.BooleanField(default=False)
    expected_route = serializers.DictField(required=False)
    expiry_days = serializers.ChoiceField(choices=[1, 7, 30], default=7)
    attachments = serializers.ListField(child=serializers.UUIDField(), max_length=10, default=list)

    def validate(self, data):
        if any(c in data["subject"] for c in "\r\n"):
            raise serializers.ValidationError("Subject cannot contain line breaks.")
        if data["mode"] == "ordinary" and (
            not data["subject"] or not data["body"] and not data["attachments"]
        ):
            raise serializers.ValidationError(
                "Ordinary messages require a subject and text or files."
            )
        if len(data["to"]) + len(data["cc"]) + len(data["bcc"]) > 50:
            raise serializers.ValidationError("At most 50 recipients are allowed.")
        return data


class Reply(serializers.Serializer):
    body = serializers.CharField(max_length=100000, allow_blank=True, default="")
    attachments = serializers.ListField(child=serializers.UUIDField(), max_length=10, default=list)
    audience = serializers.UUIDField(required=False, allow_null=True)
    reply_to = serializers.UUIDField(required=False, allow_null=True)
    reply_mode = serializers.ChoiceField(choices=["sender", "all"], default="sender")

    def validate(self, data):
        if not data["body"] and not data["attachments"]:
            raise serializers.ValidationError("Write a reply or attach a file.")
        return data


def subject_context(conversation):
    return crypto.context(conversation.organization_id, "conversation-subject", conversation.pk)


def message_context(message):
    return crypto.context(
        message.conversation.organization_id,
        "conversation-message",
        f"{message.conversation_id}/{message.pk}",
    )


def attachment_context(attachment):
    scope = (
        f"{attachment.message.conversation_id}/{attachment.message_id}"
        if attachment.message_id
        else f"staged/{attachment.uploader_id or attachment.grant_id}"
    )
    return crypto.context(attachment.organization_id, "attachment", f"{scope}/{attachment.pk}")


def active_grant(grant):
    if (
        grant.conversation.owner.status != "active"
        or not grant.conversation.owner.is_active
        or grant.revoked_at
        or grant.conversation.revoked_at
        or not grant.conversation.protected
    ):
        unavailable()
    return grant


def recipient(request):
    session = (
        RecipientSession.objects.select_related(
            "grant__conversation__organization", "grant__conversation__owner"
        )
        .filter(
            pk=request.session.get("recipient_session"),
            revoked_at=None,
            created_at__gt=timezone.now() - timedelta(hours=8),
            expires_at__gt=timezone.now(),
        )
        .first()
    )
    if session is None:
        raise Problem("Verify your email again to continue.", "recipient_session_expired", 401)
    return active_grant(session.grant)


def owned(request, ident):
    value = (
        Conversation.objects.select_related("owner", "organization")
        .filter(pk=ident, owner=request.user, organization=request.user.organization)
        .first()
    )
    return value if value else unavailable()


def attachment_data(attachment, name=None):
    return {
        "id": str(attachment.pk),
        "integrity_tag": attachment.sha256,
        "capture_id": str(attachment.evidence_capture_id)
        if attachment.evidence_capture_id
        else None,
        "name": name
        if name is not None
        else crypto.decrypt(
            attachment.name_ciphertext,
            crypto.context(attachment.organization_id, "filename", attachment.pk),
        ).decode(),
        "size": attachment.size,
        "state": attachment.state,
    }


def summary(conversation, subject=None, grants=None):
    return {
        "id": str(conversation.pk),
        "subject": subject
        if subject is not None
        else crypto.decrypt(
            conversation.subject_ciphertext, subject_context(conversation)
        ).decode(),
        "mode": conversation.mode,
        "protected": conversation.protected,
        "routing_reason": conversation.routing_reason,
        "state": conversation.state,
        "created_at": conversation.created_at,
        "updated_at": conversation.updated_at,
        "expires_at": None,
        "revoked": bool(conversation.revoked_at),
        "unread": conversation.last_staff_read is None
        or conversation.updated_at > conversation.last_staff_read,
        "recipients": [
            {
                "id": str(g.pk),
                "email": g.email,
                "kind": g.kind,
                "revoked": bool(g.revoked_at),
                "last_opened": g.last_opened,
            }
            for g in (conversation.grants.all() if grants is None else grants)
        ],
    }


def visible_messages(query, grant):
    return query.filter(
        Q(grant=grant)
        | Q(shared=True)
        | Q(staff__isnull=False, audience__isnull=True)
        | Q(audience=grant)
    )


def staff_visible_messages(query):
    # Callers scope the queryset to the authorized owner/conversation first.
    # Include historical recipient-to-recipient messages for owner oversight.
    return query


def safe_headers(message, viewer, grants=None):
    header = dict(message.mail_headers)
    if not header:
        if grants is None:
            grants = list(message.conversation.grants.all())
        header = {
            "from_name": message.staff.display_name if message.staff else message.grant.email,
            "from_email": message.conversation.sender if message.staff else message.grant.email,
            "to": [g.email for g in grants if g.kind == "to"],
            "cc": [g.email for g in grants if g.kind == "cc"],
            "bcc": [g.email for g in grants if g.kind == "bcc"],
        }
    if viewer:
        header["bcc"] = [viewer.email] if viewer.email in header.get("bcc", []) else []
    return header


def detail(conversation, grant=None, request=None):
    # Reuse this authorized conversation's recipients for all historical headers.
    # select_related creates separate conversation objects per message, so fetching
    # through message.conversation otherwise issues one query per missing header.
    grants = list(conversation.grants.all())
    messages = (
        conversation.messages.select_related("staff", "grant", "conversation")
        .prefetch_related("attachments")
        .order_by("created_at", "id")
    )
    if grant:
        messages = visible_messages(messages, grant)
    else:
        messages = staff_visible_messages(messages)
    next_cursor = None
    if request is not None:
        scope = f"{conversation.pk}:{grant.pk if grant else 'staff'}"
        cursor = request.query_params.get("before", "")
        if cursor:
            try:
                value = signing.loads(cursor, salt="message-page", max_age=86400)
                if value["scope"] != scope:
                    raise ValueError("Wrong cursor scope")
                from datetime import datetime
                from uuid import UUID

                date, ident = datetime.fromisoformat(value["date"]), UUID(value["id"])
                messages = messages.filter(
                    Q(created_at__lt=date) | Q(created_at=date, id__lt=ident)
                )
            except (signing.BadSignature, ValueError, KeyError, TypeError):
                raise Problem("Invalid or expired history cursor.", "invalid_cursor") from None
        page = list(messages.order_by("-created_at", "-id")[:51])
        messages = page[:50]
        if len(page) > 50:
            last = messages[-1]
            next_cursor = signing.dumps(
                {"scope": scope, "date": last.created_at.isoformat(), "id": str(last.pk)},
                salt="message-page",
            )
        messages.reverse()
    else:
        messages = list(messages)
    files = [a for m in messages for a in m.attachments.all()]
    values = [(conversation.subject_ciphertext, subject_context(conversation))]
    values.extend((m.body_ciphertext, message_context(m)) for m in messages)
    values.extend(
        (a.name_ciphertext, crypto.context(a.organization_id, "filename", a.pk)) for a in files
    )
    decoded = [value.decode() for value in crypto.decrypt_many(values)]
    bodies = dict(zip((m.pk for m in messages), decoded[1 : 1 + len(messages)], strict=True))
    names = dict(zip((a.pk for a in files), decoded[1 + len(messages) :], strict=True))
    data = (
        summary(conversation, decoded[0], grants)
        if grant is None
        else {
            "id": str(conversation.pk),
            "subject": decoded[0],
            "expires_at": None,
            "mode": conversation.mode,
            "state": conversation.state,
        }
    )
    data["can_reply_all"] = sum(g.revoked_at is None for g in grants) > 1 and (
        grant is None or grant.kind != "bcc"
    )
    data["viewer_email"] = grant.email if grant else conversation.sender
    data["next_messages_cursor"] = next_cursor
    data["messages"] = [
        {
            "id": str(m.pk),
            "author": m.staff.display_name
            if m.staff
            else ("You" if grant and m.grant_id == grant.pk else m.grant.email),
            "author_type": "staff" if m.staff else "recipient",
            "headers": safe_headers(m, grant, grants),
            "reply_to": str(m.reply_to_message_id) if m.reply_to_message_id else None,
            "shared": m.shared,
            "audience": str(m.audience_id) if m.audience_id else None,
            "body": bodies[m.pk],
            "created_at": m.created_at,
            "attachments": [attachment_data(a, names[a.pk]) for a in m.attachments.all()],
        }
        for m in messages
    ]
    if not grant:
        from django.db.models import Count

        data["delivery_counts"] = dict(
            conversation.delivery_jobs.values_list("state").annotate(total=Count("pk"))
        )
        data["delivery"] = [
            {"id": str(j.pk), "state": j.state, "attempts": j.attempts, "error_code": j.error_code}
            for j in conversation.delivery_jobs.order_by("-created_at", "id")[:100]
        ]
    return data


@endpoint(["GET"], staff=True)
def delivery_history(request, ident):
    conversation = owned(request, ident)
    rows, meta = paginate(
        conversation.delivery_jobs.all(),
        request,
        ordering={"created_at": "created_at"},
        default="-created_at",
    )
    return Response(
        {
            "results": [
                {
                    "id": str(row.pk),
                    "state": row.state,
                    "attempts": row.attempts,
                    "error_code": row.error_code,
                }
                for row in rows
            ],
            **meta,
        }
    )


def policy(user, data):
    sender = data["sender"].lower()
    if settings.MAIL_PROVIDER == "smtp":
        from .senders import SenderUnavailable
        from .smtp_settings import configured, credential

        try:
            personal = credential(user)
            if not configured(user):
                raise SenderUnavailable("SMTP server or credentials need attention")
        except SenderUnavailable:
            raise Problem(
                "Set up your personal SMTP sender in Connections first.", "smtp_setup_required", 409
            )
        if sender != personal.email:
            raise Problem("Send using your personal SMTP sender address.", "sender_denied", 403)
    if sender not in user.sender_addresses or not is_company_address(
        sender, user.organization.domain
    ):
        raise Problem("This sender address is not authorized.", "sender_denied", 403)
    if data["nophi_override"] and data["mode"] != "ordinary":
        raise Problem("Secure requests cannot use Nophi.", "nophi_not_allowed")
    decision = decide_delivery(
        authenticated_sender=sender,
        company_domain=user.organization.domain,
        company_addresses=settings.COMPANY_EMAIL_ALLOWLIST
        if user.organization.domain == settings.COMPANY_DOMAIN
        else (),
        recipients=data["to"] + data["cc"] + data["bcc"],
        subject="Nophi" if data["nophi_override"] else "",
        request_secure_information=data["mode"] == "secure_request",
    )
    if decision.reason == "explicit_nophi_override" and not user.can_nophi:
        audit(user.organization, user, "routing.nophi_denied", "account", user.pk, outcome="denied")
        raise Problem("You do not have permission to use Nophi.", "nophi_denied", 403)
    if decision.reason in {
        "invalid_subject",
        "missing_recipients",
        "invalid_address",
        "sender_outside_company",
    }:
        raise Problem("Invalid sender or recipients.")
    return decision


@endpoint(["POST"], staff=True)
def route_preview(request):
    data = validate(Compose, request.data)
    decision = policy(request.user, data)
    return Response({"protected": decision.protected, "reason": decision.reason})


def attach_files(message, ids, *, user=None, grant=None, prepared=None):
    if len(set(ids)) != len(ids):
        raise Problem("An attachment was listed more than once.")
    files = list(
        Attachment.objects.select_for_update(of=("self",))
        .select_related("message__conversation")
        .filter(
            pk__in=ids,
            organization=message.conversation.organization,
            message__isnull=True,
            uploader=user,
            grant=grant,
        )
    )
    if (
        len(files) != len(ids)
        or sum(a.size for a in files) > settings.MAX_UPLOAD_BYTES
        or any(a.state != "available" for a in files)
    ):
        raise Problem("Attachments are unavailable, not approved, or exceed the combined limit.")
    # New object keys preserve staged objects if this transaction rolls back; cleanup removes orphans.
    for attachment in files:
        staged_key = attachment.object_key
        from .attachment_preparation import fingerprint

        cached = (prepared or {}).get(str(attachment.pk))
        if cached is not None:
            if cached[0] != fingerprint(attachment):
                raise Problem("Staged attachment changed. Please retry.", "attachment_changed", 409)
            plaintext = cached[1]
        else:
            plaintext = crypto.decrypt(
                storage.get(attachment.object_key).decode(), attachment_context(attachment)
            )
        from .evidence import capture_attachment

        capture_attachment(attachment, plaintext)
        attachment.message = message
        ciphertext = crypto.encrypt(plaintext, attachment_context(attachment)).encode()
        attachment.object_key = (
            f"{attachment.organization_id}/messages/{message.pk}/{attachment.pk}"
        )
        storage.put(attachment.object_key, ciphertext)
        attachment.stored_size = len(ciphertext)
        attachment.save()
        transaction.on_commit(lambda key=staged_key: storage.remove(key), robust=True)


@endpoint(["GET", "POST"], staff=True)
def conversations(request):
    user = request.user
    if request.method == "GET":
        query = Conversation.objects.filter(
            owner=user, organization=user.organization
        ).prefetch_related("grants")
        search = request.query_params.get("q", "")[:200].strip()
        if request.query_params.get("state"):
            query = query.filter(state=request.query_params["state"])
        subjects = {}
        if search:
            rate_limit(request, "conversation_search", str(user.pk), maximum=10, seconds=60)
            from . import search_index

            if query.filter(search_indexed=False).exists():
                raise Problem(
                    "Conversation search index needs rebuilding.", "search_index_unavailable", 503
                )
            for word in search_index.words(search):
                query = query.filter(
                    Q(pk__in=search_index.ids(user.organization_id, "subject", word))
                    | Q(state__icontains=word)
                    | Q(grants__email__icontains=word)
                )
            query = query.distinct()
        items, meta = paginate(
            query,
            request,
            ordering={"created_at": "created_at", "updated_at": "updated_at", "state": "state"},
            default="-updated_at",
        )
        items = list(items)
        if items:
            subjects = {
                c.pk: value.decode()
                for c, value in zip(
                    items,
                    crypto.decrypt_many(
                        [(c.subject_ciphertext, subject_context(c)) for c in items]
                    ),
                    strict=True,
                )
            }
        return Response({"results": [summary(c, subjects[c.pk]) for c in items], **meta})
    document_service.require_ready()
    data = validate(Compose, request.data)
    from .attachment_preparation import prepare

    prepared = prepare(data["attachments"], user=user)
    with transaction.atomic():
        lock_organization(user.organization_id)
        user = current_staff(request)
        existing, record = idempotency(
            request, user.organization, f"staff:{user.pk}", "compose", data
        )
        if existing:
            return Response({"id": str(existing.resource_id)}, status=200)
        decision = policy(user, data)
        expected = data.get("expected_route")
        if data["mode"] == "ordinary" and expected != {
            "protected": decision.protected,
            "reason": decision.reason,
        }:
            raise Problem("Delivery route changed. Review it before sending.", "route_changed", 409)
        if decision.reason == "explicit_nophi_override" and not data["nophi_acknowledged"]:
            raise Problem(
                "Acknowledge that the content will be sent by ordinary email.",
                "nophi_acknowledgement_required",
            )

        if decision.protected:
            from .direct_chats import compose_secure

            result = compose_secure(user, data, decision, record, prepared=prepared)
            document_service.require_ready()
            return Response(result, status=201)

        conversation = Conversation(
            organization=user.organization,
            owner=user,
            sender=data["sender"].lower(),
            mode=data["mode"],
            protected=decision.protected,
            routing_reason=decision.reason,
            policy_version="2026-10-30-secure-default",
            expires_at=None,
        )
        conversation.subject_ciphertext = crypto.encrypt(
            (data["subject"] or "Secure information request").encode(),
            subject_context(conversation),
        )
        conversation.save()
        message = Message(conversation=conversation, staff=user)
        message.body_ciphertext = crypto.encrypt(data["body"].encode(), message_context(message))
        message.save()
        attach_files(message, data["attachments"], user=user, prepared=prepared)
        seen = set()
        for kind in ["to", "cc", "bcc"]:
            for address in data[kind]:
                address = address.lower()
                if address in seen:
                    continue
                seen.add(address)
                token = secrets.token_urlsafe(32)
                grant = RecipientGrant.objects.create(
                    conversation=conversation, email=address, kind=kind, token_hash=digest(token)
                )
                if decision.protected:
                    payload = {
                        "to": address,
                        "subject": "OneSmarter secure message",
                        "body": "OneSmarter has sent a secure message or information request. Verify your email to respond inside the portal. Do not reply to this notification.",
                        "link": f"{settings.RECIPIENT_PUBLIC_URL}/#/invite/{token}",
                    }
                else:
                    payload = {
                        "to": address,
                        "from": conversation.sender,
                        "subject": data["subject"],
                        "body": data["body"],
                        "attachments": [str(a) for a in data["attachments"]],
                    }
                queue_mail(
                    user.organization, payload, actor=user, conversation=conversation, grant=grant
                )
        document_service.require_ready()
        IdempotencyRecord.objects.create(**record, resource_id=conversation.pk)
        audit(
            user.organization,
            user,
            "conversation.created",
            "conversation",
            conversation.pk,
            metadata={
                "mode": data["mode"],
                "route": decision.reason,
                "policy_version": conversation.policy_version,
            },
        )
    return Response({"id": str(conversation.pk)}, status=201)


@endpoint(["GET"], staff=True)
def conversation_detail(request, ident):
    conversation = owned(request, ident)
    rate_limit(request, "thread_read", str(request.user.pk), maximum=60, seconds=60)
    audit(
        request.user.organization,
        request.user,
        "conversation.viewed",
        "conversation",
        conversation.pk,
    )
    Conversation.objects.filter(pk=conversation.pk).update(last_staff_read=timezone.now())
    return Response(detail(conversation, request=request))


@endpoint(["POST"], staff=True)
def revoke(request, ident):
    conversation = owned(request, ident)
    if not conversation.protected:
        raise Problem("Ordinary delivered email cannot be revoked.")
    with transaction.atomic():
        lock_organization(conversation.organization_id)
        current_staff(request)
        conversation = Conversation.objects.select_for_update().get(pk=conversation.pk)
        existing, record = idempotency(
            request,
            conversation.organization,
            f"staff:{request.user.pk}",
            f"revoke:{ident}",
            dict(request.data),
        )
        if existing:
            return Response({"revoked": True})
        grant_id = request.data.get("grant_id")
        if grant_id:
            grant = conversation.grants.filter(pk=grant_id).first()
            if not grant:
                unavailable()
            grant.revoked_at = timezone.now()
            grant.save(update_fields=["revoked_at"])
            audit(
                conversation.organization,
                request.user,
                "grant.revoked",
                "recipient_grant",
                grant.pk,
            )
        else:
            conversation.revoked_at = timezone.now()
            conversation.save(update_fields=["revoked_at"])
            audit(
                conversation.organization,
                request.user,
                "conversation.revoked",
                "conversation",
                conversation.pk,
            )
        IdempotencyRecord.objects.create(**record, resource_id=str(conversation.pk))
    return Response({"revoked": True})


def save_reply(request, conversation, data, *, user=None, grant=None):
    document_service.require_ready()
    from .attachment_preparation import prepare

    prepared = prepare(data["attachments"], user=user, grant=grant)
    with transaction.atomic():
        lock_organization(conversation.organization_id)
        if user:
            user = current_staff(request)
        conversation = (
            Conversation.objects.select_for_update(of=("self",))
            .select_related("organization", "owner")
            .get(pk=conversation.pk)
        )
        if not conversation.protected or conversation.revoked_at:
            raise Problem(
                "This conversation no longer accepts replies.", "conversation_unavailable", 403
            )
        if grant:
            recipient(request)
            active_grant(RecipientGrant.objects.select_related("conversation").get(pk=grant.pk))
        actor = f"staff:{user.pk}" if user else f"recipient:{grant.pk}"
        existing, record = idempotency(
            request, conversation.organization, actor, f"reply:{conversation.pk}", data
        )
        if existing:
            return existing.resource_id
        audience = None
        if user and data.get("audience"):
            audience = conversation.grants.filter(pk=data["audience"], revoked_at=None).first()
            if not audience:
                unavailable()
        selected = None
        if data.get("reply_to"):
            selection = conversation.messages.select_related("grant")
            if grant:
                selection = visible_messages(selection, grant)
            else:
                selection = staff_visible_messages(selection)
            selected = selection.filter(pk=data["reply_to"]).first()
            if selected is None:
                unavailable()
        shared = data["reply_mode"] == "all"
        if shared:
            if grant and (grant.kind == "bcc" or conversation.grants.count() < 2):
                raise Problem("Reply all is unavailable for a private copy.", status=400)
            audience = None
        elif user and selected and selected.grant_id:
            audience = selected.grant
            active_grant(audience)
        elif user and not audience and (selected or "reply_mode" in request.data):
            if conversation.grants.count() == 1:
                audience = conversation.grants.first()
            else:
                raise Problem(
                    "Select a recipient's message to reply privately, or choose Reply all."
                )
        targets = conversation.grants.filter(revoked_at=None)
        if audience:
            targets = targets.filter(pk=audience.pk)
        elif grant and not shared:
            targets = targets.none()
        if grant:
            targets = targets.exclude(pk=grant.pk)
        if shared:
            targets = targets.exclude(kind="bcc")
        sender_email = (
            getattr(getattr(user, "staffsmtp", None), "email", conversation.sender)
            if user
            else grant.email
        )
        message = Message(
            conversation=conversation,
            staff=user,
            grant=grant,
            audience=audience,
            shared=shared,
            reply_to_message=selected,
            mail_headers={
                "from_name": user.display_name if user else grant.email,
                "from_email": sender_email,
                "to": ([conversation.sender] if grant else [])
                + [g.email for g in targets if g.kind != "cc"],
                "cc": [g.email for g in targets if g.kind == "cc"],
                "bcc": [],
            },
        )
        message.body_ciphertext = crypto.encrypt(data["body"].encode(), message_context(message))
        message.save()
        attach_files(message, data["attachments"], user=user, grant=grant, prepared=prepared)
        conversation.state = "replied" if grant else "awaiting_recipient"
        conversation.updated_at = timezone.now()
        conversation.save(update_fields=["state", "updated_at"])
        if grant:
            queue_mail(
                conversation.organization,
                {
                    "to": getattr(
                        getattr(conversation.owner, "staffsmtp", None),
                        "email",
                        conversation.owner.email,
                    ),
                    "subject": "A secure conversation has a reply",
                    "body": "A recipient submitted a reply. Sign in to the portal to read it.",
                    "link": f"{settings.PUBLIC_URL}/#/messages/{conversation.pk}",
                },
                conversation=conversation,
            )
        for target in targets:
            # Retain the old hash atomically with the new notification. All
            # links remain subject to revocation and still require fresh OTP verification.
            RecipientInvitationToken.objects.get_or_create(
                grant=target, token_hash=target.token_hash
            )
            token = secrets.token_urlsafe(32)
            target.token_hash = digest(token)
            target.save(update_fields=["token_hash"])
            queue_mail(
                conversation.organization,
                {
                    "to": target.email,
                    "subject": "Your secure conversation has a reply",
                    "body": "Open the portal and verify your email to read the reply. Respond only in the portal.",
                    "link": f"{settings.RECIPIENT_PUBLIC_URL}/#/invite/{token}",
                },
                actor=user,
                conversation=conversation,
                grant=target,
            )
        document_service.require_ready()
        IdempotencyRecord.objects.create(**record, resource_id=message.pk)
        audit(
            conversation.organization,
            user or grant.pk,
            "message.submitted",
            "conversation",
            conversation.pk,
            metadata={
                "author_type": "staff" if user else "recipient",
                "file_count": len(data["attachments"]),
                "reply_mode": data["reply_mode"],
                "recipient_private_to_owner": bool(grant and not shared),
            },
        )
    return message.pk


@endpoint(["POST"], staff=True)
def staff_reply(request, ident):
    ident = save_reply(
        request, owned(request, ident), validate(Reply, request.data), user=request.user
    )
    return Response({"id": str(ident)}, status=201)


class InvitationToken(serializers.Serializer):
    token = serializers.CharField(max_length=200, required=False, allow_blank=True, default="")
    code = serializers.RegexField(r"^\d{6}$", required=False)


def token_grant(token):
    token_hash = digest(token)
    grant = (
        RecipientGrant.objects.select_related("conversation__organization", "conversation__owner")
        .filter(token_hash=token_hash)
        .first()
    )
    if grant is None:
        previous = (
            RecipientInvitationToken.objects.select_related(
                "grant__conversation__organization", "grant__conversation__owner"
            )
            .filter(token_hash=token_hash)
            .first()
        )
        grant = previous.grant if previous else None
    return active_grant(grant) if grant else unavailable()


@endpoint(["POST"])
def landing(request):
    data = validate(InvitationToken, request.data)
    rate_limit(request, "landing", maximum=60)
    grant = token_grant(data["token"])
    local, domain = grant.email.split("@")
    return Response(
        {
            "organization": grant.conversation.organization.name,
            "recipient": local[:1] + "***@" + domain,
        }
    )


def verification_grant(request, token):
    if token:
        return token_grant(token)
    # An idle session is only a routing hint for a new email challenge. It never
    # authorizes reading content. Revocation and conversation expiry still apply.
    session = (
        RecipientSession.objects.select_related(
            "grant__conversation__organization", "grant__conversation__owner"
        )
        .filter(pk=request.session.get("recipient_session"), revoked_at=None)
        .first()
    )
    if session:
        return active_grant(session.grant)
    return token_grant(token)


@endpoint(["POST"])
def issue_code(request):
    data = validate(InvitationToken, request.data)
    grant = verification_grant(request, data["token"])
    from .smtp_settings import configured

    if settings.MAIL_PROVIDER == "smtp" and not configured(grant.conversation.owner):
        raise Problem(
            "Verification email is unavailable. Ask the sender to configure their SMTP credentials.",
            "otp_sender_unavailable",
            503,
        )
    rate_limit(request, "code-hour", grant.email, maximum=10, seconds=3600)
    rate_limit(request, "code-day", grant.email, maximum=30, seconds=86400)
    with transaction.atomic():
        lock_organization(grant.conversation.organization_id)
        grant = verification_grant(request, data["token"])
        RecipientGrant.objects.select_for_update().get(pk=grant.pk)
        latest = OTPChallenge.objects.filter(grant=grant).order_by("-created_at").first()
        if latest and (timezone.now() - latest.created_at).total_seconds() < 30:
            raise Problem("Wait 30 seconds before requesting another code.", "resend_cooldown", 429)
        OTPChallenge.objects.filter(grant=grant, consumed_at=None).update(
            consumed_at=timezone.now()
        )
        code = f"{secrets.randbelow(1000000):06d}"
        challenge = OTPChallenge(grant=grant, expires_at=timezone.now() + timedelta(minutes=10))
        challenge.verifier = keyed(f"otp:{challenge.pk}:{code}", purpose="otp")
        challenge.save()
        queue_mail(
            grant.conversation.organization,
            {
                "to": grant.email,
                "subject": "Your OneSmarter verification code",
                "body": f"Your one-time code is {code}. It expires in 10 minutes. Do not share it.",
                "challenge_id": str(challenge.pk),
            },
            conversation=grant.conversation,
            grant=grant,
        )
        audit(
            grant.conversation.organization,
            grant.pk,
            "recipient.code_issued",
            "recipient_grant",
            grant.pk,
        )
    return Response({"sent": True, "resend_after": 30})


@endpoint(["POST"])
def verify_code(request):
    data = validate(InvitationToken, request.data)
    grant = verification_grant(request, data["token"])
    rate_limit(request, "code-attempt", grant.email, maximum=20, seconds=3600)
    accepted = False
    with transaction.atomic():
        lock_organization(grant.conversation.organization_id)
        grant = verification_grant(request, data["token"])
        RecipientGrant.objects.select_for_update().get(pk=grant.pk)
        challenge = (
            OTPChallenge.objects.select_for_update()
            .filter(grant=grant, consumed_at=None)
            .order_by("-created_at")
            .first()
        )
        if challenge and challenge.expires_at > timezone.now() and challenge.attempts < 5:
            challenge.attempts += 1
            accepted = verifier_matches(
                f"otp:{challenge.pk}:{data.get('code', '')}", challenge.verifier, purpose="otp"
            )
            if accepted:
                challenge.consumed_at = timezone.now()
                access = RecipientSession.objects.create(
                    grant=grant, expires_at=timezone.now() + timedelta(minutes=15)
                )
                grant.last_opened = timezone.now()
                grant.save(update_fields=["last_opened"])
            challenge.save()
        audit(
            grant.conversation.organization,
            grant.pk,
            "recipient.verified" if accepted else "recipient.code_failed",
            "recipient_grant",
            grant.pk,
            outcome="success" if accepted else "failure",
        )
    if not accepted:
        raise Problem("The code is incorrect, expired, used, or exhausted.", "invalid_code")
    request.session.cycle_key()
    request.session["recipient_session"] = str(access.pk)
    return Response({"verified": True})


@endpoint(["GET", "POST"])
def recipient_conversation(request):
    grant = recipient(request)
    if request.method == "GET":
        rate_limit(request, "recipient_thread_read", str(grant.pk), maximum=60, seconds=60)
        audit(
            grant.conversation.organization,
            grant.pk,
            "recipient.viewed",
            "conversation",
            grant.conversation_id,
        )
        return Response(detail(grant.conversation, grant, request=request))
    data = validate(Reply, request.data)
    if data.get("audience"):
        raise Problem("Recipient replies are private to assigned staff.")
    ident = save_reply(request, grant.conversation, data, grant=grant)
    return Response({"id": str(ident)}, status=201)


@endpoint(["POST"])
def recipient_activity(request):
    grant = recipient(request)
    now = timezone.now()
    updated = RecipientSession.objects.filter(
        pk=request.session.get("recipient_session"),
        grant=grant,
        revoked_at=None,
        expires_at__gt=now,
    ).update(expires_at=now + timedelta(minutes=15))
    if not updated:
        raise Problem("Verify your email again to continue.", "recipient_session_expired", 401)
    return Response({"active": True})


@endpoint(["POST"])
def recipient_logout(request):
    ident = request.session.pop("recipient_session", None)
    if ident:
        RecipientSession.objects.filter(pk=ident).update(revoked_at=timezone.now())
    request.session.flush()
    response = Response({"locked": True})
    response.delete_cookie("recipient_sessionid", path="/recipient-api/", samesite="Lax")
    return response


def upload_for(request, *, user=None, grant=None, captured_metadata=None):
    from . import evidence

    provenance = captured_metadata or evidence.source_metadata(request)
    document_service.require_ready()
    org = user.organization if user else grant.conversation.organization
    rate_limit(request, "upload", str(user.pk if user else grant.pk), maximum=30)
    upload = request.FILES.get("file")
    if not upload or upload.size <= 0 or upload.size > settings.MAX_UPLOAD_BYTES:
        raise Problem("Choose a non-empty file up to 25 MB.")
    from django.db.models import Sum

    with transaction.atomic():
        lock_organization(org)
        current_staff(request) if user else recipient(request)
        staged = (
            Attachment.objects.filter(
                organization=org, uploader=user, grant=grant, message__isnull=True
            )
            .exclude(state="deleted")
            .aggregate(total=Sum("size"))["total"]
            or 0
        )
        if staged + upload.size > settings.STAGED_UPLOAD_QUOTA_BYTES:
            raise Problem(
                "Staged upload quota reached. Submit existing files before uploading more.",
                "staged_quota",
                413,
            )
        attachment = Attachment(
            organization=org, uploader=user, grant=grant, size=upload.size, state="pending"
        )
        attachment.object_key = f"{org.pk}/staged/{attachment.pk}"
        attachment.save()
    try:
        data = upload.read(settings.MAX_UPLOAD_BYTES + 1)
        if len(data) > settings.MAX_UPLOAD_BYTES:
            raise Problem("File size limit exceeded.")
        name, media_type = storage.validate_file(upload.name, data)
        document_service.require_ready()
        from .integrity import tag

        attachment.sha256 = tag(org.pk, data)
        attachment.source_metadata_ciphertext = crypto.encrypt(
            evidence.canonical(provenance), crypto.context(org.pk, "source-metadata", attachment.pk)
        )
        attachment.size = len(data)
        attachment.media_type = media_type
        attachment.state = "available"
        attachment.name_ciphertext = crypto.encrypt(
            name.encode(), crypto.context(org.pk, "filename", attachment.pk)
        )
        attachment.object_key = f"{org.pk}/staged/{attachment.pk}"
        encrypted = crypto.encrypt(data, attachment_context(attachment)).encode()
        attachment.stored_size = len(encrypted)
        with transaction.atomic():
            lock_organization(org)
            if user:
                current_staff(request)
            else:
                recipient(request)
            if not Attachment.objects.filter(
                pk=attachment.pk, state="pending", message=None
            ).exists():
                raise Problem(
                    "Upload reservation expired. Please upload again.", "upload_expired", 409
                )
            storage.put(attachment.object_key, encrypted)
            attachment.save()
            audit(
                org,
                user or grant.pk,
                "attachment.uploaded",
                "attachment",
                attachment.pk,
                metadata={"bytes": len(data)},
            )
        return Response(attachment_data(attachment), status=201)
    except BaseException:
        # Reserved bytes are released on failure. Crash reservations remain fail-closed
        # until the existing staged-upload cleanup procedure removes them.
        try:
            storage.remove(attachment.object_key)
        except Exception:
            pass  # Keep the reservation and object key for retryable staged cleanup.
        else:
            Attachment.objects.filter(pk=attachment.pk, message__isnull=True).delete()
        raise


@endpoint(["POST"], staff=True)
def staff_upload(request):
    return upload_for(request, user=request.user)


@endpoint(["POST"])
def recipient_upload(request):
    return upload_for(request, grant=recipient(request))


@endpoint(["GET"])
def download(request, ident):
    attachment = (
        Attachment.objects.select_related("message__conversation__owner")
        .filter(pk=ident, state="available", message__isnull=False)
        .first()
    )
    if attachment is None:
        unavailable()
    conversation = attachment.message.conversation
    user = request.user
    if (
        user.is_authenticated
        and user.status == "active"
        and user.mfa_confirmed
        and request.session.get("mfa_at")
        and request.session.get("staff_version") == user.session_version
        and conversation.owner_id == user.pk
        and conversation.organization_id == user.organization_id
    ):
        if not staff_visible_messages(Message.objects.filter(pk=attachment.message_id)).exists():
            unavailable()
        actor = user
    else:
        grant = recipient(request)
        if (
            grant.conversation_id != conversation.pk
            or not visible_messages(
                Message.objects.filter(pk=attachment.message_id), grant
            ).exists()
        ):
            unavailable()
        actor = grant.pk
    # Recipient authorization above enforces expiry/revocation. Assigned staff may
    # still read retained records; ending recipient access is not data deletion.
    content, name_bytes = crypto.decrypt_many(
        [
            (storage.get(attachment.object_key).decode(), attachment_context(attachment)),
            (
                attachment.name_ciphertext,
                crypto.context(attachment.organization_id, "filename", attachment.pk),
            ),
        ]
    )
    from .integrity import matches

    if attachment.sha256 and not matches(attachment.organization_id, content, attachment.sha256):
        raise Problem("File integrity verification failed.", "integrity_failed", 503)
    name = name_bytes.decode()
    audit(conversation.organization_id, actor, "attachment.downloaded", "attachment", attachment.pk)
    response = HttpResponse(content, content_type="application/octet-stream")
    response["Content-Disposition"] = content_disposition_header(True, name)
    response["Content-Security-Policy"] = "sandbox"
    return response
