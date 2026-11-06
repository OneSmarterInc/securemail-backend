"""Independent partner inbox. Service signatures never authorize browser reads."""

import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from datetime import timedelta
from urllib.parse import quote, urlsplit

from django.conf import settings
from django.core import signing
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.middleware.csrf import get_token
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from . import crypto
from .http import Problem, endpoint, unavailable
from .models import StaffUser
from .portal_models import (
    IntegrationNonce,
    PortalChallenge,
    PortalMailbox,
    PortalMessage,
    PortalParticipant,
    PortalSession,
    PortalThread,
)
from .services import audit, keyed, lock_organization, queue_mail, rate_limit


def encrypt(value, org, kind, ident):
    return crypto.encrypt(
        json.dumps(value, separators=(",", ":")).encode(), crypto.context(org, kind, ident)
    )


def decrypt(value, org, kind, ident):
    return json.loads(crypto.decrypt(value, crypto.context(org, kind, ident)))


def field(data, name, maximum):
    value = data.get(name)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise Problem(f"Invalid {name}.")
    return value.strip()


def email(value):
    if not isinstance(value, str) or len(value) > 254:
        raise Problem("Invalid email.")
    value = value.strip().lower()
    validate_email(value)
    return value


def integration(source):
    config = settings.SECURE_MAIL_INTEGRATIONS.get(source)
    if not isinstance(config, dict) or not config.get("enabled", False):
        raise Problem("Integration unavailable.", "integration_unavailable", 503)
    return config


def owner_for(source):
    config = integration(source)
    owner = (
        StaffUser.objects.select_related("organization")
        .filter(
            pk=config.get("owner_id"),
            is_active=True,
            status="active",
            mfa_confirmed=True,
        )
        .first()
    )
    if not owner:
        raise Problem("Integration unavailable.", "integration_unavailable", 503)
    return owner


def portal_link(thread=None):
    # No capability, address or personal information is carried in this URL.
    return (
        settings.RECIPIENT_PUBLIC_URL.rstrip("/")
        + "/inbox"
        + (f"?source={quote(thread.source)}#thread/{thread.pk}" if thread else "")
    )


def invitation_link(participant):
    # Signed identifiers select a recipient, never authorize inbox access.
    # No email or personal information is embedded in the URL.
    token = signing.dumps(
        {"mailbox": str(participant.mailbox_id), "thread": str(participant.thread_id)},
        salt="portal-invitation-v1",
    )
    return settings.RECIPIENT_PUBLIC_URL.rstrip("/") + "/inbox#invite/" + token


def notification_source(data, job):
    """Resolve routing from scoped records, never subjects or recipient domains."""
    if data.get("portal_thread"):
        return (
            PortalThread.objects.filter(
                pk=data["portal_thread"], organization_id=job.organization_id
            )
            .values_list("source", flat=True)
            .first()
        )
    if data.get("portal_challenge_id"):
        challenge = PortalChallenge.objects.filter(
            pk=data["portal_challenge_id"], mailbox__organization_id=job.organization_id
        ).first()
        if challenge:
            sources = set(
                active_memberships(challenge.mailbox).values_list("thread__source", flat=True)
            )
            source = data.get("portal_source")
            if source:
                return source if source in sources else None
            # Compatibility for already queued OTPs, only when the source is unambiguous.
            return next(iter(sources)) if len(sources) == 1 else None
    return None


def delivery_allowed(data, job):
    """Recheck revocation and suppression at send time, including queued mail."""
    if data.get("portal_challenge_id"):
        return PortalChallenge.objects.filter(
            pk=data["portal_challenge_id"],
            consumed_at=None,
            attempts__lt=5,
            expires_at__gt=timezone.now(),
            mailbox__disabled_at=None,
            mailbox__organization_id=job.organization_id,
        ).exists()
    if not data.get("portal_thread"):
        return True
    participant = (
        PortalParticipant.objects.select_related("thread", "mailbox")
        .filter(
            thread_id=data["portal_thread"],
            mailbox_id=data.get("portal_mailbox"),
            revoked_at=None,
            thread__organization_id=job.organization_id,
            thread__revoked_at=None,
            thread__owner__is_active=True,
            thread__owner__status="active",
            mailbox__disabled_at=None,
        )
        .first()
    )
    if not participant or participant.suppress_notifications:
        return False
    config = settings.SECURE_MAIL_INTEGRATIONS.get(participant.thread.source, {})
    return bool(
        config.get("enabled")
        and not (
            participant.role == "provider" and config.get("suppress_provider_notifications", True)
        )
    )


def authenticate_service(request):
    source = request.headers.get("X-Integration-Key", "")
    if not re.fullmatch(r"[a-z0-9_-]{1,64}", source) or (
        not settings.SYNTHETIC_MODE and not request.is_secure()
    ):
        raise Problem("Invalid service authentication.", "service_unauthorized", 401)
    config = integration(source)
    secret = config.get("secret", "")
    stamp = request.headers.get("X-Integration-Time", "")
    nonce = request.headers.get("X-Integration-Nonce", "")
    signature = request.headers.get("X-Integration-Signature", "")
    if (
        len(secret) < 32
        or not re.fullmatch(r"\d{10}", stamp)
        or abs(time.time() - int(stamp)) > 300
        or not re.fullmatch(r"[a-f0-9]{32}", nonce)
    ):
        raise Problem("Invalid service authentication.", "service_unauthorized", 401)
    body = request.body
    if len(body) > 32768:
        raise Problem("Request too large.", "request_too_large", 413)
    canonical = "\n".join(
        ["POST", request.path, source, stamp, nonce, hashlib.sha256(body).hexdigest()]
    )
    expected = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise Problem("Invalid service authentication.", "service_unauthorized", 401)
    # Persist before processing: even failed requests cannot replay a signed nonce.
    try:
        with transaction.atomic():
            IntegrationNonce.objects.filter(expires_at__lt=timezone.now()).delete()
            IntegrationNonce.objects.create(
                source=source, nonce=nonce, expires_at=timezone.now() + timedelta(minutes=10)
            )
    except IntegrityError:
        raise Problem("Request already used.", "service_replay", 409) from None
    rate_limit(request, "integration-create", source, maximum=120, seconds=60)
    return source, config, owner_for(source)


def mailbox_for(org, address):
    mailbox, created = PortalMailbox.objects.get_or_create(
        organization=org,
        email_hash=keyed(address, purpose="portal-email"),
        defaults={"email_ciphertext": ""},
    )
    if created:
        mailbox.email_ciphertext = encrypt(address, org.pk, "portal-email", mailbox.pk)
        mailbox.save(update_fields=["email_ciphertext"])
    if mailbox.disabled_at:
        raise Problem("Mailbox unavailable.", "mailbox_disabled", 409)
    return mailbox


def notify(participant, *, initial=False, booking_names=None):
    thread = participant.thread
    config = integration(thread.source)
    # Suppression is enforced both here AND when the existing worker sends mail.
    if participant.suppress_notifications or (
        participant.role == "provider" and config.get("suppress_provider_notifications", True)
    ):
        return
    address = decrypt(
        participant.mailbox.email_ciphertext,
        thread.organization_id,
        "portal-email",
        participant.mailbox_id,
    )
    notification = {
        "to": address,
        "subject": "Your secure appointment conversation" if initial else "New secure message",
        "body": "Open Secure Mail and verify your email to view your conversation. Please do not reply to this automated email.",
        "link": invitation_link(participant),
        "portal_thread": str(thread.pk),
        "portal_mailbox": str(participant.mailbox_id),
    }
    if initial and thread.source == "selfpay" and participant.role == "provider" and booking_names:
        patient, clinic = booking_names
        notification.update(
            subject="New appointment request via MySelfPay",
            notification_kind="selfpay_clinic_request",
            body=(
                f"Dear {clinic} Team,\n\n"
                f"{patient} has submitted an appointment request to your clinic through MySelfPay.\n\n"
                "MySelfPay helps patients find self-pay healthcare services and request "
                "appointments directly with participating clinics.\n\n"
                f"MySelfPay booking reference: {thread.external_id}\n\n"
                "Please continue to OneSmarter Secure Mail to review the full request "
                "and review the approval action. You will be asked to verify your email using a "
                "one-time code before accessing the conversation.\n\n"
                "This request does not confirm an appointment. Your clinic must review "
                "and complete the confirmation process.\n\n"
                "Kind regards,\nPatient Care\nMySelfPay"
            ),
        )
    queue_mail(
        thread.organization,
        notification,
        actor=thread.owner,
    )


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def create_thread(request):
    source, config, owner = authenticate_service(request)
    data = request.data
    if not isinstance(data, dict):
        raise Problem("A JSON object is required.")
    if data.get("event_type") == "booking_confirmed":
        return confirmation_event(source, config, owner, data)
    if "event_type" in data:
        raise Problem("Unsupported integration event.")
    external_id = field(data, "external_id", 100)
    title, body = field(data, "subject", 200), field(data, "body", 16000)
    mode = data.get("delivery_mode", "two_party")
    if mode not in ("two_party", "provider_only") or (
        mode == "provider_only" and source != "selfpay"
    ):
        raise Problem("Invalid delivery mode.")
    provider_only = mode == "provider_only"
    people = data.get("participants")
    if not isinstance(people, list) or len(people) != (1 if provider_only else 2):
        raise Problem("Invalid participant count.")
    normalized = []
    for person in people:
        if not isinstance(person, dict) or person.get("role") not in {"requester", "provider"}:
            raise Problem("Invalid participant.")
        normalized.append(
            {
                "email": email(person.get("email")),
                "name": field(person, "name", 160),
                "role": person["role"],
            }
        )
    if provider_only:
        if normalized[0]["role"] != "provider":
            raise Problem("A provider mailbox is required.")
    elif {p["role"] for p in normalized} != {"requester", "provider"} or normalized[0][
        "email"
    ] == normalized[1]["email"]:
        raise Problem("Distinct requester and provider mailboxes are required.")
    provider_action = data.get("provider_action")
    if provider_only and provider_action is None:
        raise Problem("A clinic approval action is required.")
    if provider_action is not None:
        if not isinstance(provider_action, dict):
            raise Problem("Invalid clinic action.")
        action_url = field(provider_action, "url", 2048)
        parsed = urlsplit(action_url)
        action_origin = f"{parsed.scheme}://{parsed.netloc}"
        allowed = config.get("provider_action_origins", [])
        local = settings.SYNTHETIC_MODE and parsed.hostname in {"localhost", "127.0.0.1"}
        expires = provider_action.get("expires_at")
        if (
            action_origin not in allowed
            or parsed.username
            or parsed.password
            or (parsed.scheme != "https" and not (local and parsed.scheme == "http"))
            or not isinstance(expires, (int, float))
            or isinstance(expires, bool)
            or not time.time() < expires < time.time() + 7 * 86400
        ):
            raise Problem("Invalid clinic action.")
        provider_action = {"url": action_url, "expires_at": expires}
    canonical = {
        "subject": title,
        "body": body,
        "participants": sorted(normalized, key=lambda p: p["role"]),
    }
    if provider_only:
        canonical["delivery_mode"] = mode
    if provider_action is not None:
        canonical["provider_action"] = provider_action
    fingerprint = keyed(json.dumps(canonical, sort_keys=True), purpose="portal-request")
    with transaction.atomic():
        lock_organization(owner.organization)
        prior = PortalThread.objects.filter(source=source, external_id=external_id).first()
        if prior:
            if not hmac.compare_digest(prior.fingerprint, fingerprint):
                raise Problem(
                    "Request ID reused with different content.", "idempotency_conflict", 409
                )
            return Response(
                {
                    "id": str(prior.pk),
                    "url": portal_link(prior),
                    "provider_notification": "suppressed"
                    if config.get("suppress_provider_notifications", True)
                    else "queued",
                }
            )
        thread = PortalThread(
            organization=owner.organization,
            owner=owner,
            source=source,
            external_id=external_id,
            fingerprint=fingerprint,
        )
        metadata = {"subject": title, "source_name": config.get("name", source), "names": {}}
        if provider_only:
            metadata["delivery_mode"] = mode
        if provider_action is not None:
            metadata["provider_action"] = provider_action
        thread.metadata_ciphertext = ""
        thread.save()
        for person in normalized:
            mailbox = mailbox_for(owner.organization, person["email"])
            metadata["names"][str(mailbox.pk)] = person["name"]
            participant = PortalParticipant.objects.create(
                thread=thread,
                mailbox=mailbox,
                role=person["role"],
                suppress_notifications=person["role"] == "provider"
                and config.get("suppress_provider_notifications", True),
            )
            notify(
                participant,
                initial=True,
                booking_names=(
                    next(
                        (p["name"] for p in normalized if p["role"] == "requester"),
                        "MySelfPay user",
                    ),
                    next(p["name"] for p in normalized if p["role"] == "provider"),
                ),
            )
        thread.metadata_ciphertext = encrypt(
            metadata, owner.organization_id, "portal-thread", thread.pk
        )
        thread.save(update_fields=["metadata_ciphertext"])
        message = PortalMessage(
            thread=thread,
            submission_key="initial",
            fingerprint=fingerprint,
            audience="provider" if source == "selfpay" else "all",
        )
        message.body_ciphertext = encrypt(
            body, owner.organization_id, "portal-message", message_context_id(message)
        )
        message.save()
        if source == "selfpay" and not provider_only:
            clinic = next(p["name"] for p in normalized if p["role"] == "provider")
            receipt = PortalMessage(
                thread=thread,
                audience="requester",
                submission_key="initial_requester",
                fingerprint=fingerprint,
            )
            receipt.body_ciphertext = encrypt(
                f"Your appointment request to {clinic} has been received through MySelfPay.\n"
                f"MySelfPay booking reference: {external_id}\n"
                "Your clinic will review the request. The current approval status is shown above.",
                owner.organization_id,
                "portal-message",
                message_context_id(receipt),
            )
            receipt.save()
        audit(owner.organization, owner, "integration.thread_created", "portal_thread", thread.pk)
    return Response(
        {
            "id": str(thread.pk),
            "url": portal_link(thread),
            "provider_notification": "suppressed"
            if config.get("suppress_provider_notifications", True)
            else "queued",
        },
        status=201,
    )


def message_context_id(message):
    # Bind private-message audience to authenticated encryption as well as SQL filtering.
    return message.pk if message.audience == "all" else f"{message.pk}:{message.audience}"


def visible_messages(thread, member):
    messages = thread.messages.filter(Q(audience="all") | Q(audience=member.role))
    # Previously-created SelfPay booking details must also be clinic-only.
    if thread.source == "selfpay" and member.role != "provider":
        messages = messages.exclude(sender=None, submission_key="initial")
    return messages


def confirmation_event(source, config, owner, data):
    external_id = field(data, "external_id", 100)
    event_id = field(data, "event_id", 80)
    body = field(data, "body", 16000)
    actions = data.get("actions", [])
    if not isinstance(actions, list) or len(actions) > 5:
        raise Problem("Invalid confirmation actions.")
    normalized = []
    for action in actions:
        if not isinstance(action, dict):
            raise Problem("Invalid confirmation action.")
        url, label = field(action, "url", 2048), field(action, "label", 80)
        parsed = urlsplit(url)
        expiry = action.get("expires_at")
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or f"{parsed.scheme}://{parsed.netloc}" not in config.get("provider_action_origins", [])
            or not isinstance(expiry, (int, float))
            or isinstance(expiry, bool)
            or not 0 < expiry < time.time() + 31 * 86400
        ):
            raise Problem("Invalid confirmation action.")
        normalized.append({"url": url, "label": label, "expires_at": expiry})
    content = {"body": body, "actions": normalized}
    fingerprint = keyed(json.dumps(content, sort_keys=True), purpose="portal-confirmation")
    with transaction.atomic():
        lock_organization(owner.organization)
        thread = (
            PortalThread.objects.select_for_update()
            .filter(
                source=source,
                external_id=external_id,
                organization=owner.organization,
                owner=owner,
                revoked_at=None,
            )
            .first()
        )
        if not thread:
            raise Problem("Conversation unavailable.", "not_found", 404)
        key = "confirmation:" + event_id
        prior = thread.messages.filter(sender=None, submission_key=key).first()
        if prior:
            if not hmac.compare_digest(prior.fingerprint, fingerprint):
                raise Problem(
                    "Event ID reused with different content.", "idempotency_conflict", 409
                )
            return Response({"id": str(prior.pk), "thread_id": str(thread.pk)})
        recipient = (
            thread.participants.select_related("mailbox", "thread__organization", "thread__owner")
            .filter(
                role="requester",
                revoked_at=None,
                mailbox__disabled_at=None,
            )
            .first()
        )
        if not recipient:
            raise Problem("Recipient unavailable.", "not_found", 404)
        message = PortalMessage(
            thread=thread, audience="requester", submission_key=key, fingerprint=fingerprint
        )
        message.body_ciphertext = encrypt(
            content, thread.organization_id, "portal-message", message_context_id(message)
        )
        message.save()
        thread.updated_at = message.created_at
        thread.save(update_fields=["updated_at"])
        notify(recipient)
        audit(
            owner.organization,
            owner,
            "integration.confirmation_created",
            "portal_thread",
            thread.pk,
        )
    return Response({"id": str(message.pk), "thread_id": str(thread.pk)}, status=201)


def message_output(message, thread, info, mailbox_id):
    content = decrypt(
        message.body_ciphertext,
        thread.organization_id,
        "portal-message",
        message_context_id(message),
    )
    actions = content.get("actions", []) if isinstance(content, dict) else []
    allowed = integration(thread.source).get("provider_action_origins", [])
    actions = [
        action
        for action in actions
        if action["expires_at"] > time.time()
        and f"{urlsplit(action['url']).scheme}://{urlsplit(action['url']).netloc}" in allowed
    ]
    return {
        "id": str(message.pk),
        "body": content["body"] if isinstance(content, dict) else content,
        "actions": actions,
        "audience": message.audience,
        "initial": message.sender_id is None
        and message.submission_key in {"initial", "initial_requester"},
        "sender": info["names"].get(str(message.sender_id), info["source_name"]),
        "mine": message.sender_id == mailbox_id,
        "system": message.sender_id is None,
        "created_at": message.created_at.isoformat(),
    }


def active_memberships(mailbox):
    return PortalParticipant.objects.filter(
        mailbox=mailbox,
        revoked_at=None,
        thread__revoked_at=None,
        thread__owner__is_active=True,
        thread__owner__status="active",
    ).select_related("thread", "thread__owner", "thread__organization")


def access(request):
    ident = request.session.get("portal_session")
    session = (
        PortalSession.objects.select_related("mailbox").filter(pk=ident, revoked_at=None).first()
        if ident
        else None
    )
    now = timezone.now()
    if (
        not session
        or session.expires_at <= now
        or session.created_at + timedelta(hours=8) <= now
        or session.mailbox.disabled_at
    ):
        raise Problem("Verify your email to open your inbox.", "portal_session_expired", 401)
    return session


@endpoint(["GET"])
def session_status(request):
    try:
        session = access(request)
    except Problem:
        return Response({"csrf": get_token(request), "verified": False})
    return Response(
        {
            "csrf": get_token(request),
            "verified": True,
            "expires_at": session.expires_at.isoformat(),
            "email": decrypt(
                session.mailbox.email_ciphertext,
                session.mailbox.organization_id,
                "portal-email",
                session.mailbox_id,
            ),
        }
    )


@endpoint(["POST"])
def request_code(request):
    invitation = request.data.get("invitation")
    participant = None
    if invitation is not None:
        rate_limit(request, "portal-invitation", maximum=30, seconds=300)
        try:
            if not isinstance(invitation, str) or len(invitation) > 1024:
                raise ValueError
            identity = signing.loads(invitation, salt="portal-invitation-v1")
            mailbox = PortalMailbox.objects.get(pk=identity["mailbox"], disabled_at=None)
            participant = active_memberships(mailbox).get(thread_id=identity["thread"])
        except (
            signing.BadSignature,
            ValueError,
            KeyError,
            TypeError,
            PortalMailbox.DoesNotExist,
            PortalParticipant.DoesNotExist,
        ):
            raise Problem(
                "This invitation is unavailable.", "invitation_unavailable", 400
            ) from None
        address = decrypt(
            mailbox.email_ciphertext, mailbox.organization_id, "portal-email", mailbox.pk
        )
        source = participant.thread.source
    else:
        address = email(request.data.get("email"))
        source = field(request.data, "source", 64)
    rate_limit(request, "portal-code-hour", address, maximum=10, seconds=3600)
    rate_limit(request, "portal-code-day", address, maximum=30, seconds=86400)
    # Public tenant selection is an opaque integration ID, never caller-provided org authority.
    owner = owner_for(source)
    if participant and participant.thread.organization_id != owner.organization_id:
        raise Problem("This invitation is unavailable.", "invitation_unavailable", 400)
    bound = request.session.get("portal_invitation")
    if not participant and bound:
        raise Problem("Use the original invitation to request a code.", "invitation_required", 400)
    # Beginning a new verification must never leave an older mailbox authenticated.
    prior_session = request.session.pop("portal_session", None)
    if prior_session:
        PortalSession.objects.filter(pk=prior_session).update(revoked_at=timezone.now())
    if participant:
        request.session["portal_invitation"] = {
            "mailbox": str(participant.mailbox_id),
            "thread": str(participant.thread_id),
        }
    extra = {"email": address, "thread_id": str(participant.thread_id)} if participant else {}
    challenge_id = uuid.uuid4()
    with transaction.atomic():
        lock_organization(owner.organization)
        mailbox = PortalMailbox.objects.filter(
            organization=owner.organization,
            email_hash=keyed(address, purpose="portal-email"),
            disabled_at=None,
        ).first()
        if mailbox and active_memberships(mailbox).filter(thread__source=source).exists():
            current = PortalChallenge.objects.filter(
                pk=request.session.get("portal_challenge"),
                mailbox=mailbox,
                consumed_at=None,
                expires_at__gt=timezone.now(),
                attempts__lt=5,
            ).first()
            if current and (
                request.data.get("automatic") is True
                or (timezone.now() - current.created_at).total_seconds() < 60
            ):
                remaining = max(0, 60 - int((timezone.now() - current.created_at).total_seconds()))
                return Response(
                    {
                        "challenge_id": str(current.pk),
                        "sent": True,
                        "resend_after": remaining,
                        **extra,
                    }
                )
            latest = PortalChallenge.objects.filter(mailbox=mailbox).order_by("-created_at").first()
            if not latest or (timezone.now() - latest.created_at).total_seconds() >= 60:
                PortalChallenge.objects.filter(mailbox=mailbox, consumed_at=None).update(
                    consumed_at=timezone.now()
                )
                code = f"{secrets.randbelow(1000000):06d}"
                challenge = PortalChallenge.objects.create(
                    id=challenge_id,
                    mailbox=mailbox,
                    verifier=keyed(f"portal:{challenge_id}:{code}", purpose="otp"),
                    expires_at=timezone.now() + timedelta(minutes=10),
                )
                queue_mail(
                    owner.organization,
                    {
                        "to": address,
                        "subject": "Your Secure Mail verification code",
                        "body": f"Your one-time code is {code}. It expires in 10 minutes. Please do not reply to this automated email.",
                        "portal_challenge_id": str(challenge.pk),
                        "portal_source": source,
                    },
                    actor=owner,
                )
                audit(
                    owner.organization,
                    mailbox.pk,
                    "portal.code_requested",
                    "portal_mailbox",
                    mailbox.pk,
                )
    # Bind even decoy challenges to the requesting browser; never reveal mailbox existence.
    request.session["portal_challenge"] = str(challenge_id)
    return Response({"challenge_id": str(challenge_id), "sent": True, "resend_after": 60, **extra})


@endpoint(["POST"])
def verify_code(request):
    rate_limit(request, "portal-verify", maximum=30, seconds=300)
    ident = request.session.get("portal_challenge")
    code = request.data.get("code", "")
    accepted = False
    if ident and isinstance(code, str) and re.fullmatch(r"\d{6}", code):
        with transaction.atomic():
            challenge = (
                PortalChallenge.objects.select_for_update()
                .select_related("mailbox")
                .filter(pk=ident)
                .first()
            )
            if (
                challenge
                and not challenge.consumed_at
                and challenge.expires_at > timezone.now()
                and challenge.attempts < 5
                and not challenge.mailbox.disabled_at
            ):
                bound = request.session.get("portal_invitation")
                if bound and (
                    bound["mailbox"] != str(challenge.mailbox_id)
                    or not active_memberships(challenge.mailbox)
                    .filter(thread_id=bound["thread"])
                    .exists()
                ):
                    raise Problem("This invitation is unavailable.", "invitation_unavailable", 400)
                challenge.attempts += 1
                accepted = hmac.compare_digest(
                    challenge.verifier, keyed(f"portal:{ident}:{code}", purpose="otp")
                )
                if accepted:
                    challenge.consumed_at = timezone.now()
                    session = PortalSession.objects.create(
                        mailbox=challenge.mailbox, expires_at=timezone.now() + timedelta(minutes=15)
                    )
                challenge.save(update_fields=["attempts", "consumed_at"])
    if not accepted:
        raise Problem("The code is incorrect, expired or already used.", "invalid_code")
    request.session.flush()
    request.session["portal_session"] = str(session.pk)
    audit(
        session.mailbox.organization_id,
        session.mailbox_id,
        "portal.verified",
        "portal_mailbox",
        session.mailbox_id,
    )
    return Response({"verified": True, "csrf": get_token(request)})


@endpoint(["POST"])
def activity(request):
    session = access(request)
    session.expires_at = min(
        timezone.now() + timedelta(minutes=15), session.created_at + timedelta(hours=8)
    )
    session.save(update_fields=["expires_at"])
    return Response({"active": True})


@endpoint(["POST"])
def logout(request):
    PortalSession.objects.filter(pk=request.session.get("portal_session")).update(
        revoked_at=timezone.now()
    )
    request.session.flush()
    return Response({"locked": True})


def metadata(thread):
    return decrypt(thread.metadata_ciphertext, thread.organization_id, "portal-thread", thread.pk)


@endpoint(["GET"])
def inbox(request):
    session = access(request)
    rate_limit(request, "portal-inbox", str(session.mailbox_id), maximum=60, seconds=60)
    query = request.query_params.get("q", "").strip().casefold()
    if len(query) > 100:
        raise Problem("Search is too long.")
    try:
        offset = int(request.query_params.get("offset", "0"))
    except ValueError:
        raise Problem("Invalid offset.") from None
    if offset < 0 or offset > 100000:
        raise Problem("Invalid offset.")
    # Bounded encrypted-name search; scan continuation avoids unbounded decryption.
    rows = list(
        active_memberships(session.mailbox).order_by("-thread__updated_at", "-thread_id")[
            offset : offset + 101
        ]
    )
    results = []
    for member in rows[:100]:
        thread = member.thread
        if (
            thread.source not in settings.SECURE_MAIL_INTEGRATIONS
            or not settings.SECURE_MAIL_INTEGRATIONS[thread.source].get("enabled")
        ):
            continue
        info = metadata(thread)
        names = [name for ident, name in info["names"].items() if ident != str(session.mailbox_id)]
        if query and query not in (" ".join(names) + " " + info["subject"]).casefold():
            continue
        latest = visible_messages(thread, member).order_by("-created_at", "-id").first()
        updated_at = latest.created_at if latest else thread.created_at
        results.append(
            {
                "id": str(thread.pk),
                "name": ", ".join(names),
                "subject": info["subject"],
                "source": info["source_name"],
                "updated_at": updated_at.isoformat(),
                "unread": bool(latest)
                and (member.last_read is None or updated_at > member.last_read),
            }
        )
    audit(
        session.mailbox.organization_id,
        session.mailbox_id,
        "portal.inbox_viewed",
        "portal_mailbox",
        session.mailbox_id,
    )
    return Response({"results": results, "next_offset": offset + 100 if len(rows) > 100 else None})


@endpoint(["GET", "POST"])
def thread_detail(request, ident):
    session = access(request)
    rate_limit(request, "portal-thread", str(session.mailbox_id), maximum=120, seconds=60)
    # Serialize message/read operations so marking read cannot swallow a concurrent reply.
    with transaction.atomic():
        thread = (
            PortalThread.objects.select_for_update()
            .filter(pk=ident, organization_id=session.mailbox.organization_id, revoked_at=None)
            .first()
        )
        member = (
            active_memberships(session.mailbox).filter(thread=thread).first() if thread else None
        )
        if not member:
            return unavailable()
        integration(thread.source)
        info = metadata(thread)
        if request.method == "POST":
            if info.get("delivery_mode") == "provider_only":
                raise Problem(
                    "Use the clinic approval action in MySelfPay; replies are unavailable.",
                    "read_only",
                    403,
                )
            body = field(request.data, "body", 16000)
            key = request.headers.get("Idempotency-Key", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{16,100}", key):
                raise Problem("A unique Idempotency-Key is required.")
            fingerprint = keyed(body, purpose="portal-message")
            prior = PortalMessage.objects.filter(
                thread=thread, sender=session.mailbox, submission_key=key
            ).first()
            if prior:
                if prior.fingerprint != fingerprint:
                    raise Problem("Submission key reused.", "idempotency_conflict", 409)
                return Response({"id": str(prior.pk)})
            message = PortalMessage(
                thread=thread, sender=session.mailbox, submission_key=key, fingerprint=fingerprint
            )
            message.body_ciphertext = encrypt(
                body, thread.organization_id, "portal-message", message.pk
            )
            message.save()
            thread.updated_at = message.created_at
            thread.save(update_fields=["updated_at"])
            for other in (
                thread.participants.filter(revoked_at=None, mailbox__disabled_at=None)
                .exclude(mailbox=session.mailbox)
                .select_related("mailbox", "thread__organization", "thread__owner")
            ):
                notify(other)
            audit(
                thread.organization_id,
                session.mailbox_id,
                "portal.replied",
                "portal_thread",
                thread.pk,
            )
            return Response({"id": str(message.pk)}, status=201)
        # Paginate old messages without exposing any other thread's data.
        before = request.query_params.get("before", "")
        messages = visible_messages(thread, member).order_by("-created_at", "-id")
        if before:
            try:
                anchor = messages.filter(pk=uuid.UUID(before)).first()
            except ValueError:
                anchor = None
            if not anchor:
                raise Problem("Invalid message cursor.")
            messages = messages.filter(
                Q(created_at__lt=anchor.created_at)
                | Q(created_at=anchor.created_at, id__lt=anchor.pk)
            )
        batch = list(messages[:51])
        output = [message_output(m, thread, info, session.mailbox_id) for m in reversed(batch[:50])]
        if not before:
            member.last_read = batch[0].created_at if batch else thread.updated_at
            member.save(update_fields=["last_read"])
        audit(
            thread.organization_id,
            session.mailbox_id,
            "portal.thread_viewed",
            "portal_thread",
            thread.pk,
        )
        participants = [
            {
                "name": info["names"].get(str(person.mailbox_id), "Participant"),
                "email": decrypt(
                    person.mailbox.email_ciphertext,
                    thread.organization_id,
                    "portal-email",
                    person.mailbox_id,
                ),
                "mine": person.mailbox_id == session.mailbox_id,
                "role": person.role,
            }
            for person in thread.participants.filter(
                revoked_at=None, mailbox__disabled_at=None
            ).select_related("mailbox")
        ]
        initial_key = (
            "initial_requester"
            if thread.source == "selfpay" and member.role == "requester"
            else "initial"
        )
        initial = (
            visible_messages(thread, member).filter(sender=None, submission_key=initial_key).first()
        )
        request_summary = (
            decrypt(
                initial.body_ciphertext,
                thread.organization_id,
                "portal-message",
                message_context_id(initial),
            )
            if initial
            else ""
        )
        action = info.get("provider_action")
        provider_action_result = None
        if member.role == "provider" and action and action.get("expires_at", 0) > time.time():
            action_origin = urlsplit(action["url"])
            if f"{action_origin.scheme}://{action_origin.netloc}" in integration(thread.source).get(
                "provider_action_origins", []
            ):
                provider_action_result = action
        return Response(
            {
                "id": str(thread.pk),
                "booking_status": (
                    "approved"
                    if thread.messages.filter(
                        sender=None, submission_key__startswith="confirmation:"
                    ).exists()
                    else "requested"
                )
                if thread.source == "selfpay"
                else None,
                "provider_action": provider_action_result,
                "read_only": info.get("delivery_mode") == "provider_only",
                "subject": info["subject"],
                "participants": participants,
                "request_summary": request_summary,
                "messages": output,
                "next_before": str(batch[49].pk) if len(batch) > 50 else None,
            }
        )
