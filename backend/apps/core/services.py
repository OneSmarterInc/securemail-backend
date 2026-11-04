import hashlib
import hmac
import json
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac

from . import crypto
from .client_ip import client_ip
from .http import Problem
from .models import (
    AuditEvent,
    AuditSequence,
    DeliveryJob,
    IdempotencyRecord,
    Organization,
    RateBucket,
)


def lock_organization(org):
    """Acquire first in multi-resource transactions for consistent lock ordering."""
    # Protect business mutations without blocking foreign-key inserts (audit/outbox).
    return Organization.objects.select_for_update(no_key=True).get(pk=getattr(org, "pk", org))


def current_staff(request):
    from .models import StaffUser

    user = StaffUser.objects.select_for_update().get(pk=request.user.pk)
    if (
        user.status != "active"
        or not user.is_active
        or user.session_version != request.session.get("staff_version")
    ):
        raise Problem("Your session ended. Please sign in again.", "session_expired", 401)
    return user


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def keyed(value: str, *, purpose: str = "idempotency") -> str:
    return salted_hmac(
        f"onesmarter:{purpose}:v2", value, secret=settings.SECRET_KEY, algorithm="sha256"
    ).hexdigest()


def verifier_matches(value: str, stored: str, *, purpose: str) -> bool:
    """Read compatibility for pre-domain-separation OTP/idempotency records only."""
    if purpose not in {"otp", "idempotency"}:
        raise ValueError("Unsupported legacy verifier purpose")
    for secret in [settings.SECRET_KEY, *settings.SECRET_KEY_FALLBACKS]:
        current = salted_hmac(
            f"onesmarter:{purpose}:v2", value, secret=secret, algorithm="sha256"
        ).hexdigest()
        legacy = hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()
        if secrets.compare_digest(stored, current) or secrets.compare_digest(stored, legacy):
            return True
    return False


@transaction.atomic
def audit(
    org, actor, action: str, target_type: str, target_id, *, outcome="success", metadata=None
):
    org_id = getattr(org, "pk", org)
    sequence, _ = AuditSequence.objects.select_for_update().get_or_create(organization_id=org_id)
    sequence.value += 1
    sequence.save(update_fields=["value"])
    return AuditEvent.objects.create(
        organization_id=org_id,
        sequence=sequence.value,
        actor_id=str(getattr(actor, "pk", actor or "system")),
        actor_label=getattr(actor, "display_name", "Recipient" if actor else "System"),
        actor_role=getattr(actor, "role", "recipient" if actor else "system"),
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        outcome=outcome,
        metadata=metadata or {},
    )


def rate_limit(
    request, scope: str, identity: str = "", *, maximum=10, seconds=300, identity_budget=True
):
    """Atomic token buckets, using integer credits to avoid floating-point drift."""
    if maximum <= 0 or seconds <= 0:
        raise ValueError("Rate bucket capacity and refill period must be positive")
    ip = client_ip(request)
    identity = identity.strip().lower()
    # Separate people behind one NAT do not consume each other's account allowance.
    # The identity bucket also prevents bypass by rotating source IPs.
    # Aggregate budgets run first, before allocating attacker-chosen identity rows.
    buckets = [(f"ip:{ip}", maximum * 5 if identity else maximum)]
    if identity and identity_budget:
        buckets.extend(
            [(f"identity:{identity}", maximum), (f"identity-ip:{identity}:{ip}", maximum)]
        )
    period = seconds * 1_000_000
    now = timezone.now()
    rejected = False
    retry_after = 0
    with transaction.atomic():
        for value, allowance in buckets:
            capacity = allowance * period
            key = keyed(f"token-rate:v1:{scope}:{value}", purpose="rate-limit")
            bucket, _ = RateBucket.objects.select_for_update().get_or_create(
                key=key, defaults={"credits": capacity, "refilled_at": now}
            )
            previous = bucket.refilled_at or now
            delta = max(now - previous, timedelta(0))
            elapsed = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
            bucket.credits = min(capacity, bucket.credits + elapsed * allowance)
            # A backwards wall-clock adjustment must not mint tokens twice.
            bucket.refilled_at = max(previous, now)
            if bucket.credits < period:
                rejected = True
                # Integer ceiling; include a backwards-clock pause before refill.
                deficit = period - bucket.credits
                wait_us = (deficit + allowance - 1) // allowance
                rollback = max(previous - now, timedelta(0))
                wait_us += (
                    rollback.days * 86400 + rollback.seconds
                ) * 1_000_000 + rollback.microseconds
                retry_after = max(1, (wait_us + 999_999) // 1_000_000)
            else:
                bucket.credits -= period
            bucket.save(update_fields=["credits", "refilled_at"])
            if rejected:
                break
    if rejected:
        problem = Problem("Too many attempts. Please try again later.", "rate_limited", 429)
        problem.wait = retry_after  # DRF emits Retry-After without sleeping a worker.
        raise problem


def queue_mail(org, payload: dict, *, actor=None, conversation=None, grant=None):
    job = DeliveryJob(organization=org, actor=actor, conversation=conversation, grant=grant)
    job.payload_ciphertext = crypto.encrypt(
        json.dumps(payload).encode(), crypto.context(org.pk, "delivery", job.pk)
    )
    job.save()
    if settings.OUTBOX_IMMEDIATE_DISPATCH:
        from .tasks import wake_delivery

        urgent = bool(payload.get("challenge_id") or payload.get("portal_challenge_id"))
        transaction.on_commit(lambda: wake_delivery(job.pk, urgent=urgent), robust=True)
    return job


def idempotency(request, org, actor: str, operation: str, payload: dict):
    key = request.headers.get("Idempotency-Key", "")
    if not key or len(key) > 100:
        raise Problem(
            "An Idempotency-Key of at most 100 characters is required.", "idempotency_required"
        )
    Organization.objects.select_for_update(no_key=True).get(pk=org.pk)
    fingerprint = keyed(json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")))
    existing = IdempotencyRecord.objects.filter(
        organization=org, actor=actor, operation=operation, key=key
    ).first()
    if existing and not verifier_matches(
        json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")),
        existing.fingerprint,
        purpose="idempotency",
    ):
        raise Problem(
            "This submission key was already used with different data.", "idempotency_conflict", 409
        )
    return existing, {
        "organization": org,
        "actor": actor,
        "operation": operation,
        "key": key,
        "fingerprint": fingerprint,
    }


def paginate(query, request, *, ordering: dict, default: str):
    order = request.query_params.get("sort", default)
    direction = "-" if order.startswith("-") else ""
    field = ordering.get(order.lstrip("-"))
    if field is None:
        raise Problem("Unsupported sort field.", "invalid_sort")
    try:
        size = int(request.query_params.get("page_size", 25))
        page = int(request.query_params.get("page", 1))
    except ValueError as exc:
        raise Problem("Invalid pagination.") from exc
    if size not in {25, 50, 100} or page < 1 or page > 10000:
        raise Problem("Invalid pagination.")
    from django.db.models import F

    order_expression = (
        F(field).desc(nulls_last=True) if direction else F(field).asc(nulls_last=True)
    )
    query = query.order_by(order_expression, "pk")
    total = query.count()
    return list(query[(page - 1) * size : page * size]), {
        "count": total,
        "page": page,
        "page_size": size,
    }


def login_rate_limit(request, email: str):
    """Strict source cap; ten attempts per account/source network per minute."""
    import ipaddress

    address = ipaddress.ip_address(client_ip(request))
    prefix = ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 64}", strict=False)
    rate_limit(request, "login-source", maximum=50, seconds=60)
    rate_limit(request, "login-account-network", f"{email}:{prefix}", maximum=10, seconds=60)


def record_login_failure(user):
    """Aggregate failure telemetry never blocks a correct password from a fresh source.

    Backoff is communicated without sleeping workers. Source buckets enforce the
    hard limit; distributed hashing abuse additionally needs edge controls.
    """
    from .models import LoginFailureState

    now = timezone.now()
    with transaction.atomic():
        state, _ = LoginFailureState.objects.select_for_update().get_or_create(user=user)
        if (now - state.window_started).total_seconds() >= 600:
            state.failures = 0
            state.window_started = now
        state.failures += 1
        state.save()
        count = state.failures
    if count >= 100 and count % 100 == 0:
        import logging

        logging.getLogger("securemail.auth").warning(
            "sustained_login_failures account_id=%s count=%s", user.pk, count
        )
        audit(
            user.organization,
            None,
            "auth.sustained_failures",
            "account",
            user.pk,
            outcome="failure",
            metadata={"failures": count, "window_seconds": 600},
        )
    return min(300, 2 ** min(9, (count - 100) // 10)) if count >= 100 else 0
