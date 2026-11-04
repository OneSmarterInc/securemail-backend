import base64
import hashlib
import hmac
import secrets
import time
from datetime import timedelta
from urllib.parse import quote

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.middleware.csrf import get_token
from django.utils import timezone
from django_otp.oath import TOTP
from rest_framework import serializers
from rest_framework.response import Response

from . import crypto
from .company_identity import is_company_address
from .http import Problem, endpoint
from .models import Organization, StaffInvitation, StaffUser
from .operator_access import operator_token_valid
from .services import (
    audit,
    current_staff,
    digest,
    lock_organization,
    login_rate_limit,
    queue_mail,
    rate_limit,
    record_login_failure,
)


def user_data(user):
    personal = getattr(user, "staffsmtp", None)
    return {
        "id": user.pk,
        "name": user.display_name,
        "email": user.email,
        "role": user.role,
        "can_nophi": user.can_nophi,
        "can_manage_privileges": user.can_manage_privileges,
        "can_export_audit": user.can_export_audit,
        "sender_addresses": [personal.email]
        if personal and personal.email in user.sender_addresses
        else user.sender_addresses,
        "organization": user.organization.name,
        "mfa_confirmed": user.mfa_confirmed,
    }


def validate(serializer, data):
    value = serializer(data=data)
    value.is_valid(raise_exception=True)
    return value.validated_data


class Credentials(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(max_length=256, trim_whitespace=False)


class Token(serializers.Serializer):
    token = serializers.CharField(max_length=100)


@endpoint(["GET"])
def session(request):
    user = request.user
    verified = (
        user.is_authenticated
        and user.status == "active"
        and user.mfa_confirmed
        and request.session.get("staff_version") == user.session_version
        and request.session.get("mfa_at")
    )
    return Response(
        {
            "csrf": get_token(request),
            "user": user_data(user) if verified else None,
            "synthetic_mode": settings.SYNTHETIC_MODE,
            "dev_tools": settings.ENABLE_DEV_TOOLS,
            "setup_required": settings.SYNTHETIC_MODE and not StaffUser.objects.exists(),
            **(session_deadlines(request) if verified else {}),
        }
    )


@endpoint(["GET"])
def recipient_session(request):
    return Response(
        {
            "csrf": get_token(request),
            "user": None,
            "setup_required": False,
            "synthetic_mode": False,
            "dev_tools": False,
        }
    )


@endpoint(["POST"])
def setup(request):
    rate_limit(request, "bootstrap", maximum=5)
    if not settings.SYNTHETIC_MODE or not operator_token_valid(
        request.data.get("setup_token", ""), settings.SETUP_TOKEN_SHA256
    ):
        raise Problem("Setup is unavailable.", status=404)
    data = validate(Credentials, request.data)
    email = data["email"].lower()
    if not is_company_address(email):
        raise Problem("Use your company email address.")
    validate_password(data["password"])
    with transaction.atomic():
        org, _ = Organization.objects.get_or_create(
            domain=settings.COMPANY_DOMAIN, defaults={"name": "OneSmarter"}
        )
        Organization.objects.select_for_update(no_key=True).get(pk=org.pk)
        if StaffUser.objects.exists():
            raise Problem("Initial setup is already complete.", status=409)
        user = StaffUser.objects.create_user(
            username=email,
            email=email,
            password=data["password"],
            organization=org,
            display_name="Workspace administrator",
            role="admin",
            status="active",
            can_manage_privileges=True,
            can_export_audit=True,
            sender_addresses=[email],
        )
        audit(org, user, "account.bootstrap", "account", user.pk)
    begin_auth(request, user)
    return Response({"enrollment_required": True})


def begin_auth(request, user):
    request.session.flush()
    request.session["pending_user"] = user.pk
    request.session["pending_version"] = user.session_version
    request.session["pending_until"] = time.time() + 300


def pending_user(request):
    if request.session.get("pending_until", 0) < time.time():
        raise Problem("Sign in again to continue.", "authentication_required", 401)
    user = StaffUser.objects.filter(
        pk=request.session.get("pending_user"), status="active", is_active=True
    ).first()
    if user is None or request.session.get("pending_version") != user.session_version:
        raise Problem("Sign in again to continue.", "authentication_required", 401)
    return user


@endpoint(["POST"])
def sign_in(request):
    data = validate(Credentials, request.data)
    email = data["email"].lower()
    login_rate_limit(request, email)
    user = authenticate(request._request, username=email, password=data["password"])
    if user is None or user.status != "active" or not is_company_address(user.email):
        known = StaffUser.objects.filter(email=email).first()
        wait = record_login_failure(known) if known else 0
        if known:
            audit(
                known.organization,
                None,
                "auth.login_failed",
                "account",
                known.pk,
                outcome="failure",
            )
        problem = Problem(
            "Email or password is incorrect, or the account is unavailable.",
            "invalid_credentials",
            401,
        )
        if wait:
            problem.wait = wait
        raise problem
    begin_auth(request, user)
    return Response({"enrollment_required": not user.mfa_confirmed})


@endpoint(["POST"])
def enrollment(request):
    user = pending_user(request)
    if user.mfa_confirmed:
        raise Problem("MFA is already enrolled.")
    with transaction.atomic():
        lock_organization(user.organization_id)
        user = StaffUser.objects.select_for_update().get(pk=user.pk)
        pending_user(request)
        if not user.mfa_secret:
            user.mfa_secret = crypto.encrypt(
                secrets.token_bytes(20), crypto.context(user.organization_id, "mfa", user.pk)
            )
            user.save(update_fields=["mfa_secret"])
        secret = base64.b32encode(
            crypto.decrypt(user.mfa_secret, crypto.context(user.organization_id, "mfa", user.pk))
        ).decode()
    return Response(
        {
            "secret": secret,
            "uri": f"otpauth://totp/{quote('OneSmarter:' + user.email)}?secret={secret}&issuer=OneSmarter&digits=6&period=30",
        }
    )


def verify_factor(user, token: str, *, allow_recovery: bool = True) -> bool:
    if allow_recovery and user.mfa_confirmed and len(token) in {12, 32}:
        for stored in user.recovery_hashes:
            if stored.startswith("legacy-argon2$"):
                accepted = any(
                    check_password(
                        hmac.new(
                            key.encode(),
                            f"recovery:{user.pk}:{token.upper()}".encode(),
                            hashlib.sha256,
                        ).hexdigest(),
                        stored.removeprefix("legacy-argon2$"),
                    )
                    for key in [settings.SECRET_KEY, *settings.RECOVERY_LEGACY_KEYS]
                )
            else:
                accepted = check_password(token.upper(), stored)
            if accepted:
                user.recovery_hashes = [item for item in user.recovery_hashes if item != stored]
                user.save(update_fields=["recovery_hashes"])
                return True
    if not token.isdigit() or len(token) != 6 or not user.mfa_secret:
        return False
    secret = crypto.decrypt(user.mfa_secret, crypto.context(user.organization_id, "mfa", user.pk))
    totp = TOTP(secret)
    if not totp.verify(int(token), tolerance=1, min_t=user.mfa_last_tick + 1):
        return False
    user.mfa_last_tick = totp.t()
    user.save(update_fields=["mfa_last_tick"])
    return True


@endpoint(["POST"])
def verify_mfa(request):
    user = pending_user(request)
    token = validate(Token, request.data)["token"]
    rate_limit(request, "mfa", str(user.pk), maximum=5)
    codes = []
    with transaction.atomic():
        lock_organization(user.organization_id)
        user = StaffUser.objects.select_for_update().get(pk=user.pk)
        pending_user(request)
        accepted = verify_factor(user, token)
        if accepted:
            if not user.mfa_confirmed:
                codes = [secrets.token_hex(16).upper() for _ in range(8)]
                user.recovery_hashes = [make_password(code, hasher="argon2") for code in codes]
                user.mfa_confirmed = True
                user.save(update_fields=["recovery_hashes", "mfa_confirmed"])
                audit(user.organization, user, "auth.mfa_enrolled", "account", user.pk)
            audit(user.organization, user, "auth.login", "account", user.pk)
        else:
            audit(user.organization, user, "auth.mfa_failed", "account", user.pk, outcome="failure")
    if not accepted:
        raise Problem("The code is incorrect, expired, or already used.", "invalid_code", 400)
    request.session.flush()
    login(request._request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session["staff_version"] = user.session_version
    request.session["mfa_at"] = time.time()
    request.session["staff_started_at"] = time.time()
    request.session["staff_last_seen"] = time.time()
    request.session.set_expiry(settings.STAFF_ABSOLUTE_SECONDS)
    return Response(
        {"user": user_data(user), "csrf": get_token(request._request), "recovery_codes": codes}
    )


@endpoint(["POST"], staff=True)
def step_up(request):
    token = validate(Token, request.data)["token"]
    rate_limit(request, "stepup", str(request.user.pk), maximum=5)
    with transaction.atomic():
        lock_organization(request.user.organization_id)
        user = current_staff(request)
        accepted = verify_factor(user, token)
        audit(
            user.organization,
            user,
            "auth.step_up",
            "account",
            user.pk,
            outcome="success" if accepted else "failure",
        )
    if not accepted:
        raise Problem("Enter a fresh authenticator code.", "invalid_code")
    request.session["mfa_at"] = time.time()
    return Response({"verified": True})


def recent_mfa(request):
    if time.time() - request.session.get("mfa_at", 0) > 600:
        raise Problem("Confirm a fresh MFA code before this change.", "step_up_required", 403)


@endpoint(["POST"])
def sign_out(request):
    if request.user.is_authenticated:
        audit(request.user.organization, request.user, "auth.logout", "account", request.user.pk)
    logout(request._request)
    return Response({"signed_out": True})


class Activation(serializers.Serializer):
    token = serializers.CharField(max_length=200)
    password = serializers.CharField(max_length=256, trim_whitespace=False)


@endpoint(["POST"])
def activate(request):
    data = validate(Activation, request.data)
    rate_limit(request, "activation", digest(data["token"]), maximum=5)
    candidate = (
        StaffInvitation.objects.select_related("user")
        .filter(token_hash=digest(data["token"]))
        .first()
    )
    if candidate is None:
        raise Problem("This activation or recovery link is unavailable.")
    with transaction.atomic():
        lock_organization(candidate.user.organization_id)
        invitation = (
            StaffInvitation.objects.select_for_update(of=("self",))
            .select_related("user__organization")
            .filter(
                token_hash=digest(data["token"]), consumed_at=None, expires_at__gt=timezone.now()
            )
            .first()
        )
        if invitation is None or invitation.user.status not in {"invited", "active"}:
            raise Problem("This activation or recovery link is unavailable.")
        user = StaffUser.objects.select_for_update().get(pk=invitation.user_id)
        validate_password(data["password"], user)
        user.set_password(data["password"])
        user.status = "active"
        user.session_version += 1
        user.save()
        StaffInvitation.objects.filter(user=user, consumed_at=None).update(
            consumed_at=timezone.now()
        )
        audit(
            user.organization,
            user,
            "account.activated"
            if invitation.purpose == "activate"
            else "account.password_recovered",
            "account",
            user.pk,
        )
    begin_auth(request, user)
    return Response({"enrollment_required": not user.mfa_confirmed})


def invite(user, actor, purpose="activate"):
    StaffInvitation.objects.filter(user=user, consumed_at=None).update(consumed_at=timezone.now())
    token = secrets.token_urlsafe(32)
    invitation = StaffInvitation.objects.create(
        user=user,
        token_hash=digest(token),
        purpose=purpose,
        expires_at=timezone.now() + timedelta(hours=24),
    )
    queue_mail(
        user.organization,
        {
            "to": user.email,
            "subject": "Your OneSmarter account",
            "body": "Complete your account setup or password recovery. MFA is required.",
            "link": f"{settings.PUBLIC_URL}/#/activate/{token}",
            "invitation_id": str(invitation.pk),
        },
        actor=actor,
    )
    audit(
        user.organization,
        actor,
        "account.invitation_created",
        "account",
        user.pk,
        metadata={"purpose": purpose},
    )


def session_deadlines(request):
    return {
        "idle_expires_at": request.session.get("staff_last_seen", 0) + settings.STAFF_IDLE_SECONDS,
        "absolute_expires_at": request.session.get("staff_started_at", 0)
        + settings.STAFF_ABSOLUTE_SECONDS,
    }


@endpoint(["POST"], staff=True)
def activity(request):
    request.session["staff_last_seen"] = time.time()
    return Response(session_deadlines(request))
