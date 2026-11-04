"""Organisation SMTP transport and write-only, encrypted personal credentials."""

import re
import smtplib
import socket
import ssl

from django.conf import settings
from django.core.mail.backends.smtp import EmailBackend
from django.db import transaction
from rest_framework import serializers
from rest_framework.response import Response

from . import crypto
from .auth import recent_mfa, validate
from .company_identity import is_company_address
from .http import Problem, endpoint
from .models import OrganizationSMTP, StaffSMTP
from .public_network import public_address
from .senders import SenderUnavailable
from .services import audit, current_staff, lock_organization, rate_limit


def secret_context(user):
    return crypto.context(user.organization_id, "smtp-credential", user.pk)


def public_socket(host, port, timeout, source_address=None):
    family = socket.AF_INET if getattr(settings, "SMTP_IPV4_ONLY", False) else socket.AF_UNSPEC
    addresses = socket.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
    if not addresses or any(not public_address(row[4][0]) for row in addresses):
        raise OSError("SMTP host must resolve only to public addresses")
    last = None
    for family, kind, proto, _, address in addresses:
        stream = socket.socket(family, kind, proto)
        try:
            stream.settimeout(timeout)
            if source_address:
                stream.bind(source_address)
            stream.connect(address)  # Connect to the validated address; no second DNS lookup.
            return stream
        except OSError as exc:
            last = exc
            stream.close()
    raise OSError("SMTP connection unavailable") from last


class PublicSMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return public_socket(host, port, timeout, self.source_address)


class PublicSMTPSSL(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        stream = public_socket(host, port, timeout, self.source_address)
        try:
            return self.context.wrap_socket(stream, server_hostname=self._host)
        except Exception:
            stream.close()
            raise


class SMTPBackend(EmailBackend):
    def close(self):
        try:
            return super().close()
        finally:
            # Drop the application reference after use; Python cannot guarantee memory erasure.
            self.password = None

    @property
    def connection_class(self):
        return PublicSMTPSSL if self.use_ssl else PublicSMTP


def credential(user):
    value = StaffSMTP.objects.filter(user=user, organization_id=user.organization_id).first()
    if (
        user.status != "active"
        or not value
        or value.email not in user.sender_addresses
        or not is_company_address(value.email, user.organization.domain)
    ):
        raise SenderUnavailable("Configure your own approved SMTP sender in Connections")
    return value


def connection(user):
    value = credential(user)
    config = OrganizationSMTP.objects.filter(
        organization_id=user.organization_id, enabled=True
    ).first()
    if not config:
        raise SenderUnavailable("Organisation SMTP is not configured")
    if value.transport_revision != config.revision:
        raise SenderUnavailable("Confirm your credentials for the changed organisation server")
    password = crypto.decrypt(value.password_ciphertext, secret_context(user)).decode()
    return value.email, SMTPBackend(
        host=config.host,
        port=config.port,
        username=value.email,
        password=password,
        use_tls=config.security == "starttls",
        use_ssl=config.security == "tls",
        timeout=20,
        fail_silently=False,
    )


OTP_SENDER = "support@onesmarter.com"


def notification_connection():
    """System mail uses deployment SMTP credentials, never a staff mailbox."""
    if not notification_configured():
        raise SenderUnavailable("Environment notification SMTP is not configured")
    return OTP_SENDER, SMTPBackend(
        host=settings.EMAIL_HOST,
        port=settings.EMAIL_PORT,
        username=settings.EMAIL_HOST_USER,
        password=settings.EMAIL_HOST_PASSWORD,
        use_tls=settings.EMAIL_USE_TLS,
        use_ssl=settings.EMAIL_USE_SSL,
        timeout=settings.EMAIL_TIMEOUT,
        fail_silently=False,
    )


def notification_configured():
    return bool(
        settings.EMAIL_HOST
        and settings.EMAIL_HOST_USER
        and settings.EMAIL_HOST_PASSWORD
        and (settings.EMAIL_USE_TLS != settings.EMAIL_USE_SSL)
        and (
            (settings.EMAIL_USE_TLS and settings.EMAIL_PORT == 587)
            or (settings.EMAIL_USE_SSL and settings.EMAIL_PORT == 465)
        )
    )


def otp_connection(user):
    # Compatibility for callers; credentials no longer depend on the owner.
    return notification_connection()


def configured(user):
    try:
        value = credential(user)
    except SenderUnavailable:
        return False
    return OrganizationSMTP.objects.filter(
        organization_id=user.organization_id, enabled=True, revision=value.transport_revision
    ).exists()


class Transport(serializers.Serializer):
    host = serializers.CharField(max_length=253)
    sender_name = serializers.CharField(max_length=160, default="OneSmarter Support")
    port = serializers.ChoiceField(choices=[465, 587])
    security = serializers.ChoiceField(choices=["tls", "starttls"])
    enabled = serializers.BooleanField(default=True)

    def validate(self, data):
        if any(c in data["sender_name"] for c in "\r\n"):
            raise serializers.ValidationError("Sender name cannot contain line breaks.")
        host = data["host"].strip().lower().rstrip(".")
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host
        ):
            raise serializers.ValidationError(
                "Enter a public SMTP hostname, without a URL or port."
            )
        if (data["security"], data["port"]) not in {("tls", 465), ("starttls", 587)}:
            raise serializers.ValidationError("Use TLS on 465 or STARTTLS on 587.")
        data["host"] = host
        return data


class Credentials(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(
        max_length=4096, trim_whitespace=False, required=False, allow_blank=True
    )


def state(user):
    transport = OrganizationSMTP.objects.filter(organization_id=user.organization_id).first()
    personal = StaffSMTP.objects.filter(user=user, organization_id=user.organization_id).first()
    return {
        "can_manage": user.role == "admin",
        "organization": None
        if not transport
        else {
            "host": transport.host,
            "sender_name": transport.sender_name,
            "port": transport.port,
            "security": transport.security,
            "enabled": transport.enabled,
            "otp_sender": OTP_SENDER,
            "otp_configured": notification_configured(),
        },
        "personal": {
            "email": personal.email if personal else "",
            "password_set": bool(personal and personal.password_ciphertext),
            "needs_password": not personal
            or not transport
            or personal.transport_revision != transport.revision,
        },
        "approved_senders": user.sender_addresses,
    }


@endpoint(["GET"], staff=True)
def smtp_settings(request):
    return Response(state(request.user))


@endpoint(["POST"], admin=True)
def organization_settings(request):
    recent_mfa(request)
    data = validate(Transport, request.data)
    with transaction.atomic():
        lock_organization(request.user.organization_id)
        user = current_staff(request)
        if user.role != "admin":
            raise Problem("Administrator access required.", status=403)
        existing = OrganizationSMTP.objects.filter(organization=user.organization).first()
        revision = existing.revision if existing else 1
        if existing and any(
            getattr(existing, name) != data[name] for name in ("host", "port", "security")
        ):
            revision += 1
        OrganizationSMTP.objects.update_or_create(
            organization=user.organization, defaults={**data, "revision": revision}
        )
        audit(
            user.organization,
            user,
            "smtp.organization_updated",
            "organization",
            user.organization_id,
        )
    return Response(state(user))


@endpoint(["POST", "DELETE"], staff=True)
def personal_settings(request):
    recent_mfa(request)
    with transaction.atomic():
        lock_organization(request.user.organization_id)
        user = current_staff(request)
        if request.method == "DELETE":
            StaffSMTP.objects.filter(user=user).delete()
        else:
            data = validate(Credentials, request.data)
            email = data["email"].lower()
            if email not in user.sender_addresses or not is_company_address(
                email, user.organization.domain
            ):
                raise Problem("Choose your own administrator-approved sender address.", status=403)
            if (
                StaffSMTP.objects.filter(organization=user.organization, email=email)
                .exclude(user=user)
                .exists()
            ):
                raise Problem(
                    "This sender is already assigned to another staff account.", status=409
                )
            existing = StaffSMTP.objects.filter(user=user).first()
            transport = OrganizationSMTP.objects.filter(organization=user.organization).first()
            if not transport:
                raise Problem("Your administrator must configure the organisation server first.")
            password = data.get("password", "")
            if not password and (
                not existing
                or existing.email != email
                or existing.transport_revision != transport.revision
            ):
                raise Problem("Enter the password for this sender address.")
            values = {"organization": user.organization, "email": email}
            if password:
                values["password_ciphertext"] = crypto.encrypt(
                    password.encode(), secret_context(user)
                )
                values["transport_revision"] = transport.revision
            StaffSMTP.objects.update_or_create(user=user, defaults=values)
        audit(user.organization, user, "smtp.personal_updated", "account", user.pk)
    return Response(state(user))


@endpoint(["POST"], staff=True)
def check_smtp(request):
    recent_mfa(request)
    rate_limit(request, "smtp_check", str(request.user.pk), maximum=3, seconds=60)
    transport = None
    try:
        _, transport = connection(request.user)
        transport.open()
    except SenderUnavailable:
        raise Problem(
            "Save your approved sender credentials for the current organisation SMTP server first.",
            "smtp_not_configured",
            400,
        ) from None
    except smtplib.SMTPAuthenticationError:
        raise Problem(
            "The mail server rejected your SMTP login. Check the username and provider-issued "
            "app password, and ask your mail administrator whether SMTP login is permitted.",
            "smtp_authentication_failed",
            400,
        ) from None
    except ssl.SSLError:
        raise Problem(
            "SMTP TLS verification failed. Check the hostname and TLS settings with your administrator.",
            "smtp_tls_failed",
            400,
        ) from None
    except smtplib.SMTPServerDisconnected:
        raise Problem(
            "The mail server closed the connection before the login check completed. "
            "Check your provider's SMTP access policy and app-password requirements, then retry.",
            "smtp_disconnected",
            400,
        ) from None
    except (OSError, smtplib.SMTPException):
        raise Problem(
            "SMTP connection failed. Check the server, port and network access.",
            "smtp_check_failed",
            400,
        )
    finally:
        if transport:
            try:
                transport.close()
            except (OSError, smtplib.SMTPException):
                pass
    audit(
        request.user.organization,
        request.user,
        "smtp.authentication_checked",
        "account",
        request.user.pk,
    )
    return Response({"message": "SMTP authentication succeeded. No email was sent."})
