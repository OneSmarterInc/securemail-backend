from django.conf import settings
from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from rest_framework.response import Response

from . import document_service, smtp_settings
from .auth import recent_mfa
from .http import Problem, endpoint, unavailable
from .mail import payload
from .models import Conversation, DeliveryJob, IdempotencyRecord
from .operator_access import operator_token_valid
from .services import audit, current_staff, idempotency, lock_organization


@endpoint(["GET"])
def health(request):
    return Response({"status": "ok"})


@endpoint(["GET"])
def document_service_status(request):
    ready = document_service.ready()
    response = Response(
        {
            "ready": ready,
            "message": "" if ready else "Service is disabled.",
            "max_upload_bytes": settings.MAX_UPLOAD_BYTES,
            "max_files": settings.MAX_FILES,
        }
    )
    response["Cache-Control"] = "no-store"
    return response


@endpoint(["GET"], staff=True)
def dashboard(request):
    query = Conversation.objects.filter(owner=request.user, organization=request.user.organization)
    return Response(
        {
            "conversations": query.count(),
            "awaiting": query.filter(state="awaiting_recipient", revoked_at=None).count(),
            "replied": query.filter(state="replied").count(),
            "active": query.filter(
                revoked_at=None, expires_at__gt=timezone.now(), protected=True
            ).count(),
            "delivery_attention": DeliveryJob.objects.filter(
                organization=request.user.organization,
                actor=request.user,
                state__in=["failed", "uncertain"],
            ).count(),
        }
    )


@endpoint(["GET"], staff=True)
def connection_settings(request):
    jobs = DeliveryJob.objects.filter(organization=request.user.organization, actor=request.user)
    counts = dict(jobs.values_list("state").annotate(total=Count("pk")))
    return Response(
        {
            "checked_at": timezone.now().isoformat(),
            "delivery_counts": counts,
            "can_manage_accounts": request.user.role == "admin",
            "can_manage_senders": request.user.role == "admin"
            and request.user.can_manage_privileges,
            "key_protector": settings.KEY_PROTECTOR,
            "max_upload_bytes": settings.MAX_UPLOAD_BYTES,
            "environment": settings.ENVIRONMENT,
            "synthetic_mode": settings.SYNTHETIC_MODE,
            "mail": settings.MAIL_PROVIDER,
            "storage": settings.STORAGE_PROVIDER,
            "smtp_configured": smtp_settings.configured(request.user),
            "archive_configured": False,
            "audit_storage": "database",
            "crypto": settings.CRYPTO_PROVIDER,
            "document_encryption": "AES-256-GCM"
            if settings.CRYPTO_PROVIDER == "onesmarter-hybrid-v2"
            else None,
            "key_service_ready": document_service.ready(),
            "storage_configured": (
                settings.STORAGE_PROVIDER == "local"
                and settings.RUNTIME_DIR.is_dir()
                or settings.STORAGE_PROVIDER == "s3"
                and bool(settings.S3_BUCKET and settings.AWS_REGION)
            ),
            "production_ready": False,
            "gates": [
                "Independent review of OneSmarter key management",
                "Validated post-quantum architecture",
                "Approved retention and AWS region",
                "AWS Object Lock and key recovery evidence",
                "PostgreSQL concurrency and complete delivery verification",
            ],
            "sender_addresses": request.user.sender_addresses,
        }
    )


@endpoint(["POST"], staff=True)
def retry_delivery(request, ident):
    recent_mfa(request)
    if request.data.get("acknowledge_duplicate_risk") is not True:
        raise Problem("Confirm that retrying may send a duplicate notification.")
    with transaction.atomic():
        lock_organization(request.user.organization_id)
        current_staff(request)
        existing, record = idempotency(
            request,
            request.user.organization,
            f"staff:{request.user.pk}",
            f"retry_delivery:{ident}",
            dict(request.data),
        )
        if existing:
            return Response({"queued": True})
        job = (
            DeliveryJob.objects.select_for_update()
            .filter(pk=ident, organization=request.user.organization, actor=request.user)
            .first()
        )
        if not job:
            unavailable()
        if job.state not in {"failed", "uncertain"} or not job.payload_ciphertext:
            raise Problem(
                "This notification cannot be retried. Create a fresh invitation if its secret expired."
            )
        IdempotencyRecord.objects.create(**record, resource_id=str(job.pk))
        job.state, job.next_attempt = "retry", timezone.now()
        job.save()
        audit(
            request.user.organization, request.user, "delivery.retry_requested", "delivery", job.pk
        )
    return Response({"queued": True})


@endpoint(["GET"])
def development_inbox(request):
    if (
        not settings.SYNTHETIC_MODE
        or not settings.ENABLE_DEV_TOOLS
        or settings.MAIL_PROVIDER != "development"
        or not operator_token_valid(
            request.headers.get("X-Dev-Inbox-Token", ""), settings.DEV_INBOX_TOKEN_SHA256
        )
    ):
        unavailable()
    # Explicit operator capability is required even behind a loopback proxy.
    jobs = (
        DeliveryJob.objects.filter(state="development_delivered")
        .exclude(payload_ciphertext="")
        .order_by("-created_at")[:50]
    )
    return Response(
        {
            "results": [{"id": str(j.pk), "created_at": j.created_at, **payload(j)} for j in jobs],
            "synthetic_only": True,
        }
    )
