"""Read-only operational signals and explicitly authorized staged cleanup."""

import shutil
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from . import storage
from .models import Attachment, AuditEvent, DeliveryJob
from .services import audit, lock_organization


def report(*, max_archive_age: int, min_free_bytes: int) -> dict:
    now = timezone.now()
    pending = AuditEvent.objects.filter(archive__isnull=True)
    oldest = pending.order_by("occurred_at").values_list("occurred_at", flat=True).first()
    disk = shutil.disk_usage(settings.RUNTIME_DIR)
    age = int((now - oldest).total_seconds()) if oldest else 0
    stalled = DeliveryJob.objects.filter(
        Q(state="uncertain") | Q(state="sending", updated_at__lt=now - timedelta(minutes=10))
    ).count()
    issues = []
    if not settings.AUDIT_BUCKET or settings.AUDIT_RETENTION_DAYS <= 0:
        issues.append("archive_not_configured")
    if age > max_archive_age:
        issues.append("archive_backlog_over_limit")
    if disk.free < min_free_bytes:
        issues.append("storage_free_space_low")
    if stalled:
        issues.append("delivery_outcome_uncertain")
    return {
        "checked_at": now.isoformat(),
        "issues": issues,
        "disk_free_bytes": disk.free,
        "pending_archive": pending.count(),
        "oldest_pending_seconds": age,
        "uncertain_deliveries": stalled,
        "staged_uploads": Attachment.objects.filter(message=None).exclude(state="deleted").count(),
        "note": "Configuration/backlog signals only; not a live archive or recovery certification.",
    }


def clean_staged(*, older_than_hours: int, limit: int, apply: bool) -> dict:
    """Only uncommitted records; serialize against finalization through the org lock.

    A durable cleanup_pending state prevents attachment while external deletion
    runs. Failed deletion is retryable; committed files are never candidates.
    """
    if older_than_hours < 1 or not 1 <= limit <= 1000:
        raise ValueError("Specify age >= 1 hour and a batch limit from 1 to 1000.")
    cutoff = timezone.now() - timedelta(hours=older_than_hours)
    candidates = list(
        Attachment.objects.filter(message=None, created_at__lt=cutoff)
        .exclude(state="deleted")
        .order_by("created_at", "pk")
        .values_list("pk", "organization_id")[:limit]
    )
    result = {
        "candidates": len(candidates),
        "deleted": 0,
        "skipped": 0,
        "failed": 0,
        "dry_run": not apply,
    }
    if not apply:
        return result
    for ident, org in candidates:
        with transaction.atomic():
            lock_organization(org)
            row = Attachment.objects.select_for_update().get(pk=ident)
            if row.message_id is not None or row.state == "deleted" or row.created_at >= cutoff:
                result["skipped"] += 1
                continue
            row.state = "cleanup_pending"
            row.save(update_fields=["state"])
        try:
            storage.remove(row.object_key)
        except Exception:
            result["failed"] += 1
            continue
        with transaction.atomic():
            lock_organization(org)
            row = Attachment.objects.select_for_update().get(pk=ident)
            if row.message_id is not None or row.state != "cleanup_pending":
                raise ValueError("Unexpected cleanup transition")
            row.state = "deleted"
            row.stored_size = 0
            row.save(update_fields=["state", "stored_size"])
            audit(row.organization, None, "attachment.staged_deleted", "attachment", row.pk)
        result["deleted"] += 1
    return result
