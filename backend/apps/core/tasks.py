import threading
import time

from celery import shared_task

_wake_lock = threading.Lock()
_wake_retry_at = 0.0


@shared_task(name="securemail.deliver_job", ignore_result=True)
def deliver_job_task(ident):
    from .mail import process_job

    process_job(ident)


def wake_delivery(ident, *, urgent=False):
    """Best-effort wakeup; the committed database outbox remains authoritative."""
    import logging

    global _wake_retry_at
    # Concurrent/large-recipient requests must not each wait on a failed broker.
    # Skipped wakeups remain in the durable outbox for the periodic sweep.
    if not _wake_lock.acquire(blocking=False):
        return
    try:
        if time.monotonic() < _wake_retry_at:
            return
        try:
            deliver_job_task.apply_async(
                args=[str(ident)], priority=0 if urgent else 6, retry=False
            )
        except Exception:
            _wake_retry_at = time.monotonic() + 5
            logging.getLogger("securemail").warning("outbox_wakeup_unavailable")
    finally:
        _wake_lock.release()


@shared_task(name="securemail.process_pending", ignore_result=True)
def process_pending_task():
    from .mail import process_pending

    process_pending()


@shared_task(name="securemail.cleanup_transient", ignore_result=True)
def cleanup_transient_task():
    """Bounded cleanup of abandoned uploads and fully-refilled rate buckets."""
    from datetime import timedelta

    from django.db.models import Q
    from django.utils import timezone

    from .models import RateBucket
    from .operations import clean_staged

    # All current bucket refill periods are <= one day. Two idle days is safe.
    expired = list(
        RateBucket.objects.filter(
            Q(refilled_at__lt=timezone.now() - timedelta(days=2)) | Q(refilled_at=None)
        ).values_list("pk", flat=True)[:1000]
    )
    RateBucket.objects.filter(pk__in=expired).filter(
        Q(refilled_at__lt=timezone.now() - timedelta(days=2)) | Q(refilled_at=None)
    ).delete()
    result = clean_staged(older_than_hours=24, limit=100, apply=True)
    if result["failed"]:
        import logging

        logging.getLogger("securemail").warning("staged_cleanup_failed count=%s", result["failed"])
