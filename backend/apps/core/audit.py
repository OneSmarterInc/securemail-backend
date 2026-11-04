import csv
import io
from datetime import timedelta

from django.core import signing
from django.db import transaction
from django.db.models import Max, Q
from django.http import HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.response import Response

from .auth import recent_mfa
from .http import Problem, endpoint, unavailable
from .models import AuditEvent, AuditExport
from .services import audit, paginate


def event_data(event):
    return {
        "id": str(event.pk),
        "sequence": event.sequence,
        "occurred_at": event.occurred_at,
        "actor_id": event.actor_id,
        "actor": event.actor_label,
        "role": event.actor_role,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "outcome": event.outcome,
        "metadata": event.metadata,
        "archive_state": "database_only",
        "archive": None,
    }


def filtered(org, params, snapshot, high_water):
    query = AuditEvent.objects.filter(
        organization=org, occurred_at__lte=snapshot, sequence__lte=high_water
    )
    q = str(params.get("q", ""))[:200].strip()
    if q:
        query = query.filter(
            Q(actor_label__icontains=q)
            | Q(actor_id__icontains=q)
            | Q(action__icontains=q)
            | Q(target_id__icontains=q)
        )
    for field in ["action", "outcome", "target_type", "actor_id", "target_id"]:
        if params.get(field):
            query = query.filter(**{field: str(params[field])[:100]})
    for field, lookup in [("from", "occurred_at__gte"), ("to", "occurred_at__lte")]:
        if params.get(field):
            value = parse_datetime(str(params[field]))
            if value is None or timezone.is_naive(value):
                raise Problem("Use a date and time with a timezone.", "invalid_date")
            query = query.filter(**{lookup: value})
    return query


def snapshot_value(value, org):
    if value:
        try:
            data = signing.loads(value, salt="audit-snapshot", max_age=86400)
            if data["org"] != str(org.pk):
                raise ValueError("Wrong organization")
            return parse_datetime(data["at"]), data["sequence"], value
        except (signing.BadSignature, ValueError, KeyError, TypeError) as exc:
            raise Problem("Invalid or expired audit snapshot.") from exc
    now = timezone.now()
    high_water = (
        AuditEvent.objects.filter(organization=org).aggregate(value=Max("sequence"))["value"] or 0
    )
    token = signing.dumps(
        {"org": str(org.pk), "at": now.isoformat(), "sequence": high_water}, salt="audit-snapshot"
    )
    return now, high_water, token


@endpoint(["GET"], admin=True)
def events(request):
    snapshot, high_water, snapshot_token = snapshot_value(
        request.query_params.get("snapshot"), request.user.organization
    )
    query = filtered(request.user.organization, request.query_params, snapshot, high_water)
    rows, meta = paginate(
        query,
        request,
        ordering={
            "occurred_at": "occurred_at",
            "actor": "actor_label",
            "action": "action",
            "outcome": "outcome",
        },
        default="-occurred_at",
    )
    # Never copy arbitrary search text into immutable audit metadata.
    audit(
        request.user.organization,
        request.user,
        "audit.searched",
        "audit",
        "",
        metadata={"result_count": meta["count"]},
    )
    return Response(
        {
            "results": [event_data(e) for e in rows],
            **meta,
            "snapshot": snapshot_token,
            "snapshot_at": snapshot,
            "archive_enabled": False,
            "audit_storage": "database",
            "oldest_pending_seconds": 0,
            "archive_overdue": False,
            "pending_archive": 0,
        }
    )


@endpoint(["GET"], admin=True)
def event_detail(request, ident):
    event = AuditEvent.objects.filter(pk=ident, organization=request.user.organization).first()
    if not event:
        unavailable()
    audit(request.user.organization, request.user, "audit.viewed", "audit_event", event.pk)
    return Response(event_data(event))


@endpoint(["POST"], admin=True)
def create_export(request):
    if not request.user.can_export_audit:
        raise Problem("Audit export permission is required.", status=403)
    recent_mfa(request)
    filters = {
        k: str(v)[:200]
        for k, v in request.data.items()
        if k in {"q", "action", "outcome", "target_type", "actor_id", "target_id", "from", "to"}
    }
    snapshot, high_water, _ = snapshot_value(
        request.data.get("snapshot"), request.user.organization
    )
    if filtered(request.user.organization, filters, snapshot, high_water).count() > 10000:
        raise Problem("Narrow the filters to at most 10,000 events.", "export_limit")
    with transaction.atomic():
        export = AuditExport.objects.create(
            organization=request.user.organization,
            owner=request.user,
            filters=filters,
            snapshot=snapshot,
            high_water=high_water,
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        audit(
            request.user.organization,
            request.user,
            "audit.export_created",
            "audit_export",
            export.pk,
        )
    return Response(
        {
            "id": str(export.pk),
            "expires_at": export.expires_at,
            "download_url": f"/api/admin/audit-exports/{export.pk}",
        },
        status=201,
    )


def csv_safe(value):
    text = str(value)
    return (
        "'" + text
        if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n"))
        else text
    )


@endpoint(["GET"], admin=True)
def download_export(request, ident):
    if not request.user.can_export_audit:
        raise Problem("Audit export permission is required.", status=403)
    export = AuditExport.objects.filter(
        pk=ident,
        owner=request.user,
        organization=request.user.organization,
        expires_at__gt=timezone.now(),
    ).first()
    if export is None:
        unavailable()
    rows = filtered(
        request.user.organization, export.filters, export.snapshot, export.high_water
    ).order_by("-occurred_at", "id")[:10000]
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(
        ["Event ID", "Recorded at (UTC)", "Actor", "Action", "Target type", "Target ID", "Outcome"]
    )
    for e in rows:
        writer.writerow(
            [
                csv_safe(v)
                for v in [
                    e.pk,
                    e.occurred_at.isoformat(),
                    e.actor_label,
                    e.action,
                    e.target_type,
                    e.target_id,
                    e.outcome,
                ]
            ]
        )
    audit(
        request.user.organization,
        request.user,
        "audit.export_downloaded",
        "audit_export",
        export.pk,
    )
    response = HttpResponse(stream.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="audit-events.csv"'
    return response
