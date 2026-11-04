import json
from pathlib import Path

import boto3
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from backend.apps.core.archive_verify import rebuild_projection
from backend.apps.core.models import AuditArchive, AuditEvent


class Command(BaseCommand):
    help = "Export a version manifest or rebuild a NEW projection from a trusted manifest."

    def add_arguments(self, parser):
        parser.add_argument("--manifest", type=Path, required=True)
        parser.add_argument("--rebuild", type=Path)

    def handle(self, *args, **options):
        try:
            path = options["manifest"]
            if options["rebuild"]:
                manifest = json.loads(path.read_text(encoding="utf-8"))
                if manifest["schema"] != 1 or manifest["bucket"] != settings.AUDIT_BUCKET:
                    raise ValueError("Manifest scope mismatch")
                count = rebuild_projection(
                    boto3.client("s3", region_name=settings.AWS_REGION),
                    settings.AUDIT_BUCKET,
                    manifest["entries"],
                    options["rebuild"],
                )
                self.stdout.write(f"Verified and rebuilt {count} events into a new projection.")
            else:
                if not settings.AUDIT_BUCKET:
                    raise ValueError("Archive bucket is not configured")
                entries = [
                    {
                        "event_id": str(a.event_id),
                        "organization": str(a.event.organization_id),
                        "sequence": a.event.sequence,
                        "object_key": a.object_key,
                        "version_id": a.version_id,
                        "digest": a.digest,
                        "retain_until": a.retain_until.isoformat(),
                        **(
                            {
                                "batch_id": str(a.batch_id),
                                "batch_sequence": a.batch.sequence,
                                "previous_digest": a.batch.previous_digest,
                            }
                            if a.batch_id
                            else {}
                        ),
                    }
                    for a in AuditArchive.objects.select_related("event", "batch").order_by(
                        "event__sequence"
                    )
                ]
                pending = AuditEvent.objects.filter(archive__isnull=True).count()
                with path.open("x", encoding="utf-8") as out:
                    json.dump(
                        {
                            "schema": 1,
                            "bucket": settings.AUDIT_BUCKET,
                            "pending_events": pending,
                            "entries": entries,
                        },
                        out,
                        indent=2,
                    )
                path.chmod(0o600)
                self.stdout.write(
                    f"Exported {len(entries)} references; {pending} events pending. "
                    "Protect this manifest independently; it is not signed."
                )
        except Exception as exc:
            raise CommandError(
                "Archive evidence operation failed; inspect configuration and trusted manifest."
            ) from exc
