from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from backend.apps.core import crypto, evidence, storage
from backend.apps.core.conversations import attachment_context
from backend.apps.core.models import Attachment, EvidenceCapture


class Command(BaseCommand):
    help = "Backfill local evidence without inventing provenance, or request configured trusted timestamps."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true")
        parser.add_argument("--timestamp", action="store_true")
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        limit = options["limit"]
        if not 1 <= limit <= 1000:
            raise CommandError("Limit must be between 1 and 1000.")
        if options["timestamp"]:
            ids = list(
                EvidenceCapture.objects.filter(timestamp_state="pending")
                .order_by("created_at")
                .values_list("pk", flat=True)[:limit]
            )
        else:
            ids = list(
                Attachment.objects.filter(
                    message__isnull=False, state="available", evidence_capture=None
                )
                .order_by("created_at")
                .values_list("pk", flat=True)[:limit]
            )
        completed = failed = 0
        if options["apply"]:
            for ident in ids:
                try:
                    if options["timestamp"]:
                        evidence.timestamp_capture(ident)
                    else:
                        with transaction.atomic():
                            row = Attachment.objects.select_for_update().get(pk=ident)
                            plaintext = crypto.decrypt(
                                storage.get(row.object_key).decode(), attachment_context(row)
                            )
                            evidence.capture_attachment(row, plaintext, legacy=True)
                    completed += 1
                except (crypto.CryptoUnavailable, ValueError, OSError):
                    failed += 1
                    self.stderr.write(f"Capture {ident}: unavailable; original preserved.")
        self.stdout.write(
            f"candidates={len(ids)} completed={completed} failed={failed} apply={options['apply']}"
        )
        if failed:
            raise CommandError(
                "Some captures remain unresolved; originals were not deleted or replaced."
            )
