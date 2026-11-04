from django.core.management.base import BaseCommand, CommandError

from backend.apps.core.keyring import rotate
from backend.apps.core.models import Organization


class Command(BaseCommand):
    help = (
        "Provision a new active OneSmarter key version; retain old versions for reads and backups."
    )

    def add_arguments(self, parser):
        parser.add_argument("--organization", required=True)
        parser.add_argument("--reason", required=True)
        parser.add_argument(
            "--request-id",
            required=True,
            help="UUID retained and reused for every retry of this operation",
        )
        parser.add_argument(
            "--expected-active",
            required=True,
            help="Observed active UUID, or none for first provisioning; reuse on retry",
        )

    def handle(self, *args, **options):
        try:
            org = Organization.objects.get(pk=options["organization"])
            key = rotate(
                org,
                reason=options["reason"],
                request_id=options["request_id"],
                expected_active=None
                if options["expected_active"] == "none"
                else options["expected_active"],
            )
        except Exception as exc:
            raise CommandError(
                "Key rotation could not be confirmed. Inspect service versions before retrying; "
                "reuse the SAME request ID, expected active version and reason when retrying."
            ) from exc
        self.stdout.write(
            f"Rotation operation resolved to wrapping-key version {key.pk} ({key.state}). Old keys remain available. No document was re-encrypted."
        )
