"""Explicit, repeatable synthetic-store migration; never sends keys through the portal."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.test.utils import override_settings

from backend.apps.core import keyring
from backend.apps.core.models import Organization, WrappingKeyVersion


class Command(BaseCommand):
    help = "Import local synthetic private versions into the mTLS key service as decrypt-only."

    def add_arguments(self, parser):
        parser.add_argument("--organization", required=True)
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        if not settings.SYNTHETIC_MODE:
            raise CommandError("Local migration is synthetic-only.")
        try:
            org = Organization.objects.get(pk=options["organization"])
            records = list(WrappingKeyVersion.objects.filter(organization=org))
            # Validate every local record before starting. Do not overwrite local records:
            # preserve rollback until explicit service activation and verified migration.
            with override_settings(KEY_PROTECTOR="local-development"):
                material = [(row, keyring.private_keys(row)) for row in records]
            if not options["apply"]:
                self.stdout.write(f"Validated {len(material)} local versions; no import performed.")
                return
            client = keyring.service()
            for row, (pq, classical) in material:
                result = client.call(
                    "import",
                    organization=str(org.pk),
                    key_id=str(row.pk),
                    private=keyring.encode(pq.private_bytes_raw() + classical.private_bytes_raw()),
                )
                if (
                    result["pq_public"] != row.pq_public
                    or result["classical_public"] != row.classical_public
                ):
                    raise ValueError("Imported public metadata mismatch.")
            self.stdout.write(
                f"Imported {len(material)} versions as decrypt-only. Provision a new service version before switching workloads."
            )
        except Exception as exc:
            raise CommandError(
                "Import stopped. Local records were preserved; inspect configuration and retry."
            ) from exc
