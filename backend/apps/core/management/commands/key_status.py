from django.core.management.base import BaseCommand

from backend.apps.core.models import Organization, WrappingKeyVersion


class Command(BaseCommand):
    help = "List organization/key-version identifiers and states without displaying key material."

    def handle(self, *args, **options):
        for org in Organization.objects.order_by("id"):
            self.stdout.write(f"Organization {org.pk}")
            for key in WrappingKeyVersion.objects.filter(organization=org).order_by("created_at"):
                self.stdout.write(
                    f"  {key.pk}  {key.state}  {key.suite}  {key.created_at.isoformat()}"
                )
