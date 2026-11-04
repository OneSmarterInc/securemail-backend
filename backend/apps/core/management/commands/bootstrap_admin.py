from getpass import getpass

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from backend.apps.core.company_identity import is_company_address
from backend.apps.core.models import Organization, StaffUser
from backend.apps.core.services import audit


class Command(BaseCommand):
    help = "Create the first administrator; requires MFA enrollment on first login."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--name", default="Workspace administrator")

    @transaction.atomic
    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        if not is_company_address(email):
            raise CommandError("A company email address is required.")
        org, _ = Organization.objects.get_or_create(
            domain=settings.COMPANY_DOMAIN, defaults={"name": "OneSmarter"}
        )
        Organization.objects.select_for_update().get(pk=org.pk)
        if StaffUser.objects.filter(organization=org).exists():
            raise CommandError("Use the administrator Access tab to manage existing accounts.")
        password = getpass("Administrator password: ")
        if password != getpass("Confirm password: "):
            raise CommandError("Passwords do not match.")
        validate_password(password)
        user = StaffUser.objects.create_user(
            username=email,
            email=email,
            password=password,
            organization=org,
            display_name=options["name"],
            role="admin",
            status="active",
            can_manage_privileges=True,
            can_export_audit=True,
            sender_addresses=[email],
        )
        audit(org, user, "account.bootstrap", "account", user.pk)
        self.stdout.write(
            "Administrator created. Sign in and enroll MFA; no credentials were printed."
        )
