import json

from django.core.management.base import BaseCommand, CommandError

from backend.apps.core.operations import report


class Command(BaseCommand):
    help = "Output nonsecret operational signals; nonzero exit on unmet thresholds."

    def add_arguments(self, parser):
        parser.add_argument("--min-free-bytes", type=int, required=True)

    def handle(self, *args, **options):
        if options["min_free_bytes"] < 0:
            raise CommandError("Thresholds cannot be negative.")
        value = report(
            min_free_bytes=options["min_free_bytes"],
        )
        self.stdout.write(json.dumps(value, sort_keys=True))
        if value["issues"]:
            raise CommandError("Operational checks require attention.")
