import json

from django.core.management.base import BaseCommand, CommandError

from backend.apps.core.operations import report


class Command(BaseCommand):
    help = "Output nonsecret operational signals; nonzero exit on unmet thresholds."

    def add_arguments(self, parser):
        parser.add_argument("--max-archive-age-seconds", type=int, required=True)
        parser.add_argument("--min-free-bytes", type=int, required=True)

    def handle(self, *args, **options):
        if min(options["max_archive_age_seconds"], options["min_free_bytes"]) < 0:
            raise CommandError("Thresholds cannot be negative.")
        value = report(
            max_archive_age=options["max_archive_age_seconds"],
            min_free_bytes=options["min_free_bytes"],
        )
        self.stdout.write(json.dumps(value, sort_keys=True))
        if value["issues"]:
            raise CommandError("Operational checks require attention.")
