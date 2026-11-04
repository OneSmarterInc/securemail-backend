import json

from django.core.management.base import BaseCommand, CommandError

from backend.apps.core.operations import clean_staged


class Command(BaseCommand):
    help = "Dry-run abandoned staged uploads; committed submissions are never deleted."

    def add_arguments(self, parser):
        parser.add_argument("--older-than-hours", type=int, required=True)
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        try:
            value = clean_staged(
                older_than_hours=options["older_than_hours"],
                limit=options["limit"],
                apply=options["apply"],
            )
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(json.dumps(value))
        if value["failed"]:
            raise CommandError(
                "Some external deletions failed; retry after resolving storage failure."
            )
