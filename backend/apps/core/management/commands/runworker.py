import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from backend.apps.core.mail import process_pending


class Command(BaseCommand):
    help = "Run the local synthetic outbox worker. Use Celery in container environments."

    def handle(self, *args, **options):
        if not settings.SYNTHETIC_MODE:
            raise CommandError("This worker is restricted to synthetic development.")
        self.stdout.write("Synthetic outbox worker running. Message content is not logged.")
        try:
            while True:
                process_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.stdout.write("Worker stopped.")
