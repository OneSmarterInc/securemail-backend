import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.config.settings")
app = Celery("securemail")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks(["backend.apps.core"])
