from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = "backend.apps.core"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from . import search_index  # noqa: F401
