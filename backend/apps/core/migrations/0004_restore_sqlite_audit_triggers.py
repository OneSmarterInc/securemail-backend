"""SQLite rebuilds tables during AddField, which removes table-local triggers."""

from importlib import import_module

from django.db import migrations


def restore(apps, schema_editor):
    if schema_editor.connection.vendor == "sqlite":
        initial = import_module("backend.apps.core.migrations.0002_audit_immutability")
        initial.uninstall(apps, schema_editor)
        initial.install(apps, schema_editor)


class Migration(migrations.Migration):
    dependencies = [("core", "0003_auditevent_sequence_auditexport_high_water_and_more")]
    operations = [migrations.RunPython(restore, migrations.RunPython.noop)]
