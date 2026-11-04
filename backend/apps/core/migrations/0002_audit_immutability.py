from django.db import migrations


def install(apps, schema_editor):
    if schema_editor.connection.vendor == "sqlite":
        schema_editor.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON core_auditevent BEGIN SELECT RAISE(ABORT, 'Audit events are immutable'); END;")
        schema_editor.execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON core_auditevent BEGIN SELECT RAISE(ABORT, 'Audit events are immutable'); END;")
    elif schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("""CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Audit events are immutable'; END; $$;""")
        schema_editor.execute("CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON core_auditevent FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();")
        schema_editor.execute("CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON core_auditevent FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();")


def uninstall(apps, schema_editor):
    if schema_editor.connection.vendor == "sqlite":
        schema_editor.execute("DROP TRIGGER IF EXISTS audit_no_update;")
        schema_editor.execute("DROP TRIGGER IF EXISTS audit_no_delete;")
    elif schema_editor.connection.vendor == "postgresql":
        schema_editor.execute("DROP TRIGGER IF EXISTS audit_no_mutation ON core_auditevent;")
        schema_editor.execute("DROP TRIGGER IF EXISTS audit_no_truncate ON core_auditevent;")
        schema_editor.execute("DROP FUNCTION IF EXISTS reject_audit_mutation();")


class Migration(migrations.Migration):
    dependencies = [("core", "0001_initial")]
    operations = [migrations.RunPython(install, uninstall)]
