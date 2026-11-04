from unittest.mock import Mock

import pytest
from django.db import transaction

from backend.apps.core import document_service, mail
from backend.apps.core.models import AuditEvent, AuditSequence, DeliveryJob
from backend.apps.core.outbox_lock import outbox_lock
from backend.apps.core.services import audit
from backend.tests.test_flows import compose

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("ready", [True, False])
def test_batch_checks_readiness_for_each_job(staff_client, monkeypatch, ready):
    for _ in range(4):
        assert compose(staff_client).status_code == 201
    check = Mock(return_value=ready)
    monkeypatch.setattr(document_service, "ready", check)
    mail.process_pending()
    assert check.call_count == 4
    assert (
        DeliveryJob.objects.filter(state="development_delivered" if ready else "queued").count()
        == 4
    )
    if not ready:
        assert not DeliveryJob.objects.exclude(attempts=0).exists()


def test_overlapping_batch_skips_work_and_releases_on_error(monkeypatch):
    batch = Mock()
    monkeypatch.setattr(mail, "_process_batch", batch)
    # SQLite synthetic lock is process-wide across independent file handles.
    from django.db import connection

    if connection.vendor != "sqlite":
        pytest.skip("Separate-connection PostgreSQL coverage is in concurrency tests")
    with outbox_lock() as acquired:
        assert acquired
        mail.process_pending()
        batch.assert_not_called()
    batch.side_effect = RuntimeError("injected")
    with pytest.raises(RuntimeError):
        mail.process_pending()
    batch.side_effect = None
    mail.process_pending()
    assert batch.call_count == 2


def test_batch_stops_admitting_jobs_after_time_budget(staff_client, monkeypatch):
    for _ in range(3):
        compose(staff_client)
    ticks = iter([0, 0, 31])
    monkeypatch.setattr(mail.time, "monotonic", lambda: next(ticks))
    worker = Mock()
    monkeypatch.setattr(mail, "process_job", worker)
    mail.process_pending()
    assert worker.call_count == 1


def test_audit_sequence_is_separate_and_transactional(org, monkeypatch):
    monkeypatch.setattr(
        "backend.apps.core.services.lock_organization", Mock(side_effect=AssertionError("org lock"))
    )
    first = audit(org, None, "test.first", "organization", org.pk)
    with pytest.raises(RuntimeError):
        with transaction.atomic():
            audit(org, None, "test.rollback", "organization", org.pk)
            raise RuntimeError("rollback")
    second = audit(org.pk, None, "test.second", "organization", org.pk)
    assert second.sequence == first.sequence + 1
    assert AuditSequence.objects.get(organization=org).value == second.sequence
    assert not AuditEvent.objects.filter(action="test.rollback").exists()


def test_audit_sequence_migration_preserves_existing_high_water(org):
    from importlib import import_module

    from django.apps import apps

    migration = import_module("backend.apps.core.migrations.0010_separate_audit_sequence")
    first = audit(org, None, "test.before_migration", "organization", org.pk)
    AuditSequence.objects.filter(organization=org).delete()
    org.audit_sequence = first.sequence + 10
    org.save(update_fields=["audit_sequence"])
    schema = Mock(connection=Mock(alias="default"))
    migration.seed_sequences(apps, schema)
    assert AuditSequence.objects.get(organization=org).value == org.audit_sequence
    next_event = audit(org, None, "test.after_migration", "organization", org.pk)
    assert next_event.sequence == org.audit_sequence + 1
    migration.restore_legacy_counters(apps, schema)
    org.refresh_from_db()
    assert org.audit_sequence == next_event.sequence
