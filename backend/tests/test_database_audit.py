"""Application audit history has no external archival path."""

from unittest.mock import Mock

import boto3
import pytest
from django.core.management import get_commands

from backend.apps.core import audit as audit_module
from backend.apps.core import tasks
from backend.apps.core.models import AuditEvent
from backend.apps.core.operations import report
from backend.apps.core.services import audit
from backend.tests.test_rp01_environment import run_startup


@pytest.mark.django_db
def test_database_audit_persists_without_external_writes(org, settings, monkeypatch):
    external = Mock(side_effect=AssertionError("Unexpected AWS call"))
    monkeypatch.setattr(boto3, "client", external)
    audit(org, None, "test.database_only", "test", "one")
    row = AuditEvent.objects.get(action="test.database_only")
    assert audit_module.event_data(row)["archive_state"] == "database_only"
    assert audit_module.event_data(row)["archive"] is None
    health = report(min_free_bytes=0)
    assert health["pending_archive"] == 0
    assert "archive_not_configured" not in health["issues"]
    assert "archive_backlog_over_limit" not in health["issues"]
    assert "audit_archive_evidence" not in get_commands()
    assert not hasattr(audit_module, "archive_pending")
    assert not hasattr(tasks, "archive_audit_task")
    external.assert_not_called()


def test_stale_archive_environment_cannot_reactivate_removed_feature():
    result = run_startup(
        [
            "-c",
            "from backend.config import settings as s; print('audit-archive' in s.CELERY_BEAT_SCHEDULE); print(hasattr(s, 'AUDIT_BUCKET'))",
        ],
        {
            "APP_ENV": "test",
            "AUDIT_ARCHIVE_ENABLED": "true",
            "AUDIT_BUCKET": "stale-test-bucket",
            "AUDIT_RETENTION_DAYS": "invalid",
        },
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["False", "False"]
