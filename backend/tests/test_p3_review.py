import ast
import secrets
import subprocess
import sys
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest

from backend.apps.core import keyring
from backend.apps.core.models import WrappingKeyVersion
from backend.keyservice.client import ServiceUnavailable
from backend.keyservice.store import KeyStore
from backend.tests.test_flows import compose


@pytest.mark.django_db
def test_rotation_operation_replay_and_parameter_conflict(org):
    operation = str(uuid.uuid4())
    first = keyring.rotate(org, request_id=operation, expected_active=None, reason="scheduled")
    assert (
        keyring.rotate(org, request_id=operation, expected_active=None, reason="scheduled").pk
        == first.pk
    )
    assert WrappingKeyVersion.objects.filter(organization=org).count() == 1
    with pytest.raises(ValueError):
        keyring.rotate(org, request_id=operation, expected_active=None, reason="different")


@pytest.mark.django_db
def test_remote_rotation_lost_response_reuses_original_operation(
    org, settings, tmp_path, monkeypatch
):
    secret = secrets.token_bytes(32)
    store = KeyStore.initialize(tmp_path / "live.db", secret, backup_directory=tmp_path / "backups")
    store.unseal(secret, "custodian")
    operation = str(uuid.uuid4())
    lost = True

    def call(op, **data):
        nonlocal lost
        result = store.rotate(
            data["organization"], data["expected"], data["request_id"], "maintenance"
        )
        if lost:
            lost = False
            raise ServiceUnavailable("Response lost after commit")
        return result

    monkeypatch.setattr(keyring, "service", lambda: Mock(call=call))
    settings.KEY_PROTECTOR = "key-service"
    with pytest.raises(ServiceUnavailable):
        keyring.rotate(org, request_id=operation, expected_active=None)
    result = keyring.rotate(org, request_id=operation, expected_active=None)
    assert len(store.list_versions(str(org.pk))) == 1
    newer = store.rotate(str(org.pk), str(result.pk), str(uuid.uuid4()), "maintenance")
    replay = store.rotate(str(org.pk), None, operation, "maintenance")
    assert replay["state"] == "decrypt_only"
    assert replay["id"] != newer["id"]


@pytest.mark.django_db
def test_subject_search_is_owner_scoped_and_keeps_ciphertext(staff_client, admin_client):
    assert compose(staff_client, subject="Quarterly Zebra review").status_code == 201
    result = staff_client.get("/api/conversations", {"q": "zEbRa"})
    assert result.status_code == 200 and result.json()["count"] == 1
    assert admin_client.get("/api/conversations", {"q": "zebra"}).json()["count"] == 0
    from backend.apps.core.models import Conversation

    assert "Zebra" not in Conversation.objects.get().subject_ciphertext


def test_optimized_transport_probe_cannot_skip_failure():
    path = Path("scripts/check_pq_transport.py").resolve()
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(path.read_text())))
    code = """from unittest.mock import Mock, patch
from scripts.check_pq_transport import exchange
with patch("scripts.check_pq_transport.socket.socket",return_value=Mock()), patch("scripts.check_pq_transport.socket.create_connection",side_effect=OSError()), patch("scripts.check_pq_transport.threading.Thread",return_value=Mock(is_alive=lambda:False)):
    try:
        exchange(None,None)
    except RuntimeError:
        print("failure detected under optimization")
    else:
        raise SystemExit(1)
"""
    result = subprocess.run(
        [sys.executable, "-O", "-c", code], capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stderr
    assert "failure detected" in result.stdout


def test_unexpected_service_error_logs_incident_without_exception_secret(tmp_path, caplog):
    from backend.keyservice.server import Handler

    handler = object.__new__(Handler)
    handler.server = Mock()
    handler.peer = Mock(side_effect=RuntimeError("SECRET-MATERIAL-MUST-NOT-BE-LOGGED"))
    handler.response = Mock()
    handler.do_POST()
    assert handler.response.call_args.args[0] == 503
    incident = handler.response.call_args.args[1]["incident_id"]
    assert incident in caplog.text and "RuntimeError" in caplog.text
    assert "SECRET-MATERIAL" not in caplog.text
