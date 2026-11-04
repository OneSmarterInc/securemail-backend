import base64
import secrets
import sqlite3
import time
from contextlib import closing

import pytest
from django_otp.oath import TOTP

from backend.keyservice.custodian_accounts import CustodianAccounts
from backend.keyservice.server import Service
from backend.keyservice.store import KeyStore


@pytest.fixture
def accounts(tmp_path):
    accounts = CustodianAccounts(tmp_path / "custodians")
    password = secrets.token_urlsafe(24)
    accounts.create("ammar", "Ammar", password)
    with closing(sqlite3.connect(accounts.path)) as db, db:
        db.execute("UPDATE accounts SET password_setup=0")  # Existing-password MFA scenarios.
    return accounts, password


def enrollment_code(accounts, username, password):
    enrollment = accounts.login(username, password, "")
    seed = base64.b32decode(enrollment["secret"])
    return seed, f"{TOTP(seed).token():06d}"


def test_enrollment_encrypts_seed_and_replay_survives_restart(accounts):
    accounts, password = accounts
    seed, code = enrollment_code(accounts, "ammar", password)
    assert seed not in accounts.path.read_bytes()
    assert base64.b32encode(seed) not in accounts.path.read_bytes()
    account = accounts.login("ammar", password, code)
    assert accounts.current(account["id"], account["revision"])["enrolled"]
    with pytest.raises(PermissionError):
        CustodianAccounts(accounts.directory).login("ammar", password, code)
    with pytest.raises(PermissionError):
        accounts.login("ammar", password, "")


def test_failure_bucket_persists_and_blocks_correct_code(accounts):
    accounts, password = accounts
    _, code = enrollment_code(accounts, "ammar", password)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        with pytest.raises(PermissionError):
            CustodianAccounts(accounts.directory).login("ammar", password, wrong)
    with pytest.raises(PermissionError):
        accounts.login("ammar", password, code)
    with closing(sqlite3.connect(accounts.path)) as db:
        assert db.execute("SELECT blocked_until FROM accounts").fetchone()[0] > time.time()


def test_disabled_account_and_reset_revoke_sessions(accounts):
    accounts, password = accounts
    _, code = enrollment_code(accounts, "ammar", password)
    account = accounts.login("ammar", password, code)
    accounts.set_active("ammar", False)
    with pytest.raises(PermissionError):
        accounts.current(account["id"], account["revision"])
    accounts.set_active("ammar", True)
    with pytest.raises(PermissionError):
        accounts.current(account["id"], account["revision"])
    accounts.reset_totp("ammar")
    assert accounts.login("ammar", password, "")["enrollment_required"]
    with pytest.raises(PermissionError):
        accounts.current(account["id"], account["revision"])


def test_seed_tamper_and_missing_key_fail_closed(accounts):
    accounts, password = accounts
    with closing(sqlite3.connect(accounts.path)) as db, db:
        db.execute("UPDATE accounts SET seed=randomblob(64)")
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        accounts.login("ammar", password, "")
    accounts.key_path.unlink()
    with pytest.raises(ValueError, match="Missing credential key"):
        accounts.initialize()


def test_shared_gateway_keeps_custodian_sessions_independent(accounts, tmp_path):
    accounts, password = accounts
    accounts.create("sara", "Sara", password)
    with closing(sqlite3.connect(accounts.path)) as db, db:
        db.execute("UPDATE accounts SET password_setup=0 WHERE username='sara'")
    store = KeyStore.initialize(tmp_path / "keys.db", secrets.token_bytes(32))
    service = Service(store, tmp_path / "policy.json", "https://localhost")
    service.accounts = accounts
    identity = {"name": "gateway", "role": "custodian"}
    sessions = []
    for username in ["ammar", "sara"]:
        _, code = enrollment_code(accounts, username, password)
        result = service.login(
            "shared-gateway", identity, {"username": username, "password": password, "code": code}
        )
        sessions.append(result)
    assert len(service.sessions) == 2
    for result in sessions:
        current = service.authenticate_session(
            "shared-gateway", identity, "osm_custodian=" + result["token"], result["csrf"]
        )
        assert current["id"] == result["account"]["id"]
    accounts.set_active("ammar", False)
    with pytest.raises(PermissionError):
        service.authenticate_session(
            "shared-gateway", identity, "osm_custodian=" + sessions[0]["token"], sessions[0]["csrf"]
        )
    assert (
        service.authenticate_session(
            "shared-gateway", identity, "osm_custodian=" + sessions[1]["token"], sessions[1]["csrf"]
        )["username"]
        == "sara"
    )


def test_audit_filters_sort_pagination_and_append_only(accounts, tmp_path):
    accounts, password = accounts
    _, code = enrollment_code(accounts, "ammar", password)
    account = accounts.login("ammar", password, code)
    store = KeyStore.initialize(tmp_path / "keys.db", secrets.token_bytes(32))
    store.record_event("custodian:" + account["id"] + ":ammar", "seal")
    for number in range(30):
        accounts.event("sara", "login_failed", str(number))
    filters = {
        "query": "",
        "actor": "ammar",
        "operation": "seal",
        "sort": "at",
        "direction": "desc",
        "page": 1,
    }
    result = accounts.audit(store.path, filters)
    assert result["total"] == 1 and result["rows"][0]["source"] == "key"
    result = accounts.audit(store.path, {**filters, "actor": "sara", "operation": "", "page": 2})
    assert result["total"] == 30 and len(result["rows"]) == 5
    assert accounts.audit(store.path, {**filters, "query": "%' OR 1=1 --"})["total"] == 0
    with pytest.raises(ValueError):
        accounts.audit(store.path, {**filters, "sort": "at; DROP TABLE accounts"})
    with closing(sqlite3.connect(accounts.path)) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM events")


def test_first_login_requires_new_password_and_totp_atomically(tmp_path):
    accounts = CustodianAccounts(tmp_path / "first-login")
    setup_code, new_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    accounts.create("newuser", "New custodian", setup_code)
    enrollment = accounts.login("newuser", setup_code, "")
    assert enrollment["password_setup_required"] is True
    seed = base64.b32decode(enrollment["secret"])
    code = f"{TOTP(seed).token():06d}"
    for password, confirmation in [
        ("", ""),
        ("short", "short"),
        (setup_code, setup_code),
        (new_password, "mismatch"),
    ]:
        with pytest.raises(PermissionError):
            accounts.login(
                "newuser", setup_code, code, new_password=password, confirmation=confirmation
            )
    with closing(sqlite3.connect(accounts.path)) as db:
        assert db.execute("SELECT enrolled,password_setup,last_step FROM accounts").fetchone() == (
            0,
            1,
            -1,
        )
    account = accounts.login(
        "newuser", setup_code, code, new_password=new_password, confirmation=new_password
    )
    assert accounts.current(account["id"], account["revision"])["password_setup"] == 0
    with pytest.raises(PermissionError):
        accounts.login("newuser", setup_code, code)
    with pytest.raises(PermissionError):
        accounts.login("newuser", new_password, code)  # Consumed TOTP remains unusable.
    assert new_password.encode() not in accounts.path.read_bytes()
    assert setup_code.encode() not in accounts.path.read_bytes()


def test_expired_setup_cannot_create_a_session(tmp_path):
    accounts = CustodianAccounts(tmp_path / "expired")
    setup_code = secrets.token_urlsafe(32)
    accounts.create("newuser", "New custodian", setup_code)
    _, code = enrollment_code(accounts, "newuser", setup_code)
    with closing(sqlite3.connect(accounts.path)) as db, db:
        db.execute("UPDATE accounts SET enrollment_until=0")
    with pytest.raises(PermissionError):
        accounts.login("newuser", setup_code, "")
    with pytest.raises(PermissionError):
        accounts.login(
            "newuser",
            setup_code,
            code,
            new_password="a-new-long-password-123",
            confirmation="a-new-long-password-123",
        )


def test_cli_creates_private_setup_instructions_without_printing_code(tmp_path, monkeypatch):
    from io import StringIO

    from django.core.management import call_command

    directory = tmp_path / "cli-custodians"
    monkeypatch.setenv("KEY_SERVICE_CUSTODIAN_DIRECTORY", str(directory))
    output = StringIO()
    call_command("custodian", "create", username="cli-user", name="CLI custodian", stdout=output)
    files = list(directory.glob("setup-*.txt"))
    assert len(files) == 1
    setup = files[0].read_text().split("Temporary setup code: ")[1].splitlines()[0]
    assert setup not in output.getvalue()
    assert CustodianAccounts(directory).login("cli-user", setup, "")["password_setup_required"]
