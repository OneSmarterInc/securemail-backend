import base64
import json
import secrets
import time

import pytest
from django.test import Client

from backend.apps.core import crypto
from backend.apps.core.models import Organization, StaffUser


@pytest.fixture(autouse=True)
def isolated_storage(settings, tmp_path, monkeypatch):
    settings.TRUSTED_PROXY_IPS = set()
    settings.TRUSTED_PROXY_UNIX_SOCKET = False
    settings.RUNTIME_DIR = tmp_path
    settings.EVIDENCE_DIRECTORY = tmp_path / "evidence"
    settings.EVIDENCE_TSA_URL = ""
    settings.EVIDENCE_TSA_CA_FILE = ""
    settings.LOCAL_KEY_FILE = tmp_path / "key"
    settings.LOCAL_KEY_FILE.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
    settings.MAIL_PROVIDER = "development"
    settings.SMTP_SENDER_PROFILES_FILE = ""
    settings.ENABLE_DEV_TOOLS = True
    settings.ENABLE_LEGACY_RECIPIENT_API = True
    crypto._local_key.cache_clear()
    yield
    crypto._local_key.cache_clear()


@pytest.fixture
def org(db):
    return Organization.objects.create(name="OneSmarter", domain="onesmarter.com")


@pytest.fixture
def admin(org):
    return StaffUser.objects.create_user(
        username="admin@onesmarter.com",
        email="admin@onesmarter.com",
        password="A-strong-test-only-password!",
        organization=org,
        display_name="Administrator",
        role="admin",
        status="active",
        mfa_confirmed=True,
        can_manage_privileges=True,
        can_export_audit=True,
        sender_addresses=["admin@onesmarter.com"],
    )


@pytest.fixture
def staff(org):
    return StaffUser.objects.create_user(
        username="staff@onesmarter.com",
        email="staff@onesmarter.com",
        password="A-strong-test-only-password!",
        organization=org,
        display_name="Staff",
        role="staff",
        status="active",
        mfa_confirmed=True,
        sender_addresses=["staff@onesmarter.com"],
    )


def authenticated(user):
    client = Client()
    client.force_login(user)
    session = client.session
    session["staff_version"] = user.session_version
    session["mfa_at"] = time.time()
    session.save()
    return client


@pytest.fixture
def admin_client(admin):
    return authenticated(admin)


@pytest.fixture
def staff_client(staff):
    return authenticated(staff)


@pytest.fixture
def sender_profile(settings, tmp_path, monkeypatch, staff):
    settings.MAIL_PROVIDER = "smtp"
    settings.EMAIL_HOST_USER = "support@onesmarter.com"
    settings.EMAIL_HOST_PASSWORD = "synthetic-environment-secret"
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    settings.DEFAULT_FROM_EMAIL = "secure@onesmarter.com"
    settings.SMTP_SENDER_PROFILES_FILE = str(tmp_path / "senders.json")
    monkeypatch.setenv("SMTP_PASSWORD_TEST", "synthetic-test-only")
    profiles = {
        address: {
            "host": "smtp.example.test",
            "port": 587,
            "username": address,
            "password_env": "SMTP_PASSWORD_TEST",
            "security": "starttls",
        }
        for address in ["secure@onesmarter.com", "staff@onesmarter.com"]
    }
    (tmp_path / "senders.json").write_text(json.dumps(profiles))
    from django.core.mail import get_connection

    from backend.apps.core import smtp_settings
    from backend.apps.core.models import OrganizationSMTP, StaffSMTP

    OrganizationSMTP.objects.create(
        organization=staff.organization,
        host="smtp.example.test",
    )
    StaffSMTP.objects.create(
        user=staff,
        organization=staff.organization,
        email=staff.email,
        transport_revision=1,
        password_ciphertext=crypto.encrypt(
            b"synthetic-test-only", smtp_settings.secret_context(staff)
        ),
    )
    monkeypatch.setattr(smtp_settings, "SMTPBackend", lambda **kw: get_connection(**kw))
    return profiles


@pytest.fixture(scope="session", autouse=True)
def allow_test_database_teardown():
    """Only the test runner may truncate its disposable database after each test.

    Keep all audit triggers enabled while application operations run. Django's
    transaction tests flush with TRUNCATE, which our production trigger denies.
    """
    from django.db import connection
    from django.test import TransactionTestCase

    original = TransactionTestCase._fixture_teardown

    def teardown(case):
        if connection.vendor != "postgresql":
            return original(case)
        if not connection.settings_dict["NAME"].startswith("test_"):
            raise RuntimeError("Refusing teardown override outside a test database")
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE core_auditevent DISABLE TRIGGER audit_no_truncate")
        try:
            return original(case)
        finally:
            with connection.cursor() as cursor:
                cursor.execute("ALTER TABLE core_auditevent ENABLE TRIGGER audit_no_truncate")

    TransactionTestCase._fixture_teardown = teardown
    yield
    TransactionTestCase._fixture_teardown = original
