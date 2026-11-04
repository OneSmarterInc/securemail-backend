"""Real transactions on independent PostgreSQL connections; never simulated on SQLite."""

import os
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
from django.db import OperationalError, close_old_connections, connection, connections, transaction
from django.db.models import F
from django.test import Client
from django.utils import timezone
from psycopg import sql

from backend.apps.core.mail import payload
from backend.apps.core.models import (
    Conversation,
    DeliveryJob,
    Message,
    Organization,
    OTPChallenge,
    RecipientSession,
    StaffUser,
)
from backend.apps.core.services import keyed
from backend.tests.conftest import authenticated
from backend.tests.test_flows import compose, post, recipient_access

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(
        connection.vendor != "postgresql", reason="Requires real PostgreSQL row locks"
    ),
]


def race(*operations):
    barrier = threading.Barrier(len(operations))

    def run(operation):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return operation()
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=len(operations)) as pool:
        futures = [pool.submit(run, op) for op in operations]
        return [future.result(timeout=30) for future in futures]


def test_audit_does_not_wait_for_organization_business_lock(org):
    from backend.apps.core.services import audit, lock_organization

    audit(org, None, "test.seed", "organization", org.pk)

    def append():
        close_old_connections()
        try:
            return audit(org.pk, None, "test.independent", "organization", org.pk).sequence
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with transaction.atomic():
            lock_organization(org)
            assert pool.submit(append).result(timeout=5) > 0


def test_parallel_audit_sequence_and_outbox_owner(org):
    from backend.apps.core.outbox_lock import outbox_lock
    from backend.apps.core.services import audit

    def append():
        return audit(org.pk, None, "test.concurrent", "organization", org.pk).sequence

    sequences = race(*([append] * 4))
    assert len(set(sequences)) == 4

    def attempt():
        close_old_connections()
        try:
            with outbox_lock() as acquired:
                return acquired
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with outbox_lock() as acquired:
            assert acquired
            assert pool.submit(attempt).result(timeout=5) is False
        assert pool.submit(attempt).result(timeout=5) is True


def test_same_otp_is_consumed_once(staff_client):
    response = compose(staff_client)
    conversation = Conversation.objects.get(pk=response.json()["id"])
    token = payload(DeliveryJob.objects.get(conversation=conversation))["link"].split("/")[-1]
    challenge = OTPChallenge(
        grant=conversation.grants.get(), expires_at=timezone.now() + timedelta(minutes=5)
    )
    challenge.verifier = keyed(f"otp:{challenge.pk}:123456", purpose="otp")
    challenge.save()
    clients = [Client(), Client()]
    result = race(
        *(
            lambda c=c: post(c, "/recipient/verify", {"token": token, "code": "123456"}).status_code
            for c in clients
        )
    )
    assert sorted(result) == [200, 400]
    assert RecipientSession.objects.filter(grant=challenge.grant).count() == 1


def test_duplicate_submission_is_one_conversation(staff):
    clients = [authenticated(staff), authenticated(staff)]
    key = str(uuid.uuid4())
    body = {"sender": staff.email, "to": ["sara@example.com"], "mode": "secure_request"}
    results = race(*(lambda c=c: post(c, "/conversations", body, key=key) for c in clients))
    assert sorted(r.status_code for r in results) == [200, 201]
    assert results[0].json()["id"] == results[1].json()["id"]
    assert Conversation.objects.count() == 1


def test_two_admin_removals_leave_one_admin(admin):
    other = StaffUser.objects.create_user(
        username="second@onesmarter.com",
        email="second@onesmarter.com",
        organization=admin.organization,
        display_name="Second",
        role="admin",
        status="active",
        can_manage_privileges=True,
        mfa_confirmed=True,
    )
    clients = [authenticated(admin), authenticated(other)]
    results = race(
        *(
            lambda c=c, u=u: (
                post(
                    c,
                    f"/admin/accounts/{u.pk}",
                    {"action": "deactivate", "reason": "Synthetic race test"},
                ).status_code
            )
            for c, u in zip(clients, [admin, other])
        )
    )
    assert sorted(results) == [200, 409]
    assert StaffUser.objects.filter(role="admin", status="active").count() == 1


def test_revoke_serializes_with_recipient_reply(staff_client):
    recipient, conversation, _, _ = recipient_access(staff_client)
    before = Message.objects.filter(conversation=conversation).count()
    results = race(
        lambda: post(recipient, "/recipient/conversation", {"body": "racing reply"}).status_code,
        lambda: post(staff_client, f"/conversations/{conversation.pk}/revoke").status_code,
    )
    assert results[1] == 200
    assert results[0] in {201, 403, 404}
    assert Message.objects.filter(conversation=conversation).count() == before + (results[0] == 201)
    assert post(recipient, "/recipient/conversation", {"body": "after revoke"}).status_code in {
        403,
        404,
    }


def test_lock_timeout_rolls_back_and_explicit_retry_succeeds(org):
    def blocked_writer():
        close_old_connections()
        try:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL lock_timeout = '200ms'")
                Organization.objects.select_for_update().get(pk=org.pk)
                Organization.objects.filter(pk=org.pk).update(name="must not commit")
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with transaction.atomic():
            Organization.objects.select_for_update().get(pk=org.pk)
            future = pool.submit(blocked_writer)
            with pytest.raises(OperationalError):
                future.result(timeout=10)
    org.refresh_from_db()
    assert org.name != "must not commit"
    with transaction.atomic():
        locked = Organization.objects.select_for_update().get(pk=org.pk)
        locked.name = "Explicit retry"
        locked.save(update_fields=["name"])
    org.refresh_from_db()
    assert org.name == "Explicit retry"


def test_deadlock_victim_rolls_back_before_retry(org):
    other = Organization.objects.create(name="Deadlock peer", domain="deadlock.test")
    first_lock = threading.Barrier(2)

    def opposing_update(first, second):
        try:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=first)
                Organization.objects.filter(pk=first).update(audit_sequence=F("audit_sequence") + 1)
                first_lock.wait(timeout=10)
                Organization.objects.select_for_update().get(pk=second)
                Organization.objects.filter(pk=second).update(
                    audit_sequence=F("audit_sequence") + 1
                )
            return "committed"
        except OperationalError as exc:
            assert getattr(exc.__cause__, "sqlstate", None) == "40P01"
            return "deadlock_rolled_back"

    results = race(
        lambda: opposing_update(org.pk, other.pk), lambda: opposing_update(other.pk, org.pk)
    )
    assert sorted(results) == ["committed", "deadlock_rolled_back"]
    assert set(
        Organization.objects.filter(pk__in=[org.pk, other.pk]).values_list(
            "audit_sequence", flat=True
        )
    ) == {1}
    # Retry an entire rolled-back transaction in consistent lock order, not a
    # single failed statement or external delivery side effect.
    with transaction.atomic():
        for ident in sorted([org.pk, other.pk]):
            Organization.objects.select_for_update().get(pk=ident)
            Organization.objects.filter(pk=ident).update(audit_sequence=F("audit_sequence") + 1)
    assert set(
        Organization.objects.filter(pk__in=[org.pk, other.pk]).values_list(
            "audit_sequence", flat=True
        )
    ) == {2}


@pytest.mark.skipif(
    not os.environ.get("POSTGRES_TOOLS"), reason="Requires matching pg_dump/pg_restore binaries"
)
def test_actual_postgres_backup_restore_preserves_audit_and_keys(staff_client, tmp_path):
    response = compose(staff_client)
    assert response.status_code == 201
    ident = response.json()["id"]
    config = connection.settings_dict
    assert config["NAME"].startswith("test_")
    env = {
        **os.environ,
        "PGHOST": config["HOST"],
        "PGPORT": str(config["PORT"]),
        "PGUSER": config["USER"],
        "PGPASSWORD": config["PASSWORD"],
    }
    tools = Path(os.environ["POSTGRES_TOOLS"])
    suffix = ".exe" if os.name == "nt" else ""
    backup = tmp_path / "database.dump"
    subprocess.run(
        [
            str(tools / ("pg_dump" + suffix)),
            "--format=custom",
            "--file",
            str(backup),
            "--dbname",
            config["NAME"],
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    restored = "test_restore_" + uuid.uuid4().hex
    admin_args = {
        "host": config["HOST"],
        "port": config["PORT"],
        "user": config["USER"],
        "password": config["PASSWORD"],
        "dbname": "postgres",
        "autocommit": True,
    }
    with psycopg.connect(**admin_args) as control:
        control.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored)))
        try:
            subprocess.run(
                [
                    str(tools / ("pg_restore" + suffix)),
                    "--exit-on-error",
                    "--no-owner",
                    "--dbname",
                    restored,
                    str(backup),
                ],
                env=env,
                check=True,
                capture_output=True,
            )
            with psycopg.connect(**{**admin_args, "dbname": restored}) as recovered:
                row = recovered.execute(
                    "SELECT subject_ciphertext FROM core_conversation WHERE id=%s", (ident,)
                ).fetchone()
                assert row[0] == Conversation.objects.get(pk=ident).subject_ciphertext
                assert (
                    recovered.execute("SELECT count(*) FROM core_wrappingkeyversion").fetchone()[0]
                    > 0
                )
                assert recovered.execute("SELECT count(*) FROM core_auditevent").fetchone()[0] > 0
                with pytest.raises(psycopg.Error):
                    recovered.execute("DELETE FROM core_auditevent")
        finally:
            control.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(restored)))
