import secrets
import sqlite3
from contextlib import closing
from unittest.mock import Mock

import pytest

from backend.apps.core import crypto, keyring
from backend.apps.core.models import StaffSMTP
from backend.keyservice import protocol as p
from backend.tests.test_candidate_audit import candidate_env as candidate_env
from backend.tests.test_candidate_audit import vault as vault


@pytest.mark.django_db
def test_smtp_v1_ciphertext_replayed_in_database_is_rejected(vault, staff, settings, monkeypatch):
    store, _, _, _, _, _, _ = vault
    org = str(staff.organization_id)
    import uuid

    key = store.rotate(org, None, str(uuid.uuid4()), "maintenance")
    settings.KEY_PROTECTOR = "key-service"
    settings.CRYPTO_PROVIDER = "onesmarter-hybrid-v2"
    monkeypatch.setattr(
        keyring,
        "active_key",
        lambda _: Mock(
            organization_id=staff.organization_id, state="active", suite=p.SUITE, pk=key["id"]
        ),
    )

    def call(operation, **data):
        if operation == "wrap":
            return store.wrap(
                data["organization"],
                data["context"],
                p.decode(data["dek"], 32),
                data["expected"],
                "worker",
            )
        return {
            "dek": p.encode(
                store.unwrap(data["organization"], data["context"], data["wrapper"], "worker")
            )
        }

    monkeypatch.setattr(keyring, "service", lambda: Mock(call=call))
    context = crypto.context(staff.organization_id, "smtp-credential", staff.pk)
    old = crypto.encrypt(b"synthetic-first-password", context)
    row = StaffSMTP.objects.create(
        organization=staff.organization,
        user=staff,
        email="synthetic@onesmarter.com",
        password_ciphertext=old,
    )
    row.password_ciphertext = crypto.encrypt(b"synthetic-second-password", context)
    row.save(update_fields=["password_ciphertext"])
    assert crypto.decrypt(row.password_ciphertext, context) == b"synthetic-second-password"
    StaffSMTP.objects.filter(pk=row.pk).update(password_ciphertext=old)
    row.refresh_from_db()
    with pytest.raises(crypto.CryptoUnavailable):
        crypto.decrypt(row.password_ciphertext, context)


def test_mutable_ledger_rollback_is_detected_by_checkpoint(vault):
    store, secret, _, org, _, _, _ = vault
    key = store.list_versions(org, active=True)[0]
    context = f"secure-mail:v1:organization={org}:smtp-credential=7"
    store.wrap(org, context, secrets.token_bytes(32), key["id"], "worker")
    with closing(sqlite3.connect(store.path)) as db:
        old = db.execute("SELECT digest FROM current_deks WHERE context=?", (context,)).fetchone()[
            0
        ]
    store.wrap(org, context, secrets.token_bytes(32), key["id"], "worker")
    store._clear()
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("UPDATE current_deks SET digest=? WHERE context=?", (old, context))
    with pytest.raises(ValueError, match="protected-state"):
        store.unseal(secret, "custodian")


def test_insert_only_document_context_does_not_get_mutable_guard(vault):
    store, _, _, org, context, dek, wrapper = vault
    key = store.list_versions(org, active=True)[0]
    store.wrap(org, context, secrets.token_bytes(32), key["id"], "worker")
    assert store.unwrap(org, context, wrapper, "worker") == dek
