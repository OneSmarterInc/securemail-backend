"""Offline synthetic custody cutover. Stop all application writers and back up first."""

import hashlib
import json
import secrets
import uuid

from django.db import transaction
from django.test.utils import override_settings

from . import crypto, keyring, storage
from .conversations import attachment_context, message_context, subject_context
from .models import (
    Attachment,
    Conversation,
    DeliveryJob,
    EvidenceCapture,
    Message,
    StaffSMTP,
    StaffUser,
    WrappingKeyVersion,
)
from .portal_models import PortalMailbox, PortalMessage, PortalThread


def envelopes(org):
    specs = [
        (
            PortalMailbox.objects.filter(organization=org),
            "email_ciphertext",
            lambda x: crypto.context(org.pk, "portal-email", x.pk),
        ),
        (
            PortalThread.objects.filter(organization=org),
            "metadata_ciphertext",
            lambda x: crypto.context(org.pk, "portal-thread", x.pk),
        ),
        (
            PortalMessage.objects.filter(thread__organization=org),
            "body_ciphertext",
            lambda x: crypto.context(org.pk, "portal-message", x.pk),
        ),
        (
            EvidenceCapture.objects.filter(organization=org),
            "metadata_ciphertext",
            lambda x: crypto.context(org.pk, "evidence-metadata", x.pk),
        ),
        (
            Attachment.objects.filter(organization=org),
            "source_metadata_ciphertext",
            lambda x: crypto.context(org.pk, "source-metadata", x.pk),
        ),
        (
            StaffSMTP.objects.filter(organization=org),
            "password_ciphertext",
            lambda x: crypto.context(org.pk, "smtp-credential", x.user_id),
        ),
        (Conversation.objects.filter(organization=org), "subject_ciphertext", subject_context),
        (
            Message.objects.filter(conversation__organization=org),
            "body_ciphertext",
            message_context,
        ),
        (
            StaffUser.objects.filter(organization=org),
            "mfa_secret",
            lambda x: crypto.context(org.pk, "mfa", x.pk),
        ),
        (
            DeliveryJob.objects.filter(organization=org),
            "payload_ciphertext",
            lambda x: crypto.context(org.pk, "delivery", x.pk),
        ),
        (
            Attachment.objects.filter(organization=org).exclude(state="deleted"),
            "name_ciphertext",
            lambda x: crypto.context(org.pk, "filename", x.pk),
        ),
    ]
    for rows, field, context_fn in specs:
        for row in rows.iterator():
            value = getattr(row, field)
            if value:
                yield row, field, value, context_fn(row)
            if isinstance(row, Attachment) and field == "name_ciphertext":
                yield row, "object", storage.get(row.object_key).decode(), attachment_context(row)

    from .evidence import context, path_for

    for capture in EvidenceCapture.objects.filter(organization=org):
        yield capture, "evidence_bundle", path_for(capture).read_text(), context(capture)
        if capture.timestamp_state == "verified":
            yield (
                capture,
                "evidence_timestamp",
                path_for(capture, "timestamp").read_text(),
                context(capture, "evidence-timestamp"),
            )


def migrate(org, maintenance, workload, *, preserve_legacy=False):
    """Preserve file ciphertext; register existing MFA DEKs via normal authenticated wrap.

    All local data is authenticated before any remote mutation. Remote imports are
    repeatable. Database changes commit together only after every plaintext matches.
    Caller supplies distinct scoped identities; neither credentials nor plaintext
    are returned. Caller must retain an offline rollback backup until verification.
    """
    rows = list(WrappingKeyVersion.objects.filter(organization=org))
    with override_settings(KEY_PROTECTOR="local-development"):
        material = [(row, keyring.private_keys(row)) for row in rows]
        expected = {}
        legacy = []
        for row, field, value, context in envelopes(org):
            envelope = json.loads(value)
            if (
                preserve_legacy
                and set(envelope)
                == (crypto.protocol.WRAPPER - {"auth", "auth_v"}) | {"nonce", "data"}
                and envelope.get("v") == 2
                and envelope.get("suite") == keyring.SUITE
            ):
                legacy.append(
                    {
                        "model": row._meta.label,
                        "id": str(row.pk),
                        "field": field,
                        "ciphertext_sha256": hashlib.sha256(value.encode()).hexdigest(),
                    }
                )
                continue
            expected[(row._meta.label, str(row.pk), field)] = hashlib.sha256(
                crypto.decrypt(value, context)
            ).digest()
    imported = []
    for row, (pq, classical) in material:
        meta = maintenance.call(
            "import",
            organization=str(org.pk),
            key_id=str(row.pk),
            private=keyring.encode(pq.private_bytes_raw() + classical.private_bytes_raw()),
        )
        if meta["pq_public"] != row.pq_public or meta["classical_public"] != row.classical_public:
            raise ValueError("Imported public key mismatch")
        imported.append(meta)
    active = maintenance.call("versions", organization=str(org.pk), active=True)["versions"]
    destination = (
        active[0]
        if active
        else maintenance.call(
            "rotate", organization=str(org.pk), expected=None, request_id=str(uuid.uuid4())
        )
    )
    with transaction.atomic():
        verified = 0
        for row, field, original, context in envelopes(org):
            if (row._meta.label, str(row.pk), field) not in expected:
                continue
            envelope = json.loads(original)
            # Local MFA has no service anti-replay pin. Authenticate locally first,
            # then wrap the same DEK through the workload to establish that pin.
            if isinstance(row, StaffUser):
                with override_settings(KEY_PROTECTOR="local-development"):
                    dek = crypto.unwrap(envelope, context)
                wrapper = workload.call(
                    "wrap",
                    organization=str(org.pk),
                    context=context,
                    dek=crypto.b64(dek),
                    expected=destination["id"],
                )
                envelope = {**wrapper, "nonce": envelope["nonce"], "data": envelope["data"]}
                setattr(row, field, crypto.canonical(envelope).decode())
                row.save(update_fields=[field])
            wrapper = {k: envelope[k] for k in crypto.protocol.WRAPPER}
            dek = crypto.protocol.decode(
                workload.call("unwrap", organization=str(org.pk), context=context, wrapper=wrapper)[
                    "dek"
                ],
                32,
            )
            plain = crypto.AESGCM(dek).decrypt(
                crypto.unb64(envelope["nonce"]), crypto.unb64(envelope["data"]), context.encode()
            )
            actual = hashlib.sha256(plain).digest()
            if not secrets.compare_digest(actual, expected[(row._meta.label, str(row.pk), field)]):
                raise ValueError("Migrated plaintext mismatch")
            verified += 1
        for meta in imported:
            keyring.synchronize(meta)
        keyring.synchronize(destination)
    crypto._local_key.cache_clear()
    keyring.clear_remote_cache()
    return {
        "imported_versions": len(imported),
        "verified_envelopes": verified,
        "preserved_unreadable_legacy": legacy,
    }
