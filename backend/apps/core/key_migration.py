"""Resumable per-record rewrapping with atomic database pointers and retained old versions."""

import json
import uuid

from django.db import transaction

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
)
from .portal_models import PortalMailbox, PortalMessage, PortalThread
from .services import audit, lock_organization


def needs_rewrap(value, key_id):
    if not value:
        return False
    envelope = json.loads(value)
    return (
        envelope.get("v") != 2
        or envelope.get("auth_v") != 1
        or "auth" not in envelope
        or envelope.get("key_id") != str(key_id)
    )


def migrate(org, *, apply=False, limit=100):
    active = keyring.active_key(org.pk)
    totals = {
        "candidates": 0,
        "updated": 0,
        "skipped_legacy": 0,
        "skipped_invalid": 0,
        "skipped_crypto_unavailable": 0,
    }
    specs = [
        (
            PortalMailbox,
            "organization",
            [("email_ciphertext", lambda x: crypto.context(org.pk, "portal-email", x.pk))],
        ),
        (
            PortalThread,
            "organization",
            [("metadata_ciphertext", lambda x: crypto.context(org.pk, "portal-thread", x.pk))],
        ),
        (
            PortalMessage,
            "thread__organization",
            [("body_ciphertext", lambda x: crypto.context(org.pk, "portal-message", x.pk))],
        ),
        (
            EvidenceCapture,
            "organization",
            [("metadata_ciphertext", lambda x: crypto.context(org.pk, "evidence-metadata", x.pk))],
        ),
        (
            StaffSMTP,
            "organization",
            [
                (
                    "password_ciphertext",
                    lambda x: crypto.context(org.pk, "smtp-credential", x.user_id),
                )
            ],
        ),
        (Conversation, "organization", [("subject_ciphertext", subject_context)]),
        (Message, "conversation__organization", [("body_ciphertext", message_context)]),
        (
            StaffUser,
            "organization",
            [("mfa_secret", lambda x: crypto.context(org.pk, "mfa", x.pk))],
        ),
        (
            DeliveryJob,
            "organization",
            [("payload_ciphertext", lambda x: crypto.context(org.pk, "delivery", x.pk))],
        ),
        (
            Attachment,
            "organization",
            [
                ("name_ciphertext", lambda x: crypto.context(org.pk, "filename", x.pk)),
                (
                    "source_metadata_ciphertext",
                    lambda x: crypto.context(org.pk, "source-metadata", x.pk),
                ),
            ],
        ),
    ]
    for model, org_field, fields in specs:
        for ident in (
            model.objects.filter(**{org_field: org})
            .order_by("pk")
            .values_list("pk", flat=True)
            .iterator(chunk_size=100)
        ):
            with transaction.atomic():
                lock_organization(org)
                current = keyring.active_key(org.pk)
                if current.pk != active.pk:
                    raise ValueError(
                        "A key rotated during migration. Restart against the current active version."
                    )
                obj = model.objects.select_for_update().get(pk=ident)
                updates = {}
                if model is Attachment and obj.state == "deleted":
                    continue
                try:
                    originals = [getattr(obj, field) for field, _ in fields]
                    original_file = (
                        storage.get(obj.object_key).decode() if model is Attachment else None
                    )
                    if original_file:
                        originals.append(original_file)
                    parsed = [json.loads(value) for value in originals if value]
                    if any(not isinstance(value, dict) for value in parsed):
                        raise ValueError("Invalid envelope")
                    if any(
                        value.get("v") == 2 and (value.get("auth_v") != 1 or "auth" not in value)
                        for value in parsed
                    ):
                        totals["skipped_legacy"] += 1
                        continue
                except (ValueError, UnicodeError):
                    totals["skipped_invalid"] += 1
                    continue
                try:
                    for field, context_fn in fields:
                        original = getattr(obj, field)
                        if needs_rewrap(original, active.pk):
                            updates[field] = (
                                crypto.rewrap(original, context_fn(obj)) if apply else original
                            )
                    if model is Attachment:
                        if needs_rewrap(original_file, active.pk):
                            if apply:
                                envelope = crypto.rewrap(
                                    original_file, attachment_context(obj)
                                ).encode()
                                new_key = f"{org.pk}/rewrapped/{obj.pk}/{uuid.uuid4()}"
                                storage.put(new_key, envelope)
                                # Retain old objects until approved cleanup permits deletion.
                                updates.update(object_key=new_key, stored_size=len(envelope))
                            else:
                                updates["object_key"] = obj.object_key
                except crypto.CryptoUnavailable:
                    # Do not replace any part of this record or infer that a
                    # service outage is a legacy envelope. Later records may work.
                    totals["skipped_crypto_unavailable"] += 1
                    continue
                if updates:
                    totals["candidates"] += 1
                    if apply:
                        for field, value in updates.items():
                            setattr(obj, field, value)
                        obj.save(update_fields=list(updates))
                        audit(
                            org,
                            None,
                            "key.envelope_rewrapped",
                            model._meta.model_name,
                            obj.pk,
                            metadata={"destination_key": str(active.pk)},
                        )
                        totals["updated"] += 1
                    if totals["candidates"] >= limit:
                        return totals
    return totals
