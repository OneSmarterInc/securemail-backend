"""Request-local preparation before taking the organization submission lock.

Evidence is committed against the durable staged attachment. It remains hidden
until submission; interrupted preparation is safely reusable on the next attempt.
Plaintext never persists here beyond the request.
"""

from django.conf import settings
from django.db import transaction

from . import crypto, storage
from .models import Attachment


def fingerprint(row):
    return (row.object_key, row.sha256, row.name_ciphertext, row.source_metadata_ciphertext)


def prepare(ids, *, user=None, grant=None):
    from .conversations import attachment_context
    from .evidence import capture_attachment

    prepared = {}
    from .http import Problem

    total = 0
    # Only a single attachment row is locked during slow evidence I/O, never
    # the organization. Finalization rechecks authority, state and this snapshot.
    for ident in sorted(set(str(value) for value in ids)):
        with transaction.atomic():
            row = (
                Attachment.objects.select_for_update()
                .filter(
                    pk=ident,
                    message=None,
                    state="available",
                    uploader=user,
                    grant=grant,
                    organization_id=user.organization_id
                    if user
                    else grant.conversation.organization_id,
                )
                .first()
            )
            if row is None:
                continue  # Final transaction handles idempotent replays or rejects.
            total += row.size
            if total > settings.MAX_UPLOAD_BYTES:
                raise Problem("Attachments exceed the combined size limit.")
            plaintext = crypto.decrypt(
                storage.get(row.object_key).decode(), attachment_context(row)
            )
            capture_attachment(row, plaintext)
            prepared[str(row.pk)] = (fingerprint(row), plaintext)
    return prepared
