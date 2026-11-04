from django.core.management.base import BaseCommand, CommandError

from backend.apps.core import crypto, search_index
from backend.apps.core.models import Attachment, Conversation


class Command(BaseCommand):
    help = "Rebuild HMAC metadata word tokens; requires available decryption keys."

    def handle(self, **options):
        total = 0
        self.failed = 0
        for model in (Conversation, Attachment):
            model.objects.update(search_indexed=False)
        for model, field, kind in (
            (Conversation, "subject_ciphertext", "conversation-subject"),
            (Attachment, "name_ciphertext", "filename"),
        ):
            # Safe restart after interruption: rebuild every resource deterministically.
            # Mark stale rows first so search never silently omits old data.
            batch = []
            for item in model.objects.order_by("organization_id", "pk").iterator(chunk_size=25):
                if batch and (len(batch) == 25 or item.organization_id != batch[0].organization_id):
                    total += self.flush(batch, field, kind)
                    batch = []
                batch.append(item)
            total += self.flush(batch, field, kind)
        self.stdout.write(f"Indexed {total} resources; {self.failed} unavailable.")
        if self.failed:
            raise CommandError(
                "Some encrypted metadata is unavailable. Restore access to its keys and rerun; original content was not changed."
            )

    def flush(self, batch, field, kind):
        pairs = [
            (getattr(item, field), crypto.context(item.organization_id, kind, item.pk))
            for item in batch
        ]
        try:
            values = crypto.decrypt_many(pairs)
        except crypto.CryptoUnavailable:
            # One legacy/corrupt envelope must not prevent the remaining resources
            # from being indexed. Do not print plaintext or encrypted envelopes.
            values = []
            for pair in pairs:
                try:
                    values.append(crypto.decrypt(*pair))
                except crypto.CryptoUnavailable:
                    values.append(None)
                    self.failed += 1
        for item, value in zip(batch, values, strict=True):
            if value is not None:
                search_index.index_value(item, value.decode())
        return sum(value is not None for value in values)
