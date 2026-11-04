"""Scoped HMAC word search. No plaintext, DEKs or order-preserving index."""

import hashlib
import hmac
import re

from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from . import crypto
from .models import Attachment, Conversation, MetadataToken


def words(value):
    return set(re.findall(r"\w+", value.casefold()))


def token(org, word):
    if not settings.SEARCH_INDEX_KEY:
        raise crypto.CryptoUnavailable("Search index key is not configured.")
    return hmac.new(
        settings.SEARCH_INDEX_KEY.encode(),
        f"secure-mail:metadata-word:v1:{org}:{word}".encode(),
        hashlib.sha256,
    ).hexdigest()


def ids(org, kind, word):
    return MetadataToken.objects.filter(
        organization_id=org, kind=kind, token=token(org, word)
    ).values("resource_id")


def index_value(instance, plaintext):
    kind = "subject" if isinstance(instance, Conversation) else "filename"
    with transaction.atomic():
        # Serialize concurrent refreshes of this resource's token set.
        type(instance).objects.select_for_update().get(pk=instance.pk)
        MetadataToken.objects.filter(
            organization_id=instance.organization_id, kind=kind, resource_id=instance.pk
        ).delete()
        MetadataToken.objects.bulk_create(
            [
                MetadataToken(
                    organization_id=instance.organization_id,
                    kind=kind,
                    resource_id=instance.pk,
                    token=token(instance.organization_id, word),
                )
                for word in words(plaintext)
            ]
        )
        type(instance).objects.filter(pk=instance.pk).update(search_indexed=True)
        instance.search_indexed = True


@receiver(post_save, sender=Conversation)
@receiver(post_save, sender=Attachment)
def index_saved(sender, instance, raw=False, **kwargs):
    if raw or instance.search_indexed:
        return
    kind = "conversation-subject" if sender is Conversation else "filename"
    ciphertext = instance.subject_ciphertext if sender is Conversation else instance.name_ciphertext
    if ciphertext:
        index_value(
            instance,
            crypto.decrypt(
                ciphertext, crypto.context(instance.organization_id, kind, instance.pk)
            ).decode(),
        )
