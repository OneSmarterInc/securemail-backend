"""Partner portal records; content uses the existing envelope encryption service."""

import uuid

from django.db import models
from django.utils import timezone

from .models import Organization, StaffUser


class PortalMailbox(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    email_hash = models.CharField(max_length=64)
    email_ciphertext = models.TextField()
    disabled_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "email_hash"], name="portal_mailbox_identity"
            )
        ]


class PortalThread(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    owner = models.ForeignKey(StaffUser, on_delete=models.PROTECT)
    source = models.CharField(max_length=64)
    external_id = models.CharField(max_length=100)
    fingerprint = models.CharField(max_length=64)
    metadata_ciphertext = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now, db_index=True)
    revoked_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["source", "external_id"], name="portal_source_request")
        ]


class PortalParticipant(models.Model):
    thread = models.ForeignKey(PortalThread, on_delete=models.PROTECT, related_name="participants")
    mailbox = models.ForeignKey(PortalMailbox, on_delete=models.PROTECT, related_name="memberships")
    role = models.CharField(max_length=16)
    last_read = models.DateTimeField(null=True)
    revoked_at = models.DateTimeField(null=True)
    suppress_notifications = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["thread", "mailbox"], name="portal_thread_member")
        ]


class PortalMessage(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    thread = models.ForeignKey(PortalThread, on_delete=models.PROTECT, related_name="messages")
    sender = models.ForeignKey(PortalMailbox, null=True, on_delete=models.PROTECT)
    body_ciphertext = models.TextField()
    submission_key = models.CharField(max_length=100)
    fingerprint = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["thread", "submission_key", "sender"], name="portal_reply_idempotency"
            )
        ]
        indexes = [models.Index(fields=["thread", "created_at"])]


class PortalChallenge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mailbox = models.ForeignKey(PortalMailbox, on_delete=models.PROTECT)
    verifier = models.CharField(max_length=64)
    attempts = models.PositiveSmallIntegerField(default=0)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(default=timezone.now)


class PortalSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mailbox = models.ForeignKey(PortalMailbox, on_delete=models.PROTECT)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)


class IntegrationNonce(models.Model):
    source = models.CharField(max_length=64)
    nonce = models.CharField(max_length=64)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["source", "nonce"], name="integration_nonce_once")
        ]
