import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160)
    audit_sequence = models.PositiveBigIntegerField(default=0)
    domain = models.CharField(max_length=253, default="onesmarter.com", unique=True)


class AuditSequence(models.Model):
    organization = models.OneToOneField(Organization, on_delete=models.PROTECT, primary_key=True)
    value = models.PositiveBigIntegerField(default=0)


class StaffUser(AbstractUser):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=160)
    role = models.CharField(
        max_length=10, choices=[("staff", "Staff"), ("admin", "Administrator")], default="staff"
    )
    status = models.CharField(
        max_length=12,
        default="invited",
        choices=[(v, v.title()) for v in ("invited", "active", "suspended", "deactivated")],
    )
    can_nophi = models.BooleanField(default=False)
    can_manage_privileges = models.BooleanField(default=False)
    can_export_audit = models.BooleanField(default=False)
    sender_addresses = models.JSONField(default=list)
    session_version = models.PositiveIntegerField(default=0)
    last_activity = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey("self", null=True, on_delete=models.PROTECT)
    mfa_secret = models.TextField(blank=True)
    mfa_confirmed = models.BooleanField(default=False)
    mfa_last_tick = models.BigIntegerField(default=-1)
    recovery_hashes = models.JSONField(default=list)


class StaffInvitation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(StaffUser, on_delete=models.PROTECT)
    token_hash = models.CharField(max_length=64, unique=True)
    purpose = models.CharField(max_length=20, default="activate")
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(default=timezone.now)


class Conversation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    owner = models.ForeignKey(StaffUser, on_delete=models.PROTECT)
    sender = models.EmailField()
    mode = models.CharField(max_length=16, default="ordinary")
    protected = models.BooleanField(default=True)
    routing_reason = models.CharField(max_length=40)
    policy_version = models.CharField(max_length=64, default="2026-10-27-v1")
    subject_ciphertext = models.TextField()
    search_indexed = models.BooleanField(default=False)
    # Historical deadline only; recipient links now remain valid until revoked.
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True)
    state = models.CharField(max_length=20, default="awaiting_recipient")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    last_staff_read = models.DateTimeField(null=True)

    class Meta:
        indexes = [models.Index(fields=["organization", "owner", "-created_at"])]


class RecipientGrant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(Conversation, on_delete=models.PROTECT, related_name="grants")
    email = models.EmailField()
    kind = models.CharField(max_length=3, default="to")
    token_hash = models.CharField(max_length=64, unique=True)
    revoked_at = models.DateTimeField(null=True)
    last_opened = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["conversation", "email"], name="unique_grant_mailbox")
        ]


class RecipientInvitationToken(models.Model):
    """Previous invitation hashes inherit all access restrictions from their grant."""

    grant = models.ForeignKey(
        RecipientGrant, on_delete=models.CASCADE, related_name="invitation_tokens"
    )
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(default=timezone.now)


class Message(models.Model):
    class Meta:
        indexes = [
            models.Index(fields=["conversation", "-created_at", "-id"], name="message_history_page")
        ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(
        Conversation, on_delete=models.PROTECT, related_name="messages"
    )
    staff = models.ForeignKey(StaffUser, null=True, on_delete=models.PROTECT)
    grant = models.ForeignKey(RecipientGrant, null=True, on_delete=models.PROTECT)
    # A staff reply can be private to one recipient; null is visible to all grants.
    audience = models.ForeignKey(
        RecipientGrant, null=True, on_delete=models.PROTECT, related_name="direct_messages"
    )
    body_ciphertext = models.TextField()
    shared = models.BooleanField(default=False)
    mail_headers = models.JSONField(default=dict)
    reply_to_message = models.ForeignKey("self", null=True, on_delete=models.PROTECT)
    created_at = models.DateTimeField(default=timezone.now)


class Attachment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    message = models.ForeignKey(
        Message, null=True, on_delete=models.PROTECT, related_name="attachments"
    )
    uploader = models.ForeignKey(StaffUser, null=True, on_delete=models.PROTECT)
    grant = models.ForeignKey(RecipientGrant, null=True, on_delete=models.PROTECT)
    name_ciphertext = models.TextField()
    search_indexed = models.BooleanField(default=False)
    object_key = models.CharField(max_length=200)
    size = models.PositiveIntegerField()
    stored_size = models.PositiveIntegerField(default=0)
    media_type = models.CharField(max_length=100)
    state = models.CharField(max_length=16, default="pending")
    sha256 = models.CharField(max_length=80, blank=True)
    source_metadata_ciphertext = models.TextField(blank=True)
    evidence_capture = models.ForeignKey("EvidenceCapture", null=True, on_delete=models.PROTECT)
    created_at = models.DateTimeField(default=timezone.now)


class EvidenceCapture(models.Model):
    """One immutable capture per original submission; delivery copies share it."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    sha256 = models.CharField(max_length=80)
    metadata_ciphertext = models.TextField()
    bundle_sha256 = models.CharField(max_length=64)
    provenance = models.CharField(max_length=24)
    created_at = models.DateTimeField(default=timezone.now)
    timestamp_state = models.CharField(max_length=16, default="pending")
    timestamp_sha256 = models.CharField(max_length=64, blank=True)
    timestamp_checked_at = models.DateTimeField(null=True)

    class Meta:
        indexes = [models.Index(fields=["organization", "-created_at"])]


class OTPChallenge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    grant = models.ForeignKey(RecipientGrant, on_delete=models.PROTECT)
    verifier = models.CharField(max_length=64)
    attempts = models.PositiveSmallIntegerField(default=0)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(default=timezone.now)


class RecipientSession(models.Model):
    created_at = models.DateTimeField(default=timezone.now)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    grant = models.ForeignKey(RecipientGrant, on_delete=models.PROTECT)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)


class IdempotencyRecord(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    actor = models.CharField(max_length=100)
    operation = models.CharField(max_length=150)
    key = models.CharField(max_length=100)
    fingerprint = models.CharField(max_length=64)
    resource_id = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "actor", "operation", "key"], name="unique_submission"
            )
        ]


class DeliveryJob(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    actor = models.ForeignKey(StaffUser, null=True, on_delete=models.PROTECT)
    conversation = models.ForeignKey(
        Conversation, null=True, on_delete=models.PROTECT, related_name="delivery_jobs"
    )
    grant = models.ForeignKey(RecipientGrant, null=True, on_delete=models.PROTECT)
    payload_ciphertext = models.TextField()
    state = models.CharField(max_length=32, default="queued")
    attempts = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=50, blank=True)
    next_attempt = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["state", "next_attempt"])]


class ImmutableQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("Audit events cannot be updated.")

    def delete(self):
        raise ValueError("Audit events cannot be deleted.")

    def bulk_update(self, *args, **kwargs):
        raise ValueError("Audit events cannot be updated.")


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    sequence = models.PositiveBigIntegerField(default=0)
    actor_id = models.CharField(max_length=100)
    actor_label = models.CharField(max_length=180)
    actor_role = models.CharField(max_length=30)
    action = models.CharField(max_length=80)
    target_type = models.CharField(max_length=40)
    target_id = models.CharField(max_length=100)
    outcome = models.CharField(max_length=16, default="success")
    metadata = models.JSONField(default=dict)
    occurred_at = models.DateTimeField(default=timezone.now)
    objects = ImmutableQuerySet.as_manager()

    class Meta:
        indexes = [
            models.Index(fields=["organization", "-occurred_at", "id"]),
            models.Index(fields=["organization", "actor_id", "action"]),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Audit events cannot be updated.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("Audit events cannot be deleted.")


class AuditBatch(models.Model):
    """Historical archive schema only; no runtime writer after archive removal."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    sequence = models.PositiveBigIntegerField()
    previous_digest = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)
    payload = models.TextField()
    retain_until = models.DateTimeField()
    version_id = models.CharField(max_length=300, blank=True)
    archived_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "sequence"], name="unique_audit_batch_sequence"
            )
        ]


class AuditArchive(models.Model):
    """Preserved historical references; never used for new audit events."""

    batch = models.ForeignKey(AuditBatch, null=True, on_delete=models.PROTECT)
    event = models.OneToOneField(
        AuditEvent, on_delete=models.PROTECT, primary_key=True, related_name="archive"
    )
    object_key = models.CharField(max_length=200)
    version_id = models.CharField(max_length=300)
    digest = models.CharField(max_length=64)
    retain_until = models.DateTimeField()
    archived_at = models.DateTimeField(default=timezone.now)


class AuditExport(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    owner = models.ForeignKey(StaffUser, on_delete=models.PROTECT)
    filters = models.JSONField(default=dict)
    snapshot = models.DateTimeField()
    high_water = models.PositiveBigIntegerField(default=0)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now)


class RateBucket(models.Model):
    key = models.CharField(max_length=100, primary_key=True)
    credits = models.BigIntegerField(default=0)
    refilled_at = models.DateTimeField(null=True, db_index=True)


class WrappingKeyVersion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    suite = models.CharField(max_length=100)
    state = models.CharField(
        max_length=20,
        default="active",
        choices=[("active", "Active"), ("decrypt_only", "Decrypt only")],
    )
    pq_public = models.TextField()
    classical_public = models.TextField()
    private_ciphertext = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization"],
                condition=models.Q(state="active"),
                name="one_active_wrapping_key",
            )
        ]


class OrganizationSMTP(models.Model):
    organization = models.OneToOneField(Organization, on_delete=models.PROTECT, primary_key=True)
    host = models.CharField(max_length=253)
    sender_name = models.CharField(max_length=160, default="OneSmarter Support")
    port = models.PositiveIntegerField(default=587)
    security = models.CharField(max_length=12, default="starttls")
    enabled = models.BooleanField(default=True)
    revision = models.PositiveIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)


class StaffSMTP(models.Model):
    user = models.OneToOneField(StaffUser, on_delete=models.PROTECT, primary_key=True)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    email = models.EmailField()
    password_ciphertext = models.TextField()
    transport_revision = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "email"], name="unique_org_smtp_sender")
        ]


class DirectChat(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    owner = models.ForeignKey(StaffUser, on_delete=models.PROTECT)
    recipient_email = models.EmailField()
    conversation = models.OneToOneField(Conversation, on_delete=models.PROTECT)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "recipient_email"], name="unique_staff_recipient_chat"
            )
        ]


class GroupChat(models.Model):
    owner = models.ForeignKey(StaffUser, on_delete=models.PROTECT)
    participants_hash = models.CharField(max_length=64)
    conversation = models.OneToOneField(Conversation, on_delete=models.PROTECT)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "participants_hash"], name="unique_staff_group_chat"
            )
        ]


class MetadataToken(models.Model):
    """HMAC word index; authorization remains on the original resource query."""

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    kind = models.CharField(max_length=12)
    resource_id = models.UUIDField()
    token = models.CharField(max_length=64)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "kind", "resource_id", "token"], name="unique_metadata_word"
            )
        ]
        indexes = [
            models.Index(fields=["organization", "kind", "token"], name="metadata_word_lookup")
        ]


class LoginFailureState(models.Model):
    user = models.OneToOneField(StaffUser, on_delete=models.CASCADE, primary_key=True)
    failures = models.PositiveIntegerField(default=0)
    window_started = models.DateTimeField(default=timezone.now)


# Register the independently scoped integration inbox models.
from .portal_models import (  # noqa: E402,F401
    IntegrationNonce,
    PortalChallenge,
    PortalMailbox,
    PortalMessage,
    PortalParticipant,
    PortalSession,
    PortalThread,
)
