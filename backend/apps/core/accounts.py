from datetime import timedelta

from django.db import transaction
from django.db.models import Count, Q, Sum
from django.utils import timezone
from rest_framework import serializers
from rest_framework.response import Response

from .auth import invite, recent_mfa, validate
from .company_identity import is_company_address
from .http import Problem, endpoint, unavailable
from .models import (
    Attachment,
    Conversation,
    DeliveryJob,
    IdempotencyRecord,
    Message,
    Organization,
    StaffInvitation,
    StaffUser,
)
from .services import audit, current_staff, idempotency, lock_organization, paginate


class AccountInput(serializers.Serializer):
    name = serializers.CharField(max_length=160)
    email = serializers.EmailField(max_length=254)
    role = serializers.ChoiceField(choices=["staff", "admin"], default="staff")
    can_nophi = serializers.BooleanField(default=False)
    can_manage_privileges = serializers.BooleanField(default=False)
    can_export_audit = serializers.BooleanField(default=False)
    sender_addresses = serializers.ListField(
        child=serializers.EmailField(), max_length=20, default=list
    )

    def validate_email(self, value):
        if not is_company_address(value):
            raise serializers.ValidationError(
                "Staff accounts require an approved company email address."
            )
        return value.lower()


class AccountAction(serializers.Serializer):
    action = serializers.ChoiceField(
        choices=[
            "edit",
            "permissions",
            "suspend",
            "reactivate",
            "deactivate",
            "resend",
            "cancel_invitation",
            "recovery",
            "revoke_sessions",
            "reset_mfa",
        ]
    )
    reason = serializers.CharField(max_length=300)
    name = serializers.CharField(max_length=160, required=False)
    role = serializers.ChoiceField(choices=["staff", "admin"], required=False)
    can_nophi = serializers.BooleanField(required=False)
    can_manage_privileges = serializers.BooleanField(required=False)
    can_export_audit = serializers.BooleanField(required=False)
    sender_addresses = serializers.ListField(
        child=serializers.EmailField(), max_length=20, required=False
    )


def usage_for(users, org, days=30):
    ids = [u.pk for u in users]
    start = timezone.now() - timedelta(days=days)
    values = {
        ident: {
            "protected_messages": 0,
            "secure_requests": 0,
            "normal_messages": 0,
            "staff_replies": 0,
            "recipient_submissions": 0,
            "files_uploaded": 0,
            "bytes_uploaded": 0,
            "retained_bytes": 0,
            "assigned_conversations": 0,
            "pending_notifications": 0,
            "failed_notifications": 0,
        }
        for ident in ids
    }
    conversations = Conversation.objects.filter(organization=org, owner_id__in=ids)
    for row in conversations.values("owner_id").annotate(
        assigned=Count("id"),
        protected_count=Count(
            "id", filter=Q(created_at__gte=start, protected=True, mode="ordinary")
        ),
        requests=Count("id", filter=Q(created_at__gte=start, mode="secure_request")),
        normal=Count("id", filter=Q(created_at__gte=start, protected=False)),
    ):
        values[row["owner_id"]].update(
            assigned_conversations=row["assigned"],
            protected_messages=row["protected_count"],
            secure_requests=row["requests"],
            normal_messages=row["normal"],
        )
    for row in (
        Message.objects.filter(
            conversation__organization=org, staff_id__in=ids, created_at__gte=start
        )
        .values("staff_id")
        .annotate(total=Count("id"))
    ):
        totals = values[row["staff_id"]]
        authored_conversations = (
            totals["protected_messages"] + totals["secure_requests"] + totals["normal_messages"]
        )
        values[row["staff_id"]]["staff_replies"] = max(0, row["total"] - authored_conversations)
    for row in (
        Message.objects.filter(
            conversation__organization=org,
            conversation__owner_id__in=ids,
            grant__isnull=False,
            created_at__gte=start,
        )
        .values("conversation__owner_id")
        .annotate(total=Count("id"))
    ):
        values[row["conversation__owner_id"]]["recipient_submissions"] = row["total"]
    for row in (
        Attachment.objects.filter(
            organization=org, uploader_id__in=ids, message__isnull=False, created_at__gte=start
        )
        .values("uploader_id")
        .annotate(files=Count("id"), size=Sum("size"))
    ):
        values[row["uploader_id"]].update(files_uploaded=row["files"], bytes_uploaded=row["size"])
    for row in (
        Attachment.objects.filter(organization=org, message__conversation__owner_id__in=ids)
        .values("message__conversation__owner_id")
        .annotate(size=Sum("stored_size"))
    ):
        values[row["message__conversation__owner_id"]]["retained_bytes"] = row["size"]
    for row in (
        DeliveryJob.objects.filter(organization=org, actor_id__in=ids)
        .values("actor_id")
        .annotate(
            pending=Count("id", filter=Q(state__in=["queued", "retry", "sending"])),
            failed=Count("id", filter=Q(state__in=["failed", "uncertain"])),
        )
    ):
        values[row["actor_id"]].update(
            pending_notifications=row["pending"], failed_notifications=row["failed"]
        )
    return values


def account_data(user, usage=None):
    return {
        "id": user.pk,
        "name": user.display_name,
        "email": user.email,
        "role": user.role,
        "status": user.status,
        "mfa_confirmed": user.mfa_confirmed,
        "can_nophi": user.can_nophi,
        "can_manage_privileges": user.can_manage_privileges,
        "can_export_audit": user.can_export_audit,
        "sender_addresses": user.sender_addresses,
        "last_login": user.last_login,
        "last_activity": user.last_activity,
        "created_at": user.date_joined,
        "updated_at": user.updated_at,
        "created_by": user.created_by_id,
        "usage": usage or {},
    }


def validate_privileges(actor, data):
    if (
        any(data.get(field) for field in ["can_nophi", "can_manage_privileges", "can_export_audit"])
        or data.get("role") == "admin"
    ):
        if not actor.can_manage_privileges:
            raise Problem("Privilege-management permission is required.", "privilege_denied", 403)
    if data.get("sender_addresses") and not actor.can_manage_privileges:
        raise Problem(
            "Privilege-management permission is required for sender addresses.",
            "privilege_denied",
            403,
        )
    addresses = [email.lower() for email in data.get("sender_addresses", [])]
    if any(not is_company_address(email, actor.organization.domain) for email in addresses):
        raise Problem("Sender addresses must belong to the company domain.")
    return list(dict.fromkeys(addresses))


@endpoint(["GET", "POST"], admin=True)
def accounts(request):
    actor = request.user
    if request.method == "GET":
        query = StaffUser.objects.filter(organization=actor.organization)
        q = request.query_params.get("q", "")[:200].strip()
        if q:
            query = query.filter(
                Q(display_name__icontains=q)
                | Q(email__icontains=q)
                | (Q(pk=int(q)) if q.isdigit() else Q(pk__isnull=True))
            )
        for field in ["status", "role"]:
            if request.query_params.get(field):
                query = query.filter(**{field: request.query_params[field]})
        for field in ["mfa_confirmed", "can_nophi"]:
            if request.query_params.get(field) in {"true", "false"}:
                query = query.filter(**{field: request.query_params[field] == "true"})
        users, meta = paginate(
            query,
            request,
            ordering={
                "name": "display_name",
                "email": "email",
                "role": "role",
                "status": "status",
                "last_login": "last_login",
                "created_at": "date_joined",
            },
            default="-created_at",
        )
        try:
            days = int(request.query_params.get("days", 30))
        except ValueError as exc:
            raise Problem("Invalid usage period.") from exc
        if days not in {7, 30, 90}:
            raise Problem("Usage period must be 7, 30 or 90 days.")
        usage = usage_for(users, actor.organization, days)
        return Response(
            {
                "results": [account_data(u, usage[u.pk]) for u in users],
                **meta,
                "period_days": days,
                "updated_at": timezone.now(),
            }
        )
    recent_mfa(request)
    data = validate(AccountInput, request.data)
    email = data["email"].lower()
    if not is_company_address(email, actor.organization.domain):
        raise Problem("Staff accounts require a company email address.")
    addresses = validate_privileges(actor, data) or [email]
    with transaction.atomic():
        lock_organization(actor.organization_id)
        actor = current_staff(request)
        if actor.role != "admin":
            raise Problem("Administrator access is required.", status=403)
        validate_privileges(actor, data)
        existing, record = idempotency(
            request, actor.organization, f"staff:{actor.pk}", "create_account", data
        )
        if existing:
            return Response({"id": int(existing.resource_id)}, status=200)
        if StaffUser.objects.filter(username=email).exists():
            raise Problem("An account with this email already exists.", "duplicate_account", 409)
        user = StaffUser.objects.create_user(
            username=email,
            email=email,
            password=None,
            display_name=data["name"],
            organization=actor.organization,
            created_by=actor,
            sender_addresses=addresses,
            role=data["role"],
            can_nophi=data["can_nophi"],
            can_manage_privileges=data["can_manage_privileges"],
            can_export_audit=data["can_export_audit"],
        )
        invite(user, actor)
        audit(
            actor.organization,
            actor,
            "account.created",
            "account",
            user.pk,
            metadata={"role": user.role},
        )
        IdempotencyRecord.objects.create(**record, resource_id=str(user.pk))
    return Response({"id": user.pk}, status=201)


@endpoint(["GET", "POST"], admin=True)
def account_detail(request, ident):
    actor = request.user
    target = StaffUser.objects.filter(pk=ident, organization=actor.organization).first()
    if target is None:
        unavailable()
    if request.method == "GET":
        data = account_data(target, usage_for([target], actor.organization)[target.pk])
        invitation = StaffInvitation.objects.filter(user=target).order_by("-created_at").first()
        data["invitation"] = (
            None
            if not invitation
            else {"expires_at": invitation.expires_at, "consumed": bool(invitation.consumed_at)}
        )
        return Response(data)
    recent_mfa(request)
    data = validate(AccountAction, request.data)
    action = data["action"]
    with transaction.atomic():
        Organization.objects.select_for_update().get(pk=actor.organization_id)
        actor = current_staff(request)
        if actor.role != "admin":
            raise Problem("Administrator access is required.", status=403)
        target = StaffUser.objects.select_for_update().get(pk=target.pk)
        existing, record = idempotency(
            request, actor.organization, f"staff:{actor.pk}", f"account:{target.pk}", data
        )
        if existing:
            return Response({"updated": True})
        before = {"role": target.role, "status": target.status, "can_nophi": target.can_nophi}
        if action in {"suspend", "deactivate", "permissions"}:
            removes_admin = action != "permissions" or data.get("role", target.role) != "admin"
            if (
                removes_admin
                and target.role == "admin"
                and target.status == "active"
                and StaffUser.objects.filter(
                    organization=actor.organization, role="admin", status="active"
                ).count()
                <= 1
            ):
                raise Problem("The last active administrator cannot be removed.", "last_admin", 409)
        if target.role == "admin" and not actor.can_manage_privileges and action != "edit":
            raise Problem("Privilege-management permission is required.", status=403)
        removes_manager = action in {"suspend", "deactivate"} or (
            action == "permissions"
            and (
                data.get("role", target.role) != "admin"
                or data.get("can_manage_privileges", target.can_manage_privileges) is False
            )
        )
        if (
            removes_manager
            and target.role == "admin"
            and target.status == "active"
            and target.can_manage_privileges
            and not StaffUser.objects.filter(
                organization=actor.organization,
                role="admin",
                status="active",
                can_manage_privileges=True,
            )
            .exclude(pk=target.pk)
            .exists()
        ):
            raise Problem(
                "Keep at least one active administrator with privilege-management authority.",
                "last_privileged_admin",
                409,
            )
        if action == "edit":
            if "name" not in data:
                raise Problem("Enter a display name.")
            target.display_name = data["name"]
        elif action == "permissions":
            if not actor.can_manage_privileges:
                raise Problem("Privilege-management permission is required.", status=403)
            validate_privileges(actor, data)
            for field in [
                "role",
                "can_nophi",
                "can_manage_privileges",
                "can_export_audit",
                "sender_addresses",
            ]:
                if field in data:
                    setattr(
                        target,
                        field,
                        [a.lower() for a in data[field]]
                        if field == "sender_addresses"
                        else data[field],
                    )
            target.session_version += 1
        elif action in {"suspend", "deactivate", "reactivate"}:
            if action == "reactivate" and target.status not in {"suspended", "deactivated"}:
                raise Problem("Only suspended/deactivated accounts can be reactivated.")
            if action == "suspend" and target.status != "active":
                raise Problem("Only active accounts can be suspended.")
            target.status = {
                "suspend": "suspended",
                "deactivate": "deactivated",
                "reactivate": "active",
            }[action]
            target.session_version += 1
            StaffInvitation.objects.filter(user=target, consumed_at=None).update(
                consumed_at=timezone.now()
            )
            if action == "reactivate":
                if not actor.can_manage_privileges or target.pk == actor.pk:
                    raise Problem(
                        "A different privileged administrator must reactivate accounts.", status=403
                    )
                target.set_unusable_password()
                target.mfa_secret = ""
                target.mfa_confirmed = False
                target.mfa_last_tick = -1
                target.recovery_hashes = []
                invite(target, actor, purpose="password_recovery")
        elif action == "reset_mfa":
            if not actor.can_manage_privileges or target.pk == actor.pk:
                raise Problem("A different privileged administrator must reset MFA.", status=403)
            if target.status != "active":
                raise Problem("MFA reset requires an active account.")
            # Password possession alone must not win the re-enrollment race.
            # The verified employee must consume a fresh emailed recovery link.
            target.set_unusable_password()
            target.mfa_secret = ""
            target.mfa_confirmed = False
            target.mfa_last_tick = -1
            target.recovery_hashes = []
            target.session_version += 1
            StaffInvitation.objects.filter(user=target, consumed_at=None).update(
                consumed_at=timezone.now()
            )
            invite(target, actor, purpose="password_recovery")
        elif action == "revoke_sessions":
            target.session_version += 1
        elif action == "resend":
            if target.status != "invited":
                raise Problem("Only pending invitations can be resent.")
            invite(target, actor)
        elif action == "cancel_invitation":
            if target.status != "invited":
                raise Problem("Only pending invitations can be cancelled.")
            target.status = "deactivated"
            StaffInvitation.objects.filter(user=target, consumed_at=None).update(
                consumed_at=timezone.now()
            )
        elif action == "recovery":
            if target.status != "active":
                raise Problem("Recovery requires an active account.")
            invite(target, actor, purpose="password_recovery")
        target.save()
        IdempotencyRecord.objects.create(**record, resource_id=str(target.pk))
        audit(
            actor.organization,
            actor,
            "account." + action,
            "account",
            target.pk,
            metadata={
                "reason": data["reason"],
                "before": before,
                "after": {
                    "role": target.role,
                    "status": target.status,
                    "can_nophi": target.can_nophi,
                },
            },
        )
    return Response({"updated": True})
