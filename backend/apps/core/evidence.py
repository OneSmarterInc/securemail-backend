"""Local append-only evidence bundles. Local preservation is not cloud WORM."""

import base64
import csv
import hashlib
import http.client
import io
import json
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.response import Response

from . import crypto, document_service, integrity
from .evidence_transport import checked_url, retrieve
from .http import Problem, endpoint, unavailable
from .models import Attachment, EvidenceCapture, Message
from .services import audit, rate_limit


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def context(capture, purpose="evidence"):
    return crypto.context(capture.organization_id, purpose, capture.pk)


def path_for(capture, suffix="bundle") -> Path:
    return settings.EVIDENCE_DIRECTORY / str(capture.organization_id) / f"{capture.pk}.{suffix}"


def preserve(path: Path, value: bytes):
    """Publish a complete fsynced file without ever replacing an existing path."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Atomic create-only publication; an existing path is an error.
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def source_metadata(request) -> dict:
    source = str(request.data.get("source_url", "")).strip()
    claimed = str(request.data.get("downloaded_at", "")).strip()
    if not source and not claimed:
        return {"source_url": None, "downloaded_at": None, "provenance": "upload_only"}
    if not source or not claimed:
        raise Problem(
            "Source URL and original download time are required for each file.",
            "source_metadata_required",
        )
    try:
        checked_url(source)
        when = parse_datetime(claimed)
        if claimed and (when is None or timezone.is_naive(when) or when > timezone.now()):
            raise ValueError("Download time must include a timezone and cannot be in the future.")
    except ValueError as exc:
        raise Problem(str(exc)) from None
    return {
        "source_url": source or None,
        "downloaded_at": when.isoformat() if when else None,
        "provenance": "uploader_declared" if source or claimed else "upload_only",
    }


def capture_attachment(attachment, plaintext: bytes, *, legacy=False):
    """Called within the attachment finalization transaction, after authorization/validation."""
    if attachment.evidence_capture_id:
        if not integrity.matches(attachment.organization_id, plaintext, attachment.sha256):
            raise Problem("File integrity verification failed.", "integrity_failed", 503)
        return attachment.evidence_capture
    file_digest = digest(plaintext)
    if attachment.sha256 and not integrity.matches(
        attachment.organization_id, plaintext, attachment.sha256
    ):
        raise Problem("File integrity verification failed.", "integrity_failed", 503)
    metadata = (
        json.loads(
            crypto.decrypt(
                attachment.source_metadata_ciphertext,
                crypto.context(attachment.organization_id, "source-metadata", attachment.pk),
            )
        )
        if attachment.source_metadata_ciphertext
        else {
            "source_url": None,
            "downloaded_at": None,
            "provenance": "legacy_unknown" if legacy else "upload_only",
        }
    )
    capture = EvidenceCapture(
        organization_id=attachment.organization_id,
        sha256=integrity.tag(attachment.organization_id, plaintext),
        provenance=metadata["provenance"],
    )
    ordinary_upload = (
        bool(attachment.source_metadata_ciphertext) and metadata.get("provenance") == "upload_only"
    )
    if (
        not legacy
        and not ordinary_upload
        and (not metadata.get("source_url") or not metadata.get("downloaded_at"))
    ):
        raise Problem(
            "This staged file has no source URL or download time. Upload it again with both details.",
            "source_metadata_required",
        )
    manifest = {
        "schema": 1,
        "capture_id": str(capture.pk),
        "organization_id": str(attachment.organization_id),
        "original_attachment_id": str(attachment.pk),
        "filename": crypto.decrypt(
            attachment.name_ciphertext,
            crypto.context(attachment.organization_id, "filename", attachment.pk),
        ).decode(),
        "sha256": file_digest,
        "size": len(plaintext),
        "media_type": attachment.media_type,
        "portal_uploaded_at": attachment.created_at.isoformat(),
        "catalogued_at": capture.created_at.isoformat(),
        "hash_computed_at": timezone.now().isoformat(),
        **metadata,
        "preservation": "local_append_only_not_worm",
    }
    bundle = canonical({"manifest": manifest, "file_base64": base64.b64encode(plaintext).decode()})
    encrypted = crypto.encrypt(bundle, context(capture)).encode()
    capture.bundle_sha256 = digest(encrypted)
    capture.metadata_ciphertext = crypto.encrypt(
        canonical(manifest), context(capture, "evidence-metadata")
    )
    preserve(path_for(capture), encrypted)
    capture.save()
    attachment.evidence_capture = capture
    attachment.sha256 = capture.sha256
    attachment.save(update_fields=["evidence_capture", "sha256"])
    audit(
        attachment.organization_id,
        attachment.uploader_id or attachment.grant_id,
        "evidence.captured",
        "evidence_capture",
        capture.pk,
        metadata={"provenance": capture.provenance, "preservation": "local_not_worm"},
    )
    return capture


def read_bundle(capture) -> tuple[dict, bytes]:
    document_service.require_ready()
    raw = path_for(capture).read_bytes()
    if digest(raw) != capture.bundle_sha256:
        raise ValueError("Evidence ciphertext digest mismatch.")
    bundle = json.loads(crypto.decrypt(raw.decode(), context(capture)))
    manifest = bundle["manifest"]
    content = base64.b64decode(bundle["file_base64"], validate=True)
    if (
        manifest["capture_id"] != str(capture.pk)
        or manifest["organization_id"] != str(capture.organization_id)
        or digest(content) != manifest["sha256"]
        or not integrity.matches(capture.organization_id, content, capture.sha256)
        or len(content) != manifest["size"]
    ):
        raise ValueError("Evidence manifest or original-file digest mismatch.")
    return manifest, content


def openssl(*args):
    try:
        result = subprocess.run(
            [settings.EVIDENCE_OPENSSL, "ts", *map(str, args)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
            env={
                **os.environ,
                "OPENSSL_CONF": str(Path(__file__).with_name("evidence-openssl.cnf")),
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Timestamp verifier unavailable.") from exc
    if result.returncode:
        raise ValueError("Timestamp request or signature verification failed.")
    return result.stdout


def verify_timestamp(manifest: dict, proof: dict):
    if not settings.EVIDENCE_TSA_CA_FILE:
        raise ValueError("An approved timestamp trust bundle is required.")
    with tempfile.TemporaryDirectory(prefix="evidence-ts-") as directory:
        root = Path(directory)
        (root / "query").write_bytes(base64.b64decode(proof["query"], validate=True))
        (root / "reply").write_bytes(base64.b64decode(proof["reply"], validate=True))
        # Verify both the original nonce-bearing request and the current manifest digest.
        common = ["-in", root / "reply", "-CAfile", settings.EVIDENCE_TSA_CA_FILE]
        openssl("-verify", "-queryfile", root / "query", *common)
        openssl("-verify", "-digest", digest(canonical(manifest)), *common)


def timestamp_capture(ident):
    if not settings.EVIDENCE_TSA_URL or not settings.EVIDENCE_TSA_CA_FILE:
        raise ValueError("Trusted timestamping is not configured.")
    with transaction.atomic():
        capture = EvidenceCapture.objects.select_for_update().get(pk=ident)
        if capture.timestamp_state == "verified":
            return
        manifest, _ = read_bundle(capture)
        receipt_path = path_for(capture, "timestamp")
        if receipt_path.exists():
            encrypted = receipt_path.read_bytes()
            proof = json.loads(
                crypto.decrypt(encrypted.decode(), context(capture, "evidence-timestamp"))
            )
        else:
            with tempfile.TemporaryDirectory(prefix="evidence-ts-") as directory:
                query = Path(directory) / "query"
                openssl(
                    "-query",
                    "-sha256",
                    "-digest",
                    digest(canonical(manifest)),
                    "-cert",
                    "-out",
                    query,
                )
                request = query.read_bytes()
            reply, _, media_type = retrieve(
                settings.EVIDENCE_TSA_URL, limit=1024 * 1024, body=request
            )
            if media_type.split(";", 1)[0].strip().lower() != "application/timestamp-reply":
                raise ValueError("Invalid timestamp response media type.")
            proof = {
                "query": base64.b64encode(request).decode(),
                "reply": base64.b64encode(reply).decode(),
                "manifest_sha256": digest(canonical(manifest)),
                "tsa_url": settings.EVIDENCE_TSA_URL,
            }
            verify_timestamp(manifest, proof)
            encrypted = crypto.encrypt(
                canonical(proof), context(capture, "evidence-timestamp")
            ).encode()
            preserve(receipt_path, encrypted)
        verify_timestamp(manifest, proof)
        capture.timestamp_state = "verified"
        capture.timestamp_sha256 = digest(encrypted)
        capture.timestamp_checked_at = timezone.now()
        capture.save(update_fields=["timestamp_state", "timestamp_sha256", "timestamp_checked_at"])
        audit(
            capture.organization_id,
            "timestamp-worker",
            "evidence.timestamp_verified",
            "evidence_capture",
            capture.pk,
        )


def authorized_attachments(user):
    from .conversations import staff_visible_messages

    messages = staff_visible_messages(
        Message.objects.filter(
            conversation__owner=user, conversation__organization_id=user.organization_id
        )
    )
    return Attachment.objects.filter(message__in=messages, state="available")


def authorized_captures(user):
    ids = authorized_attachments(user).values("evidence_capture_id")
    return EvidenceCapture.objects.filter(organization_id=user.organization_id, pk__in=ids)


def document_table(request, page):
    """Sort the authorized document set before pagination; decrypt metadata in batches."""
    from .conversations import subject_context

    ordering = request.query_params.get("sort", "-uploaded_at")
    field = ordering.removeprefix("-")
    if field not in {"filename", "conversation", "sender", "uploaded_at", "download"}:
        raise Problem("Invalid document sort column.")
    from django.db.models import CharField, F, Q, Value
    from django.db.models.functions import Coalesce, Lower, NullIf

    from . import search_index
    from .services import rate_limit

    rate_limit(request, "document_table", str(request.user.pk), maximum=60, seconds=60)
    query = authorized_attachments(request.user)
    search = request.query_params.get("q", "").strip()
    if len(search) > 200:
        raise Problem("Search is limited to 200 characters.")
    if search:
        if query.filter(
            Q(search_indexed=False) | Q(message__conversation__search_indexed=False)
        ).exists():
            raise Problem(
                "Document search index needs rebuilding.", "search_index_unavailable", 503
            )
        for word in search_index.words(search):
            query = query.filter(
                Q(pk__in=search_index.ids(request.user.organization_id, "filename", word))
                | Q(
                    message__conversation_id__in=search_index.ids(
                        request.user.organization_id, "subject", word
                    )
                )
                | Q(message__staff__email__icontains=word)
                | Q(message__staff__display_name__icontains=word)
                | Q(message__grant__email__icontains=word)
                | Q(created_at__icontains=word)
            )
    # HMAC values cannot preserve alphabetical order. Only native metadata sorts
    # are offered, with a stable id tie-breaker before any remote decryption.
    if field not in {"uploaded_at", "sender"}:
        raise Problem("Sort documents by date or sender.")
    query = query.annotate(
        sender_sort=Lower(
            Coalesce(
                NullIf(F("message__staff__display_name"), Value("")),
                F("message__staff__email"),
                F("message__grant__email"),
                Value(""),
                output_field=CharField(),
            )
        )
    )
    sort = ("-" if ordering.startswith("-") else "") + (
        "created_at" if field == "uploaded_at" else "sender_sort"
    )
    count = query.count()
    attachments = list(
        query.select_related("message__conversation", "message__staff", "message__grant").order_by(
            sort, "pk"
        )[(page - 1) * 25 : page * 25]
    )
    conversations = {
        item.message.conversation_id: item.message.conversation for item in attachments
    }
    values = [
        (item.name_ciphertext, crypto.context(item.organization_id, "filename", item.pk))
        for item in attachments
    ]
    values.extend(
        (item.subject_ciphertext, subject_context(item)) for item in conversations.values()
    )
    decoded = []
    for offset in range(0, len(values), 100):
        decoded.extend(
            value.decode() for value in crypto.decrypt_many(values[offset : offset + 100])
        )
    subjects = dict(zip(conversations, decoded[len(attachments) :], strict=True))
    rows = []
    for attachment, filename in zip(attachments, decoded[: len(attachments)], strict=True):
        message = attachment.message
        headers = message.mail_headers or {}
        sender_email = headers.get("from_email") or (
            message.staff.email if message.staff else message.grant.email if message.grant else ""
        )
        sender = headers.get("from_name") or (
            message.staff.display_name if message.staff else sender_email
        )
        rows.append(
            {
                "id": str(attachment.pk),
                "filename": filename,
                "conversation_id": str(message.conversation_id),
                "conversation": subjects[message.conversation_id],
                "sender": sender,
                "sender_email": sender_email,
                "uploaded_at": attachment.created_at.isoformat(),
            }
        )
    return Response({"results": rows, "count": count, "page": page})


@endpoint(["GET"], staff=True)
def catalog(request):
    document_service.require_ready()
    try:
        page = max(1, int(request.query_params.get("page", 1)))
    except ValueError:
        raise Problem("Invalid page.") from None
    if request.query_params.get("view") == "documents":
        return document_table(request, page)
    query = authorized_captures(request.user)
    if request.query_params.get("sha256"):
        try:
            query = query.filter(
                sha256=integrity.tag_digest(
                    request.user.organization_id, request.query_params["sha256"].lower()
                )
            )
        except ValueError:
            raise Problem("Enter a valid SHA-256 digest.") from None
    rows = []
    for capture in query.order_by("-created_at", "pk")[(page - 1) * 25 : page * 25]:
        manifest = json.loads(
            crypto.decrypt(capture.metadata_ciphertext, context(capture, "evidence-metadata"))
        )
        rows.append(
            {
                **manifest,
                "timestamp_state": capture.timestamp_state,
                "timestamp_checked_at": capture.timestamp_checked_at,
            }
        )
    if request.query_params.get("export") == "csv":
        output = io.StringIO(newline="")
        fields = [
            "capture_id",
            "filename",
            "source_url",
            "final_url",
            "downloaded_at",
            "portal_uploaded_at",
            "catalogued_at",
            "sha256",
            "provenance",
            "preservation",
            "timestamp_state",
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            cleaned = {}
            for field in fields:
                value = str(row.get(field) or "")
                # Treat spreadsheet formula-like filenames as literal text.
                cleaned[field] = (
                    "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
                )
            writer.writerow(cleaned)
        audit(
            request.user.organization_id,
            request.user,
            "evidence.catalog_exported",
            "organization",
            request.user.organization_id,
        )
        response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="capture-catalog-page-{page}.csv"'
        response["Cache-Control"] = "no-store"
        return response
    return Response(
        {
            "results": rows,
            "count": query.count(),
            "page": page,
            "uncatalogued_count": authorized_attachments(request.user)
            .filter(evidence_capture=None)
            .count(),
            "storage": "local_append_only_not_worm",
            "tsa_configured": bool(settings.EVIDENCE_TSA_URL and settings.EVIDENCE_TSA_CA_FILE),
        }
    )


@endpoint(["GET"], staff=True)
def export_capture(request, ident):
    capture = authorized_captures(request.user).filter(pk=ident).first()
    if not capture:
        unavailable()
    rate_limit(request, "evidence_export", str(request.user.pk), maximum=10, seconds=60)
    try:
        manifest, content = read_bundle(capture)
        proof = None
        if capture.timestamp_state == "verified":
            raw = path_for(capture, "timestamp").read_bytes()
            if digest(raw) != capture.timestamp_sha256:
                raise ValueError("Timestamp receipt digest mismatch.")
            proof = json.loads(crypto.decrypt(raw.decode(), context(capture, "evidence-timestamp")))
            verify_timestamp(manifest, proof)
    except (ValueError, OSError, KeyError):
        raise Problem(
            "Evidence verification failed. Contact your administrator.",
            "evidence_integrity_failed",
            503,
        ) from None
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("original/" + Path(manifest["filename"]).name, content)
        archive.writestr("manifest.json", canonical(manifest))
        archive.writestr(
            "README.txt",
            "Local preservation is not cloud WORM. Verify SHA-256 against manifest.json.\n"
            "Source/download time may be unknown or uploader-declared. A timestamp proves existence, not source truth.\n"
            + (
                "RFC 3161 query and verified response included. Verify using an independently approved TSA CA bundle.\n"
                if proof
                else "Trusted timestamp is PENDING. No trusted time is claimed.\n"
            ),
        )
        if proof:
            archive.writestr("timestamp.tsq", base64.b64decode(proof["query"]))
            archive.writestr("timestamp.tsr", base64.b64decode(proof["reply"]))
    audit(
        capture.organization_id, request.user, "evidence.exported", "evidence_capture", capture.pk
    )
    response = HttpResponse(output.getvalue(), content_type="application/zip")
    response["Content-Disposition"] = f'attachment; filename="evidence-{capture.pk}.zip"'
    response["Cache-Control"] = "no-store"
    return response


@endpoint(["POST"], staff=True)
def capture_url(request):
    from django.core.files.uploadedfile import SimpleUploadedFile

    from .conversations import upload_for

    document_service.require_ready()
    rate_limit(request, "source_capture", str(request.user.pk), maximum=5, seconds=60)
    source = str(request.data.get("source_url", ""))
    started = timezone.now()
    try:
        data, final_url, media_type = retrieve(source, limit=settings.MAX_UPLOAD_BYTES)
    except (ValueError, OSError, http.client.HTTPException):
        # No raw remote response, URL query or network internals in user errors/logs.
        raise Problem(
            "Source capture failed. Use a public HTTPS document URL within the upload limit.",
            "capture_failed",
            400,
        ) from None
    suffix = {
        "application/pdf": ".pdf",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "text/plain": ".txt",
    }.get(media_type.split(";", 1)[0].lower())
    if not suffix:
        raise Problem("The source must return a PDF, PNG, JPEG or plain-text document.")
    request.FILES["file"] = SimpleUploadedFile("capture" + suffix, data, content_type=media_type)
    provenance = {
        "source_url": source,
        "final_url": final_url,
        "download_started_at": started.isoformat(),
        "downloaded_at": timezone.now().isoformat(),
        "provenance": "server_download",
        "http_status": 200,
    }
    return upload_for(request, user=request.user, captured_metadata=provenance)
