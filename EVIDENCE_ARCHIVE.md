# Local evidence capture and preservation

Decision: 31 October 2026. Keep preservation local, leave the trusted timestamp authority unset, and do not automatically switch to AWS on deployment. Hospital-list comparison is excluded.

## What the portal records

Each newly submitted original attachment receives one capture UUID. Delivery copies, including private BCC copies, reference that original capture. A separate upload or source download creates another capture. Idempotent submission retries reuse the existing result.

The canonical JSON manifest records the original-byte SHA-256, filename, byte count, media type, portal upload time, cataloguing time, hash computation time and provenance. Source URL and original download time remain null when unknown. Optional upload details are explicitly **uploader-declared**. The staff upload control can instead download a public HTTPS document: it records the requested URL, final URL, server-observed start/completion times and HTTP status. All downloads still undergo the normal file-type, size and antivirus checks. It supports PDF, PNG, JPEG and text, not arbitrary website mirroring or authenticated browsing.

Source retrieval uses certificate-verified HTTPS, port 443, validated public DNS destinations, pinned connection addresses, bounded redirects, response size and network time limits. Every redirect is revalidated. Credentials in URLs, private/reserved IP destinations, compression, non-success responses and unsupported document types are rejected. DNS resolution still depends on the host resolver; production network egress controls remain required.

The catalog is scoped to documents the current staff member may read. Administrator role alone does not grant document access. Private recipient replies and BCC access boundaries remain enforced. Source URLs are displayed as text, not loaded automatically. Failed or missing historical captures are reported separately from completed captures. Each scoped catalog page can be exported as CSV with formula-like values escaped for spreadsheet safety.

## Local storage and honest status

`EVIDENCE_DIRECTORY` defaults to `.runtime/evidence`. Place it on persistent storage for deployment. Each capture is an independently application-encrypted bundle containing the exact original bytes and canonical manifest. A temporary file is flushed and fsynced, then published with an exclusive hard link; an existing capture path is never overwritten. Supported filesystems must support hard links. Directories/files use restrictive creation permissions; Windows deployments must additionally provision restrictive ACLs.

The portal verifies the encrypted-bundle digest, authenticated encryption context, capture identity, original byte count and original-file SHA-256 before exporting. Normal attachment downloads also verify the recorded original-byte hash. Export packages contain the original file, manifest, explicit preservation limitations and, when available, the RFC 3161 query/response. Exports are confidential plaintext downloads, subject to the same content authorization and unsealed-key requirements.

**This is not administrator-proof WORM storage.** A machine administrator can change or delete local files. The UI always labels it local preservation, never compliance-locked cloud storage. No bucket was created and no irreversible retention period was selected. An approved WORM destination and retention policy are still needed if the order requires cloud compliance retention. Any future AWS transition requires an explicit decision and migration plan; changing deployment environment must not silently change the backend.

There is no automatic expiry/deletion of committed capture bundles. Archive disk usage is additional to normal portal storage; monitor capacity and include captures, database and usable key versions in off-host backups. Database/file publication is not a distributed transaction: a crash after publication but before database commit may leave an orphan encrypted bundle. Preserve such bundles for reconciliation against the manifest/audit history; do not automatically delete them. A full restore requires the matching database and custody backups.

## Trusted timestamp integration

The live TSA is intentionally **unset**, so captures show **Pending — no trusted timestamp claimed**. No local clock or synthetic authority is presented as trusted evidence.

When an authority is approved, configure `EVIDENCE_TSA_URL` (public HTTPS) and `EVIDENCE_TSA_CA_FILE` (separately approved PEM trust bundle), and provision `EVIDENCE_OPENSSL`. The client generates an RFC 3161 SHA-256 request with a nonce over the canonical manifest; the manifest binds the original-file SHA-256. Verification checks the signed response against both the nonce-bearing request and manifest digest using OpenSSL and the approved trust bundle. Only a verified response becomes a separate encrypted, create-only receipt. Interrupted publication can reuse and reverify an existing receipt. Exports reverify the receipt; a changed manifest or signature fails closed.

Operate timestamp processing separately from interactive saves:

```powershell
python manage.py evidence_preserve --timestamp --limit 100
python manage.py evidence_preserve --timestamp --apply --limit 100
```

The first command is a dry run. The second requires approved TSA configuration and network access. It is an operator batch, not an implicit external request made by an upload. Schedule the command only after the authority and its use are approved. TSA revocation evidence, certificate-expiry handling and long-term renewal policy require operator review before production evidence use. A trusted timestamp establishes existence of the hashed manifest; it does not independently establish that an uploader-declared source is true.

References: [OpenSSL RFC 3161 tooling](https://docs.openssl.org/3.5/man1/openssl-ts/), [S3 Object Lock considerations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html).

## Existing files and key lifecycle

```powershell
python manage.py evidence_preserve --limit 100
python manage.py evidence_preserve --apply --limit 100
```

Backfill preserves original files and hashes the bytes that can be decrypted now. It never invents their source URL, original download time or an earlier trusted timestamp. Unreadable legacy files are reported and retained for the established trusted-reimport/recovery process. Re-downloads must be new captures; retain and identify the original separately.

Source metadata and catalog metadata participate in envelope rewrapping. Immutable bundle/receipt envelopes are retained as written, so their wrapping-key versions must remain recoverable. Do not retire an old private key merely because current portal attachment envelopes have been rewrapped. Custody verification enumerates evidence bundles/receipts as well as database envelopes. A future archive-envelope migration must create a new linked version, preserving the original and its keys until approved disposal.

## Verification boundaries

Tests exercise original-byte preservation, SHA-256, no overwrite, corruption refusal, scoped catalog/export access, BCC copy lineage, sealed-key refusal, source validation, SSRF rejection and legacy backfill. A disposable local test CA produces actual RFC 3161 signatures for success and tampering tests; it is not configured as the live TSA. Local tests do not establish external TSA approval, cloud WORM retention or legal admissibility.


## Required capture provenance — 31 October 2026

New uploaded files require both a source document HTTPS URL and an original download timestamp with timezone. Missing, invalid, timezone-free or future download times are rejected before staging. The shared staff/recipient upload form collects one file at a time with its own provenance. These values remain uploader-declared, not independently verified. Direct URL capture records the requested/final URL and actual server download-completion time automatically. Finalization also rejects older staged files missing these fields; upload them again with accurate provenance. Existing committed captures and explicit legacy backfills remain unchanged and honestly report unknown fields. No earlier download time is inferred from file modification time or portal upload time. Files with no known web source cannot be newly captured through this workflow; do not invent a URL or time. TSA verification and local-storage limitations are unchanged.


### Message attachments (updated 2026-10-31)

Message composers accept files directly without source URL, original download time,
or URL-capture controls. These attachments are catalogued as `upload_only`, with
SHA-256 and server upload/catalog times; source URL and original download time remain
null. No origin or historical download time is inferred. Explicit evidence URL
capture remains separate and continues to record server-observed provenance.
When provenance is supplied through the API, both source URL and a valid download
time are still required. Missing encrypted metadata on a staged record is not
silently accepted as an ordinary upload.
