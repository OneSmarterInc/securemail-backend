# OneSmarter Secure Mail — Design System

Updated: 2026-10-28. Reference selected by the user: supplied `OneSmarter_Secure_Mail_UI (1).html`.

## Implementation note

The live React interface is in `frontend/src/`, with semantic design tokens in `styles.css`. Key readiness refers to the OneSmarter-owned key-management system, with no OSIVault branding or dependency. Show synthetic mode and actual archive state honestly; an encryption algorithm badge must not imply production approval.

The production target also excludes AWS KMS. The separate custodian page displays sealed/ready status and reports unavailable requests without exposing keys. Portal administrators do not receive custody/unseal controls by virtue of their account-management role. The standalone maintenance page is implemented; access requires an explicitly provisioned custodian identity.

Use **Access expires on …** for recipient deadlines. Explain that submitted messages/files stay in the same conversation for authorized staff after session/access expiry. Distinguish **Uploaded — not submitted** from **Submitted to this conversation**. Do not say files expire with the session or promise **Stored forever**. Refer to DATA_RETENTION.md for the no-automatic-deletion baseline and operational limits.

## Direction and reference boundaries

Use the supplied HTML's light, restrained business-mail aesthetic: OneSmarter teal actions, navy text, pale neutral backgrounds, white cards, clear typography, and compact navigation. Current `web/style.css` and the supplied HTML provide the source colors and layout measurements below.

Preserve this direction while improving accessibility and real workflow states. The sample HTML is a visual/interaction reference, not a production security implementation. Do not copy its visible sample OTPs, in-memory authorization, full recipient-address disclosure, or simulated delivery as production behavior.

No new logo, dark-mode theme, decorative gradients, glass cards, large illustrations, or animation-heavy redesign is included in this baseline. The blurred modal backdrop in the prototype is optional; it must not reduce legibility or performance.

## Color tokens

Use semantic CSS custom properties rather than repeating raw colors. Source colors are retained unless noted as a proposed accessibility refinement.

| Token | Hex | Use |
| --- | --- | --- |
| `--color-primary` | `#117C78` | Main actions; white label |
| `--color-primary-hover` | `#0C6663` | Main-action hover/pressed treatment |
| `--color-heading` | `#142F43` | Brand and headings |
| `--color-text` | `#172B3C` | Primary reading text |
| `--color-muted` | `#526575` | Secondary text; proposed darker replacement for faint prototype text |
| `--color-background` | `#F5F7FA` | Page background |
| `--color-surface` | `#FFFFFF` | Cards, forms, navigation |
| `--color-border` | `#DCE3EA` | Decorative boundaries; not the sole signal for an input |
| `--color-input-border` | `#6B7F8F` | Proposed stronger control boundary |
| `--color-selected-bg` | `#E7F3F1` | Active navigation / selected surfaces |
| `--color-selected-text` | `#086C68` | Active navigation text |
| `--color-info-bg` | `#F0F6F7` | Guidance panels |
| `--color-info-text` | `#355862` | Proposed darker guidance text |
| `--color-success-bg` | `#EDF4F0` | Available/success state surface |
| `--color-success-text` | `#285C3D` | Proposed darker success label |
| `--color-warning-bg` | `#FFF6DF` | Prototype banner / caution surface |
| `--color-warning-text` | `#765B22` | Warning text |
| `--color-danger-bg` | `#F6ECEB` | Failed/revoked/error surface |
| `--color-danger-text` | `#9B3028` | Proposed darker error label |
| `--color-focus` | `#0C6663` | Proposed stronger keyboard focus ring |

Validate actual foreground/background combinations rather than assuming a token guarantees accessibility. Target at least 4.5:1 for ordinary text, 3:1 for large text and meaningful UI boundaries; target WCAG 2.2 AA for the integrated product. Never communicate state only through color.

## Typography

- Font stack: `Inter, ui-sans-serif, system-ui, -apple-system, sans-serif`, matching the reference. Inter is declared but not bundled by the prototype; do not claim it is installed. Use the system fallback or self-host an approved licensed font; avoid third-party font requests on confidential views.
- Body: proposed 16 px, weight 400, line height 1.6; the reference uses a 14 px base. Use 14 px for compact supporting metadata when readable.
- Page heading: 28 px desktop / 24 px mobile, weight 700, line height 1.2.
- Section heading: 21 px, weight 600 or 700, line height 1.3.
- Labels/buttons: 14–16 px, weight 600. Supporting metadata: 12–14 px; essential instructions must not depend on 10 px uppercase text.
- Reading surfaces: approximately 65–80 characters per line where practical; wrap long addresses and filenames.
- Use a real heading hierarchy; do not use heading levels merely for visual size.

## Layout and spacing

- Base spacing scale: 4, 8, 12, 16, 24, 32, 40, 48 px.
- Desktop sidebar: 260 px; compact sidebar around 220 px below 900 px, following the prototype.
- Main content: maximum width 1500 px; desktop padding 40 px vertically / 48 px horizontally, reducing at smaller widths.
- Message detail: two columns around 1.6:1 above 900 px; one column below.
- At 650 px and below, navigation becomes compact above content. Allow wrapping or an accessible menu instead of forcing horizontal scrolling.
- Minimum supported viewport: 360 px. Keep primary actions, OTP entry, recipient chips, and upload errors usable there.
- Cards: 12 px radius, 1 px border, typically 24 px padding. Buttons: 8 px radius. Inputs: 7–8 px radius. Dialog: approximately 15 px radius, maximum 90 viewport-height units with internal scrolling.
- Prefer 44 px minimum touch targets. Preserve readable content at 200% zoom and test reflow.

## Components and interaction rules

| Component | Required behavior |
| --- | --- |
| Primary button | Teal fill, white label, verb describing the real action; visible focus and loading state |
| Secondary button | White/neutral surface with readable boundary; never compete with every primary action |
| Destructive action | Explicit text such as Revoke access; explain affected recipient/scope and confirm intent where warranted |
| Form field | Persistent label, associated hint/error, valid autocomplete, clear required/optional status |
| Recipient chips | Distinct To/Cc/Bcc fields; keyboard add/remove/edit, validation, no hidden external-recipient route change |
| Route indicator | Protected or Normal email plus reason; independent of delivery/access state |
| Status badge | Text and optional icon as well as color; never imply cryptographic proof |
| Attachment row | Safe displayed name, size, upload progress, pending scan/available/rejected state, authorized action |
| Dialog | Label, initial focus, focus containment, Escape when appropriate, focus return, safe handling of unsaved work |
| Toast | Supplementary non-sensitive confirmation; never the only place a critical error appears |
| Empty state | Explain what is absent and provide an appropriate next action |
| Loading state | Keep layout stable, announce status, prevent accidental duplicate actions without relying on UI alone |

Use subtle color/opacity transitions around 120–180 ms. Avoid mandatory scaling animations on buttons or layout shifts. Respect reduced-motion preferences.

## Screen contract

| Screen | Required content / states |
| --- | --- |
| Staff login and MFA | Application-managed sign-in, chosen MFA, recovery, expired session, safe authentication errors |
| Dashboard | Authorized list, status counts, approved search/filter/pagination, New message and Request secure information |
| Compose | Approved sender, To/Cc/Bcc, subject/body/files, expiry, live route preview, server errors |
| Request information | Recipient, optional instructions, expiry, neutral invitation preview; blank instructions allowed |
| Staff conversation | Thread, protected file actions, recipient grants, separate statuses, approved audit events and revoke controls |
| Recipient landing | Organization, masked designated mailbox, Email me a code; no confidential subject or changeable destination |
| Code entry | One accessible six-digit field proposed, paste/autofill support, resend timer, invalid/expired/exhausted states |
| Recipient reply | Instructions/thread within grant scope, text/files/both, upload and scan states, confirmation after durable storage |
| Unavailable | Neutral expired/revoked/unavailable message with contact-sender guidance; no confidential details |
| Connection setup | Authorized sender configuration, Proton/key/service health, clear operational failures |
| Access → Accounts | Admin-managed staff directory, creation, details, last login, usage, lifecycle actions, search/filter/sort/pagination |
| Access → Audit logs | Dedicated read-only event table, search/filter/sort, details, related events, permitted exports and archive health |
| Admin policy settings | Separately authorized sender/settings controls; no implicit message-content access |

## Administrator navigation and workspace

Administrators use the same staff login, MFA, sidebar, dashboard, compose and scoped conversation views. Add an **Access** navigation item with dedicated **Accounts** and **Audit logs** pages and independent URLs. Ordinary staff must not receive these datasets; hiding navigation does not enforce authorization. Clear cached admin data and handle denied requests when permissions change.

### Accounts page

- Header: **Staff accounts**, organization scope and primary **Create account** action. Summary counts may show total/active accounts, pending invitations and MFA enrollment pending using server-defined states.
- Toolbar: labeled name/email/account-ID search, role/status/MFA/Nophi filters, date criteria, usage-period selector, Clear filters, refresh, result count and last-updated time.
- Default columns: Name, Email, Role, Status, MFA, Last login, Usage, Actions. Put creation/modification/activity dates, sessions, sender permissions and full metric details in configurable secondary columns or an account detail panel.
- Last login means completion of required authentication including MFA. Show **Never** for accounts without a successful login; show timestamps with explicit timezone. Last activity is a separate field, not background polling.
- Distinguish period activity totals from current retained-storage/assignment gauges. Display metric units, selected period, freshness and unknown/stale values according to PRD.md.
- Row actions: View account, Edit details, Manage permissions, Resend/cancel invitation, Suspend/reactivate/deactivate, Initiate recovery, Revoke sessions, View audit history. Expose only permitted/state-valid actions and explain disabled actions.
- Create account form: name, company email, approved sender addresses and explicit permissions. Default to staff and Nophi off; elevated-role selection requires privilege-management authority. Show account creation and invitation delivery outcomes separately.
- Sensitive actions identify the account and consequences, collect a reason, and require recent MFA where specified. Administrators never see permanent passwords, MFA secrets or recovery codes.
- Deactivation stops access and preserves retained conversations/audit attribution; it is not a Delete account shortcut. Explain approved ownership/reassignment handling.

### Audit logs page

- Header: **Audit logs**, organization scope, accurate immutable-retention explanation, and permission-gated **Export filtered results**.
- Toolbar: event/actor/resource search, date-time range with timezone, actor/action/category/target/outcome filters, Clear filters, refresh, result count and snapshot time.
- Default columns: Recorded at, Actor, Action, Target, Outcome, Event ID, Actions. Details include occurred-at time, safe before/after metadata, reason/correlation/policy references and archive evidence.
- Default order: newest recorded first. New events show a **New events available** control; do not automatically move inspected rows.
- Row actions: View details, Copy event ID, View related events. No edit form, Delete action, Clear history button or destructive bulk selection. Corrections appear as linked new events.
- Show Pending archive, Archived, Verification failed or Unavailable from evidence. Pending records must not display a verified/immutable archive badge. Keep archive-failure banners visible and actionable.
- Export review shows filters, snapshot, permitted fields, scope, progress and expiry. Distinguish current page from all filtered results; handle queued/failed/expired jobs and permission loss. Exports contain no message content or secrets.

### Table behavior and accessibility

Use semantic table captions and scoped headers. Sortable headings contain keyboard-operable buttons with visible neutral/up/down arrows, action labels and accurate `aria-sort` on the active column. Actions columns are not sortable. Support both directions with deterministic backend ID tie-breakers; proposed null account timestamps sort last.

Search/filter/sort operate on the full authorized server dataset, not only loaded rows. Reset pagination when criteria change, debounce text input, cancel stale requests and prevent old responses overwriting new results. Proposed page sizes: 25/50/100, with a server maximum. Show range, accurate or explicitly estimated totals, navigation, and distinct empty/no-results/error/loading states.

Preserve harmless filter preferences without storing names/emails or sensitive query text in shareable URLs/browser storage. At narrow widths, move secondary columns into labeled row details/cards; retain identity, status, actions and accessible sort/filter controls without page-level horizontal scrolling. Include permission loss, stale usage, unknown timestamps and archive failures in keyboard/mobile review. Do not add a table library without a verified need.

Use precise labels: **Access**, **Accounts**, **Audit logs**, **Create account**, **Last successful login**, **Never**, **Usage period**, **Updated at**. App-level audit wording: **Historical events cannot be edited or deleted in this portal.** State storage-retention guarantees only when verified. These admin screens are required additions absent from the supplied prototype.

## Product wording

Use:

- **Request secure information** for the dedicated intake action.
- **Send protected** and **Send normal email** for the final route-specific send action.
- **Normal email — Nophi override** when an explicitly permitted staff member selects that route.
- **Reply saved. Staff notification pending.** when storage succeeds before email delivery.
- **Checking file…** while quarantined; **Available** only after authorization and scanning allow it.
- **Access revoked. Previously downloaded copies cannot be recalled.** after the relevant server-confirmed action.

Do not use unverified claims such as Quantum secure, Zero access, End-to-end encrypted, Delivered, or Read. Show provider accepted/unknown delivery when that is all the evidence available. An email OTP is mailbox verification, not staff-style MFA or proof of legal identity.

Keep sample codes and the persistent **Interactive prototype — sample content only** warning in demo mode. Production must never show or log an issued OTP. A lock icon is decoration, not evidence.

## Privacy and accessibility checks

- No sensitive subjects, filenames, code values, or token URLs in document titles, telemetry, toasts, or third-party widgets.
- Do not persist decrypted content or credentials in localStorage, IndexedDB, service-worker caches, or browser state persistence.
- Associate errors with controls and announce asynchronous failures; preserve non-sensitive input appropriately after recoverable errors.
- Recheck server permission on every action. Handle session expiry/revocation while the page is open and clear sensitive UI state when notified or detected.
- Treat Bcc visibility and recipient scope as server-enforced constraints, not CSS hiding.
- Verify keyboard-only navigation, screen-reader labels, focus return, narrow-screen uploads, long text, contrast, reduced motion, and loading/error/empty states.

## Prototype gaps to retain in planning

The supplied sample does not implement staff login/MFA, a dedicated request-information action, real route preview, complete To/Cc/Bcc, real file contents, recipient file uploads, real delivery, persistent state, production encryption, or admin policy controls. Preserve visual continuity while implementing these gaps; do not mark them complete because the HTML renders.

## Verified accessibility refinements - 28 October 2026

Avatar initials use the darker selected-text token for contrast. Native dialogs use unique accessible title IDs, intercept Escape consistently, and restore focus to the still-connected opener on close. Browser checks scan rendered data (not just loading screens), exercise skip navigation and keyboard dialog dismissal, and include a 390px viewport. Manual screen-reader announcements, zoom/reflow and other supported browsers remain review work.

## Portal separation and deployment interface - 2026-10-28

Staff and administrators require exact @onesmarter.com accounts. Recipients may use any valid mailbox. Staff enter through /staff/; invitation links enter through /recipient/ and use a separate API namespace and session cookie. Normal user pages no longer display development banners, test-mailbox controls or engineering release requirements. Operator test tools require explicit opt-in. Local captured notifications are explicitly marked not emailed. This supersedes earlier instructions to show development-mode banners on customer pages; deployment status remains documented and enforced on the server. See [DEPLOYMENT.md](DEPLOYMENT.md) for compatibility, configuration and outstanding release blockers.


## Compact workspace revision — 31 October 2026

Retain the teal/navy identity, system font stack and white surfaces. Desktop navigation is 232 px wide with a stable, independently scrollable sidebar; the content header is 56 px. Main desktop spacing is 24–28 px, cards 20 px, tables 12 px vertical cell padding. Body stays 14 px and primary controls retain 44 px targets. Mobile navigation wraps, forms stack, and expiry controls get full width at 720 px and below.

Use page-specific breadcrumbs and aria-current for navigation. Filter buttons expose aria-pressed. Empty states distinguish an empty inbox from an empty filter result. Conversation metadata must describe the delivery mode in ordinary language, not internal routing codes. Remove repeated scope slogans inside every statistic card. Keep access limitations and security errors visible.

Connection summaries show status first; optional diagnostic fields live under View details. SMTP credentials remain write-only and the screen explains encrypted passwords versus sealed keys. Document provenance inputs are collapsed until needed, then expand automatically if an upload lacks mandatory provenance; this reduces text-only compose clutter without weakening server validation.

Use desktop and 360 px browser checks for inbox, request, compose, conversation, accounts, audit, settings, evidence, sign-in and recipient entry. Browser review fixtures contain only fictional data.


## Unified conversation entry — 31 October 2026

One New conversation action replaces the separate message and information-request actions. The single form accepts optional subject/message for protected invitations, files, To/Cc/Bcc and an access deadline. Default payload uses the existing secure_request contract; authorized Nophi explicitly selects ordinary mode with its required subject/content and acknowledgement. Existing /request links remain a compatible alias to the same composer. Existing protected conversations cannot be downgraded. Page headers omit redundant category labels; conversation headers combine navigation, title/date and delivery status.
