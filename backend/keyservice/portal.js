"use strict";
// No localStorage/sessionStorage, third-party scripts, analytics or secret logging.
const element = (id) => document.getElementById(id);
const base = window.location.pathname.startsWith("/maintenance/") ? "/maintenance" : "";
let csrf = "";
let rootId = "";
let busy = false;
let auditPage = 1;
let auditSort = "at";
let auditDirection = "desc";
let auditTotal = 0;
const feedback = (text) => { element("feedback").textContent = text; };
function clearEnrollment() {
  element("enrollment").hidden = true;
  element("setup-key").value = "";
  const canvas = element("totp-qr");
  canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height);
  element("password-setup").hidden = true;
  for (const id of ["first-password", "first-password-confirm"]) { element(id).value = ""; element(id).required = false; }
}
function signedOut() {
  csrf = "";
  rootId = "";
  document.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; });
  document.querySelectorAll('textarea').forEach((input) => { input.value = ""; input.disabled = true; input.required = false; });
  document.querySelectorAll('input[type="checkbox"]').forEach((input) => { input.checked = false; });
  element("controls").hidden = true;
  element("signin").hidden = false;
  element("totp-code").value = "";
  element("audit-rows").replaceChildren();
  document.body.classList.remove("signed-in");
  clearEnrollment();
}
async function request(path, data) {
  const response = await fetch(base + path, {
    method: "POST", credentials: "same-origin", cache: "no-store",
    headers: {"Content-Type": "application/json", "X-CSRFToken": csrf},
    body: JSON.stringify(data),
  });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 403) signedOut();
    throw new Error(response.status === 403 ? "Access denied or session expired. Sign in again." :
      response.status === 409 ? "The key state changed. Refresh status before trying again." :
      response.status === 503 ? "Key service is sealed or unavailable." : "The operation could not be verified. Check the recovery key and retry.");
  }
  return result;
}
async function refresh() {
  const state = await request("/v1/custody-status", {});
  rootId = state.root_id;
  element("signed-in").textContent = "Signed in as " + state.custodian;
  element("state").textContent = state.sealed ? "Sealed" : state.audit_integrity === "unverified_override" ? "Unsealed — integrity unverified" : "Ready";
  element("override-controls").hidden = !state.audit_candidate;
  element("candidate-restore").hidden = !state.candidate_restore_enabled;
  element("root-version").textContent = "Root version: " + rootId;
  element("unseal").hidden = !state.sealed;
  element("seal").hidden = state.sealed;
  return state;
}
async function perform(action) {
  if (busy) return;
  busy = true;
  document.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  try { await action(); } catch (error) { feedback(error instanceof Error ? error.message : "Operation failed."); }
  finally { busy = false; document.querySelectorAll("button").forEach((button) => { button.disabled = false; }); updatePagination(); }
}
element("login").addEventListener("submit", (event) => {
  event.preventDefault();
  void perform(async () => {
    const data = {username: element("username").value, password: element("password").value, code: element("totp-code").value.trim()};
    if (!element("password-setup").hidden) {
      data.new_password = element("first-password").value;
      data.confirmation = element("first-password-confirm").value;
      if (data.new_password !== data.confirmation) throw new Error("The new passwords do not match.");
    }
    element("password").value = "";
    element("totp-code").value = "";
    let result;
    try { result = await request("/login", data); }
    finally { data.password = ""; data.code = ""; data.new_password = ""; data.confirmation = ""; element("first-password").value = ""; element("first-password-confirm").value = ""; }
    if (result.enrollment_required) {
      element("enrollment").hidden = false;
      element("setup-key").value = result.secret;
      element("password-setup").hidden = !result.password_setup_required;
      element("first-password").required = element("first-password-confirm").required = !!result.password_setup_required;
      await window.renderCustodianQr(element("totp-qr"), result.uri);
      result.secret = result.uri = "";
      feedback(result.password_setup_required ? "Scan the QR code, re-enter your temporary setup code, choose your new password, and confirm the authenticator code. Maintenance stays locked until setup is complete." : "Scan the QR code, then re-enter your password and your authenticator code to finish enrollment.");
      element("password").focus();
      return;
    }
    csrf = result.csrf;
    clearEnrollment();
    document.body.classList.add("signed-in");
    element("signin").hidden = true;
    element("controls").hidden = false;
    element("tab-service").click();
    await refresh(); feedback("Custodian signed in. No recovery key has been stored.");
  });
});
element("unseal").addEventListener("submit", (event) => {
  event.preventDefault();
  void perform(async () => {
    const data = {secret: element("recovery").value.trim()}; element("recovery").value = "";
    if (element("override-enable").checked) data.integrity_override_reason = element("override-reason").value.trim();
    element("override-reason").value = "";
    try { await request("/v1/unseal", data); } finally { data.secret = ""; }
    const state = await refresh(); feedback(state.audit_integrity === "unverified_override" ? "Custodian override recorded. Integrity is unverified; document sending remains disabled until checkpoint export succeeds." : "Key service is ready. Authorized document operations can resume.");
  });
});
element("seal").addEventListener("submit", (event) => {
  event.preventDefault();
  void perform(async () => { await request("/v1/seal", {}); element("seal-confirm").checked = false; await refresh(); feedback("Key service sealed. Stored documents have not been deleted."); });
});
element("rotate").addEventListener("submit", (event) => {
  event.preventDefault();
  void perform(async () => {
    if (element("new-secret").value !== element("confirm-secret").value) throw new Error("Recovery keys do not match.");
    const data = {secret: element("new-secret").value.trim(), expected: rootId};
    element("new-secret").value = element("confirm-secret").value = "";
    let result;
    try { result = await request("/v1/rotate-root", data); } finally { data.secret = ""; }
    element("backup-confirm").checked = false; await refresh(); feedback("Root protection rotated. Old-root backups are retained. Retirement requires independently signed off-host copy and clean-machine restore evidence; a same-host drill is insufficient. Do not repeat rotation." + (result.storage_cleanup_complete ? "" : " Live database cleanup also requires operator maintenance."));
  });
});
element("logout").addEventListener("click", () => {
  void perform(async () => { try { await request("/v1/logout", {}); } finally { signedOut(); } feedback("Signed out. The service sealing state was not changed."); });
});
window.addEventListener("pagehide", signedOut);

function updatePagination() {
  element("audit-prev").disabled = busy || auditPage <= 1;
  element("audit-next").disabled = busy || auditPage * 25 >= auditTotal;
}
function updateOptions(id, values, label) {
  const select = element(id), selected = select.value;
  select.replaceChildren(new Option(label, ""), ...values.map(value => new Option(value.replaceAll("_", " "), value)));
  select.value = selected;
}
async function loadAudit() {
  element("audit-summary").textContent = "Loading activity…";
  const from = element("audit-from").value, to = element("audit-to").value;
  const result = await request("/v1/custody-audit", {
    query: element("audit-query").value.trim(), actor: element("audit-actor").value,
    operation: element("audit-operation").value, sort: auditSort, direction: auditDirection, page: auditPage,
    from: from ? new Date(from + "T00:00:00").getTime() / 1000 : null,
    to: to ? new Date(to + "T23:59:59").getTime() / 1000 : null,
  });
  auditTotal = result.total;
  updateOptions("audit-actor", result.actors, "All custodians");
  updateOptions("audit-operation", result.operations, "All actions");
  const rows = element("audit-rows"); rows.replaceChildren();
  for (const item of result.rows) {
    const row = document.createElement("tr");
    for (const value of [new Date(item.at * 1000).toLocaleString(), item.actor, item.operation.replaceAll("_", " "), item.subject || (item.source === "key" ? "Key service" : "Custodian account")]) {
      const cell = document.createElement("td"); cell.textContent = value; row.appendChild(cell);
    }
    rows.appendChild(row);
  }
  if (!result.rows.length) {
    const row = document.createElement("tr"), cell = document.createElement("td");
    cell.colSpan = 4; cell.textContent = "No activity matches these filters."; row.appendChild(cell); rows.appendChild(row);
  }
  element("audit-summary").textContent = result.total + " matching " + (result.total === 1 ? "event" : "events");
  element("audit-page").textContent = "Page " + auditPage + " of " + Math.max(1, Math.ceil(auditTotal / 25));
  updatePagination();
}
for (const name of ["service", "audit"]) {
  element("tab-" + name).addEventListener("click", () => {
    for (const other of ["service", "audit"]) {
      element("tab-" + other).setAttribute("aria-selected", String(other === name));
      element("tab-" + other).tabIndex = other === name ? 0 : -1;
      element(other + "-panel").hidden = other !== name;
    }
    if (name === "audit") void perform(loadAudit);
  });
  element("tab-" + name).addEventListener("keydown", event => {
    if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      event.preventDefault(); const next = event.key === "Home" ? "service" : event.key === "End" ? "audit" : name === "service" ? "audit" : "service";
      element("tab-" + next).focus(); element("tab-" + next).click();
    }
  });
}
element("audit-filters").addEventListener("submit", event => { event.preventDefault(); auditPage = 1; void perform(loadAudit); });
element("audit-refresh").addEventListener("click", () => void perform(loadAudit));
element("audit-clear").addEventListener("click", () => { element("audit-filters").reset(); auditPage = 1; void perform(loadAudit); });
element("audit-prev").addEventListener("click", () => { if (auditPage > 1) { auditPage--; void perform(loadAudit); } });
element("audit-next").addEventListener("click", () => { if (auditPage * 25 < auditTotal) { auditPage++; void perform(loadAudit); } });
document.querySelectorAll("[data-sort]").forEach(button => button.addEventListener("click", () => {
  auditDirection = auditSort === button.dataset.sort && auditDirection === "asc" ? "desc" : "asc";
  auditSort = button.dataset.sort; auditPage = 1;
  document.querySelectorAll("[data-sort]").forEach(other => other.closest("th").setAttribute("aria-sort", other === button ? (auditDirection === "asc" ? "ascending" : "descending") : "none"));
  void perform(loadAudit);
}));
for (const [toggle, reason] of [["override-enable", "override-reason"], ["restore-override", "restore-reason"]]) {
  element(toggle).addEventListener("change", () => { element(reason).disabled = !element(toggle).checked; element(reason).required = element(toggle).checked; });
}
element("restore").addEventListener("submit", (event) => {
  event.preventDefault();
  void perform(async () => {
    const data = {secret: element("restore-secret").value.trim(), destination_id: crypto.randomUUID()};
    element("restore-secret").value = "";
    if (element("restore-override").checked) data.integrity_override_reason = element("restore-reason").value.trim();
    element("restore-reason").value = "";
    let result;
    try { result = await request("/v1/restore-candidate", data); } finally { data.secret = ""; }
    feedback("Sealed recovery copy created: " + result.restored_id + (result.audit_integrity === "unverified_override" ? ". Integrity override remains pending checkpoint export." : ". Verify custody and recovery before use."));
  });
});
setInterval(() => { if (csrf && !busy) void perform(refresh); }, 15000);
