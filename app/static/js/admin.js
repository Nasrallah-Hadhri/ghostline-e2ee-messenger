// SOC console: accounts, live sessions, HMAC audit chain, ciphertext vault.
(() => {
  "use strict";
  const { el, $, toast, ago, clock, short } = GhostUI;
  const REFRESH_MS = 10_000;
  let verifying = false;

  async function logout() {
    try { await GhostAPI.post("/api/auth/logout"); } catch { /* already gone */ }
    await GhostKeystore.wipeIdentity().catch(() => {});
    location.assign("/");
  }

  const btn = (label, onclick, cls = "") => el("button", { class: `btn btn-sm ${cls}`, type: "button", onclick }, label);

  async function act(path, body, what) {
    try {
      await GhostAPI.post(path, body);
      toast("Done", what, "ok");
      await refresh();
    } catch (err) { toast("Refused", err.message, "bad"); }
  }

  function renderStats(s) {
    const set = (id, v) => { $(id).textContent = v; };
    set("#s-users", s.users); set("#s-sessions", s.live_sessions); set("#s-failed", s.failed_logins_24h);
    set("#s-denied", s.denied_24h); set("#s-messages", s.messages_stored); set("#s-audit", s.audit_entries);
  }

  function renderUsers(users) {
    const body = $("#users");
    body.textContent = "";
    for (const u of users) {
      const status = u.disabled ? el("span", { class: "tag tag-bad" }, "disabled")
        : u.locked ? el("span", { class: "tag tag-warn" }, "locked") : el("span", { class: "tag tag-ok" }, "active");
      const actions = el("div", { class: "actions" });
      if (!u.self) {
        actions.append(u.disabled
          ? btn("Enable", () => act(`/api/admin/users/${u.id}/enable`, {}, `${u.username} enabled`))
          : btn("Disable", () => act(`/api/admin/users/${u.id}/disable`, {}, `${u.username} disabled, sessions killed`), "btn-danger"));
        actions.append(btn(u.role === "admin" ? "Make user" : "Make admin",
          () => act(`/api/admin/users/${u.id}/role`, { role: u.role === "admin" ? "user" : "admin" }, `${u.username} role changed`)));
        actions.append(btn("Kick", () => act(`/api/admin/users/${u.id}/logout`, {}, `${u.username} signed out everywhere`)));
      }
      if (u.locked) actions.append(btn("Unlock", () => act(`/api/admin/users/${u.id}/unlock`, {}, `${u.username} unlocked`)));
      body.append(el("tr", {},
        el("td", {}, u.username, u.self ? el("span", { class: "muted" }, " (you)") : ""),
        el("td", {}, el("span", { class: `tag ${u.role === "admin" ? "tag-warn" : "tag-dim"}` }, u.role)),
        el("td", {}, u.totp_enabled ? el("span", { class: "ok" }, "on") : el("span", { class: "muted" }, "off")),
        el("td", {}, status),
        el("td", {}, u.last_login ? ago(u.last_login) : "never"),
        el("td", {}, actions)));
    }
  }

  function renderSessions(sessions) {
    const body = $("#sessions");
    body.textContent = "";
    if (!sessions.length) body.append(el("tr", {}, el("td", { colspan: "4", class: "muted" }, "No live sessions.")));
    for (const s of sessions) {
      body.append(el("tr", {},
        el("td", {}, s.username, s.current ? el("span", { class: "muted" }, " (this one)") : ""),
        el("td", {}, s.ip || "–"), el("td", {}, ago(s.last_seen)),
        el("td", {}, s.current ? "" : btn("Revoke", () => act(`/api/admin/sessions/${s.id}/revoke`, {}, `session of ${s.username} revoked`), "btn-danger"))));
    }
  }

  function actionClass(a) {
    if (/fail|denied|reject|replay/.test(a)) return "bad";
    if (/^admin\./.test(a)) return "warn";
    if (/ok$|enable|register/.test(a)) return "ok";
    return "";
  }

  function renderAudit(entries) {
    const body = $("#audit");
    body.textContent = "";
    for (const e of entries) {
      body.append(el("tr", { dataset: { id: e.id } },
        el("td", {}, e.id), el("td", {}, `${new Date(e.ts).toLocaleDateString()} ${clock(e.ts)}`),
        el("td", {}, e.actor || "–"), el("td", { class: actionClass(e.action) }, e.action),
        el("td", {}, short(e.target || "–", 14)), el("td", {}, e.ip || "–"),
        el("td", { class: "trunc", title: e.details }, e.details === "{}" ? "" : e.details),
        el("td", { class: "trunc", title: e.hmac }, short(e.hmac, 12))));
    }
    if (entries.length) $("#chain-head").textContent = `head ${short(entries[0].hmac, 16)}`;
  }

  function renderVault(messages) {
    const body = $("#vault");
    body.textContent = "";
    if (!messages.length) body.append(el("tr", {}, el("td", { colspan: "7", class: "muted" }, "No messages stored.")));
    for (const m of messages) {
      body.append(el("tr", {},
        el("td", {}, `${m.from} → ${m.to}`), el("td", {}, m.counter), el("td", {}, ago(m.created_at)),
        el("td", {}, m.expires_at ? clock(m.expires_at) : "–"),
        el("td", { class: "trunc" }, m.iv), el("td", { class: "trunc", title: m.ciphertext }, m.ciphertext),
        el("td", { class: "trunc" }, short(m.signature, 16))));
    }
  }

  async function verifyChain() {
    if (verifying) return;
    verifying = true;
    const button = $("#verify-chain");
    button.disabled = true;
    const state = $("#chain-state");
    state.textContent = "walking chain…";
    state.className = "chain-state warn";
    const result = await GhostAPI.post("/api/admin/audit/verify");
    const rows = [...$("#audit").querySelectorAll("tr")].reverse(); // oldest first
    for (const row of rows) {
      row.classList.add("scan");
      await sleep(18);
      row.classList.remove("scan");
      if (!result.ok && Number(row.dataset.id) === result.broken_at) { row.classList.add("broken"); break; }
    }
    if (result.ok) {
      state.textContent = `intact · ${result.count} entries`;
      state.className = "chain-state ok";
      toast("Audit chain intact", `${result.count} entries verified with HMAC-SHA256`, "ok");
    } else {
      state.textContent = `broken at #${result.broken_at}`;
      state.className = "chain-state bad";
      toast(`Tampering detected at #${result.broken_at}`, result.reason, "bad");
    }
    button.disabled = false;
    verifying = false;
    setTimeout(refresh, 1500);
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function refresh() {
    if (verifying) return;
    try {
      const [stats, users, sessions, audit, vault] = await Promise.all([
        GhostAPI.get("/api/admin/stats"), GhostAPI.get("/api/admin/users"), GhostAPI.get("/api/admin/sessions"),
        GhostAPI.get("/api/admin/audit?limit=150"), GhostAPI.get("/api/admin/vault"),
      ]);
      renderStats(stats);
      renderUsers(users.users);
      renderSessions(sessions.sessions);
      renderAudit(audit.entries);
      renderVault(vault.messages);
      $("#refreshed").textContent = clock(new Date().toISOString());
    } catch (err) {
      if (err.status === 401) location.assign("/?expired=1");
      else if (err.status === 403) location.assign("/terminal");
    }
  }

  $("#nav-logout").addEventListener("click", logout);
  $("#verify-chain").addEventListener("click", verifyChain);
  refresh();
  setInterval(refresh, REFRESH_MS);
})();
