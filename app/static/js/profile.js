// Profile: identity fingerprints, TOTP enrolment, passphrase change, own sessions.
(() => {
  "use strict";
  const { el, $, toast, ago, copy, identicon } = GhostUI;
  const { b64 } = GhostCrypto;
  let me = null;

  async function logout(reason) {
    try { await GhostAPI.post("/api/auth/logout"); } catch { /* already gone */ }
    await GhostKeystore.wipeIdentity().catch(() => {});
    location.assign(reason === "expired" ? "/?expired=1" : "/");
  }

  // ------------------------------------------------------------- identity --
  async function renderIdentity() {
    const fpEcdh = await GhostCrypto.fingerprint(me.identity.ecdh_pub);
    const fpEcdsa = await GhostCrypto.fingerprint(me.identity.ecdsa_pub);
    const box = $("#identity");
    box.textContent = "";
    box.append(
      el("div", { class: "dossier-head" }, identicon(await GhostCrypto.digestHex(me.identity.ecdsa_pub), 56),
        el("div", {}, el("div", { class: "name" }, me.user.username),
          el("span", { class: `tag ${me.user.role === "admin" ? "tag-warn" : "tag-dim"}` }, me.user.role))),
      el("dl", { class: "kv" },
        el("dt", { class: "label" }, "ECDH P-256 · encryption"), el("dd", { class: "mono-sm" }, fpEcdh),
        el("dt", { class: "label" }, "ECDSA P-256 · signatures"), el("dd", { class: "mono-sm" }, fpEcdsa),
        el("dt", { class: "label" }, "Key version"), el("dd", {}, `v${me.identity.version}`)),
      el("div", { class: "actions" },
        el("button", { class: "btn btn-sm", type: "button", onclick: () => copy(`${fpEcdh}\n${fpEcdsa}`, "fingerprints") }, "Copy fingerprints")));
  }

  // ---------------------------------------------------------------- 2FA --
  function otpRow() {
    return el("div", { class: "otp" },
      el("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", "aria-label": "6-digit code" }));
  }

  function renderTwoFa() {
    const box = $("#twofa");
    box.textContent = "";
    if (me.user.totp_enabled) {
      box.append(el("p", {}, el("span", { class: "tag tag-ok" }, "enabled"), " Codes are required at every sign-in."));
      if (me.user.role === "admin") { box.append(el("p", { class: "muted" }, "Mandatory for admin accounts.")); return; }
      const row = otpRow();
      const code = GhostUI.otp(row, () => {});
      box.append(el("p", { class: "label" }, "Enter a current code to turn it off"), row,
        el("div", { class: "actions" }, el("button", { class: "btn btn-danger btn-sm", type: "button", onclick: async () => {
          try {
            ({ user: me.user } = await GhostAPI.post("/api/2fa/disable", { code: code.value() }));
            toast("Two-factor disabled", "", "");
            renderTwoFa();
          } catch (err) { code.clear(); toast("Not disabled", err.message, "bad"); }
        } }, "Disable two-factor")));
      return;
    }
    box.append(el("p", {}, el("span", { class: "tag tag-warn" }, "off"), " Anyone with your passphrase can sign in."),
      el("button", { class: "btn btn-primary", type: "button", onclick: beginSetup }, "Set up authenticator"));
  }

  async function beginSetup() {
    const box = $("#twofa");
    let setup;
    try { setup = await GhostAPI.post("/api/2fa/setup"); } catch (err) { return toast("Setup failed", err.message, "bad"); }
    const row = otpRow();
    const status = el("p", { class: "meter-text" });
    const code = GhostUI.otp(row, async (value) => {
      try {
        ({ user: me.user } = await GhostAPI.post("/api/2fa/enable", { code: value }));
        toast("Two-factor enabled", "Your session was renewed.", "ok");
        renderTwoFa();
        if (me.user.role === "admin") $("#nav-admin").hidden = false;
      } catch (err) { status.textContent = err.message; status.className = "meter-text bad"; code.clear(); }
    });
    box.textContent = "";
    box.append(
      el("p", {}, "1. Scan with an authenticator app (Aegis, Google Authenticator, 1Password…)."),
      el("div", { class: "row" },
        el("img", { class: "qr", src: setup.qr_data_uri, alt: "TOTP enrolment QR code" }),
        el("div", { class: "stack" }, el("span", { class: "label" }, "or type this secret"),
          el("span", { class: "secret" }, setup.secret.match(/.{1,4}/g).join(" ")),
          el("button", { class: "btn btn-sm", type: "button", onclick: () => copy(setup.secret, "secret") }, "Copy secret"))),
      el("p", {}, "2. Enter the 6-digit code it shows."), row, status);
    code.focus();
  }

  // ---------------------------------------------------------- passphrase --
  function wirePassphrase() {
    const form = $("#pass-form");
    const log = $("#pass-log");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const current = $("#pass-current").value;
      const next = $("#pass-new").value;
      const issues = GhostPolicy.checkPassphrase(next, me.user.username);
      if (next !== $("#pass-new2").value) issues.push("New passphrases do not match.");
      if (next === current) issues.push("New passphrase must differ from the current one.");
      log.textContent = "";
      if (issues.length) { issues.forEach((i) => GhostBoot.line(log, i, "FAIL")); return; }

      const button = form.querySelector("button");
      button.disabled = true;
      const iterations = (await GhostAPI.post("/api/auth/prelogin", { username: me.user.username })).kdf_iterations;
      let oldMaster, newMaster, sealed;
      const salt = GhostCrypto.randomBytes(16);
      try {
        await GhostBoot.run(log, [
          { label: "deriving current key", task: async () => {
            const p = await GhostAPI.post("/api/auth/prelogin", { username: me.user.username });
            oldMaster = await GhostCrypto.deriveMaster(current, b64.decode(p.kdf_salt), p.kdf_iterations);
          } },
          { label: "deriving new key", task: async () => { newMaster = await GhostCrypto.deriveMaster(next, salt, iterations); } },
          { label: "re-sealing identity under new key", task: async () => {
            const { identity } = await GhostAPI.get("/api/auth/identity-blob");
            sealed = await GhostCrypto.rewrapIdentity(await GhostCrypto.deriveWrapKey(oldMaster),
                                                       await GhostCrypto.deriveWrapKey(newMaster),
                                                       identity.wrapped_priv, identity.wrap_iv, me.user.username);
          } },
          { label: "committing · other sessions revoked", task: async () => {
            await GhostAPI.post("/api/auth/password", {
              current_auth_key: await GhostCrypto.deriveAuthKey(oldMaster),
              new_auth_key: await GhostCrypto.deriveAuthKey(newMaster),
              new_kdf_salt: b64.encode(salt), ...sealed,
            });
          } },
        ]);
        form.reset();
        toast("Passphrase changed", "Other devices were signed out.", "ok");
        renderSessions();
      } catch { /* logged */ } finally { button.disabled = false; }
    });
  }

  // ------------------------------------------------------------- sessions --
  function device(ua) {
    if (!ua) return "unknown";
    const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
    const os = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : /iPhone|iPad/.test(ua) ? "iOS" : "";
    return `${browser}${os ? ` · ${os}` : ""}`;
  }

  async function renderSessions() {
    const { sessions } = await GhostAPI.get("/api/auth/sessions");
    const body = $("#sessions");
    body.textContent = "";
    for (const s of sessions) {
      body.append(el("tr", {},
        el("td", {}, device(s.user_agent), s.current ? el("span", { class: "tag tag-ok" }, " this device") : ""),
        el("td", {}, s.ip || "–"), el("td", {}, ago(s.created_at)), el("td", {}, ago(s.last_seen)),
        el("td", {}, s.current ? "" : el("button", { class: "btn btn-sm btn-danger", type: "button", onclick: async () => {
          await GhostAPI.post(`/api/auth/sessions/${s.id}/revoke`);
          toast("Session revoked", device(s.user_agent), "ok");
          renderSessions();
        } }, "Revoke"))));
    }
  }

  async function boot() {
    try { me = await GhostAPI.get("/api/auth/me"); } catch { return logout("expired"); }
    $("#title").textContent = me.user.username;
    $("#subtitle").textContent = `${me.user.role} account · id ${me.user.id}`;
    $("#nav-admin").hidden = !(me.user.role === "admin" && me.user.totp_enabled);
    $("#nav-logout").addEventListener("click", () => logout());
    await renderIdentity();
    renderTwoFa();
    wirePassphrase();
    await renderSessions();
    if (new URLSearchParams(location.search).has("setup2fa") && !me.user.totp_enabled) beginSetup();
  }

  boot();
})();
