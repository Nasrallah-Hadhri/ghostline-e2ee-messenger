// Sign-in + registration. The passphrase never leaves this page: only auth_key
// (derived) is sent, and private keys travel sealed under wrap_key.
(() => {
  "use strict";
  const { b64 } = GhostCrypto;
  const { $ } = GhostUI;
  const log = $("#boot-log");
  const loginForm = $("#login-form");
  const mfaForm = $("#mfa-form");
  const registerForm = $("#register-form");

  const brand = $("#brand");
  if (brand) {
    const dim = brand.querySelector(".dim");
    GhostUI.scramble(brand.firstChild, "GHOST", { duration: 700 });
    GhostUI.scramble(dim, "LINE", { duration: 900 });
  }

  async function saveIdentity(user, keys, identity) {
    await GhostKeystore.saveIdentity({
      userId: user.id, username: user.username, role: user.role,
      ecdhPriv: keys.ecdhPriv, ecdsaPriv: keys.ecdsaPriv,
      ecdhPub: identity.ecdh_pub, ecdsaPub: identity.ecdsa_pub, version: identity.version,
    });
  }

  function problems(list) {
    log.textContent = "";
    list.forEach((p) => GhostBoot.line(log, p, "FAIL"));
  }

  async function busy(form, flow) {
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try { await flow(); } catch { /* the failing step already logged */ } finally { button.disabled = false; }
  }

  // --- Sign in -------------------------------------------------------------------
  if (loginForm) {
    if (new URLSearchParams(location.search).has("expired")) {
      GhostBoot.line(log, "Session ended. Sign in again.", "WARN");
    }

    let master = null;
    let username = "";

    async function finish(resp) {
      let keys;
      await GhostBoot.run(log, [
        { label: "opening sealed identity (aes-256-gcm)",
          task: async () => {
            const wrapKey = await GhostCrypto.deriveWrapKey(master);
            keys = await GhostCrypto.openIdentity(wrapKey, resp.identity.wrapped_priv,
                                                  resp.identity.wrap_iv, resp.user.username);
          } },
        { label: "storing non-extractable keys locally", task: () => saveIdentity(resp.user, keys, resp.identity) },
      ], { clear: false });
      master = null;
      location.assign("/terminal");
    }

    async function abort() {
      // Never leave a server session alive without usable keys.
      await GhostAPI.post("/api/auth/logout").catch(() => {});
      master = null;
    }

    loginForm.addEventListener("submit", (event) => {
      event.preventDefault();
      username = loginForm.username.value.trim().toLowerCase();
      const passphrase = loginForm.password.value;
      if (!username || !passphrase) return problems(["Handle and passphrase are required."]);

      busy(loginForm, async () => {
        let params, resp;
        try {
          await GhostBoot.run(log, [
            { label: "fetching kdf parameters",
              task: async () => { params = await GhostAPI.post("/api/auth/prelogin", { username }); } },
            { label: "deriving master key · pbkdf2-sha256",
              task: async () => {
                master = await GhostCrypto.deriveMaster(passphrase, b64.decode(params.kdf_salt), params.kdf_iterations);
              } },
            { label: "proving key to server",
              task: async () => {
                resp = await GhostAPI.post("/api/auth/login",
                                           { username, auth_key: await GhostCrypto.deriveAuthKey(master) });
              } },
          ]);
        } catch (err) {
          loginForm.password.value = "";
          master = null;
          throw err;
        }
        loginForm.password.value = "";
        if (resp.mfa_required) {
          GhostBoot.line(log, "second factor required", "WARN");
          loginForm.hidden = true;
          mfaForm.hidden = false;
          code.focus();
          return;
        }
        try { await finish(resp); } catch (err) { await abort(); throw err; }
      });
    });

    const code = GhostUI.otp($("#otp"), () => mfaForm.requestSubmit());
    mfaForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (code.value().length !== 6) return;
      busy(mfaForm, async () => {
        let resp;
        try {
          await GhostBoot.run(log, [
            { label: "verifying one-time code",
              task: async () => { resp = await GhostAPI.post("/api/auth/mfa", { code: code.value() }); } },
          ], { clear: false });
        } catch (err) {
          code.clear();
          if (/start again/.test(err.message)) {
            mfaForm.hidden = true;
            loginForm.hidden = false;
            master = null;
          }
          throw err;
        }
        try { await finish(resp); } catch (err) { await abort(); throw err; }
      });
    });
  }

  // --- Registration ----------------------------------------------------------------
  if (registerForm) {
    const iterations = Number(registerForm.dataset.kdfIterations);
    const fill = $("#meter-fill");
    const meterText = $("#meter-text");

    registerForm.password.addEventListener("input", () => {
      const pw = registerForm.password.value;
      const bits = GhostPolicy.entropyBits(pw);
      const issues = GhostPolicy.checkPassphrase(pw, registerForm.username.value);
      const pct = Math.min(100, (bits / 100) * 100);
      fill.style.width = `${pw ? pct : 0}%`;
      fill.style.background = issues.length ? "var(--bad)" : bits >= 80 ? "var(--ok)" : "var(--accent)";
      meterText.textContent = !pw ? "" : issues.length ? issues[0] : `≈ ${bits} bits of entropy`;
    });

    registerForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const username = registerForm.username.value.trim().toLowerCase();
      const passphrase = registerForm.password.value;
      const issues = [...GhostPolicy.checkUsername(username), ...GhostPolicy.checkPassphrase(passphrase, username)];
      if (passphrase !== registerForm.password2.value) issues.push("Passphrases do not match.");
      if (issues.length) return problems(issues);

      busy(registerForm, async () => {
        const salt = GhostCrypto.randomBytes(16);
        let master, identity, sealed, resp;
        await GhostBoot.run(log, [
          { label: `deriving master key · ${iterations.toLocaleString("en")} rounds`,
            task: async () => { master = await GhostCrypto.deriveMaster(passphrase, salt, iterations); } },
          { label: "generating ecdh p-256 + ecdsa p-256 key pairs",
            task: async () => { identity = await GhostCrypto.generateIdentity(); } },
          { label: "sealing private keys · aes-256-gcm",
            task: async () => {
              sealed = await GhostCrypto.sealIdentity(await GhostCrypto.deriveWrapKey(master), identity, username);
            } },
          { label: "publishing public keys",
            task: async () => {
              resp = await GhostAPI.post("/api/auth/register", {
                username,
                auth_key: await GhostCrypto.deriveAuthKey(master),
                kdf_salt: b64.encode(salt),
                kdf_iterations: iterations,
                identity: {
                  ecdh_pub: await GhostCrypto.publicJwk(identity.ecdh.publicKey),
                  ecdsa_pub: await GhostCrypto.publicJwk(identity.ecdsa.publicKey),
                  ...sealed.blob,
                },
              });
            } },
          { label: "storing non-extractable keys locally",
            task: () => saveIdentity(resp.user, sealed.keys, resp.identity) },
        ]);
        location.assign("/terminal");
      });
    });
  }
})();
