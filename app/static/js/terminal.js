// GhostLine terminal: contacts, E2E channels, inspector, command line, palette.
(() => {
  "use strict";
  const { el, $, toast, clock, ago, short, copy, identicon, scramble } = GhostUI;
  const KEEPALIVE_MS = 60_000;
  const TTL_LABEL = { 30: "30s", 300: "5m", 3600: "1h", 86400: "24h" };

  const S = {
    me: null,            // /api/auth/me
    keys: null,          // local identity record (non-extractable CryptoKeys)
    myEcdsaPub: null,    // CryptoKey, to verify our own sent messages
    serverKey: null,     // Ed25519 directory key (base64)
    convs: new Map(),    // convId -> conversation json (+ unread)
    peers: new Map(),    // userId -> peer record
    aes: new Map(),      // convId -> AES-GCM CryptoKey
    msgs: new Map(),     // convId -> Map(msgId -> message record)
    next: new Map(),     // convId -> next counter to use
    active: null,
    selected: null,
    deadline: 0,
    lastPing: Date.now(),
  };

  // ---------------------------------------------------------------- session --
  async function logout(reason) {
    try { await GhostAPI.post("/api/auth/logout"); } catch { /* already gone */ }
    await GhostKeystore.wipeIdentity().catch(() => {});
    location.assign(reason === "expired" ? "/?expired=1" : "/");
  }

  function applySession(session) { S.deadline = Date.now() + session.idle_remaining_s * 1000; }

  async function keepalive() {
    S.lastPing = Date.now();
    try { applySession((await GhostAPI.get("/api/auth/me")).session); }
    catch (err) { if (err.status === 401) logout("expired"); }
  }

  function tickSession() {
    const total = S.me ? S.me.session.idle_timeout_s : 900;
    const left = Math.max(0, Math.round((S.deadline - Date.now()) / 1000));
    $("#session-timer").textContent = `${String(Math.floor(left / 60)).padStart(2, "0")}:${String(left % 60).padStart(2, "0")}`;
    const bar = $("#session-bar");
    bar.style.transform = `scaleX(${left / total})`;
    bar.classList.toggle("low", left <= 60);
    if (left === 0) logout("expired");
  }

  // ------------------------------------------------------------------ peers --
  const myEntry = () => ({ user_id: S.me.user.id, ecdh_pub: S.me.identity.ecdh_pub, ecdsa_pub: S.me.identity.ecdsa_pub });

  async function loadPeer(userId) {
    if (S.peers.has(userId)) return S.peers.get(userId);
    const { username, identity } = await GhostAPI.get(`/api/users/${userId}/identity`);
    const peer = { id: userId, username, identity, trust: "new", directory: "unchecked" };

    try {
      peer.directory = (await GhostCrypto.verifyDirectory(S.serverKey, identity)) ? "valid" : "invalid";
    } catch { peer.directory = "unsupported"; }

    const pin = await GhostKeystore.getPin(S.me.user.id, userId);
    if (!pin) {
      await GhostKeystore.putPin(S.me.user.id, userId, {
        ecdh_pub: identity.ecdh_pub, ecdsa_pub: identity.ecdsa_pub, version: identity.version,
        verified: false, first_seen: new Date().toISOString(),
      });
      peer.trust = "new";
    } else if (pin.ecdh_pub !== identity.ecdh_pub || pin.ecdsa_pub !== identity.ecdsa_pub) {
      peer.trust = "changed";
    } else {
      peer.trust = pin.verified ? "verified" : "pinned";
    }
    if (peer.directory === "invalid") peer.trust = "forged";

    peer.ecdsaKey = await GhostCrypto.importEcdsaPublic(identity.ecdsa_pub);
    peer.fp = await GhostCrypto.digestHex(identity.ecdsa_pub);
    peer.fpEcdh = await GhostCrypto.fingerprint(identity.ecdh_pub);
    peer.fpEcdsa = await GhostCrypto.fingerprint(identity.ecdsa_pub);
    peer.safety = await GhostCrypto.safetyNumber(myEntry(), { user_id: userId, ...identity });
    S.peers.set(userId, peer);
    return peer;
  }

  const blocked = (peer) => peer.trust === "changed" || peer.trust === "forged";

  async function setVerified(peer, verified) {
    await GhostKeystore.putPin(S.me.user.id, peer.id, {
      ecdh_pub: peer.identity.ecdh_pub, ecdsa_pub: peer.identity.ecdsa_pub, version: peer.identity.version,
      verified, first_seen: new Date().toISOString(),
    });
    peer.trust = verified ? "verified" : "pinned";
    toast(verified ? "Marked verified" : "Verification removed", `${peer.username}`, verified ? "ok" : "");
    renderContacts();
    if (S.active && activePeer() === peer) { renderHeader(); renderDossier(); updateCompose(); }
  }

  function trustTag(peer) {
    const map = {
      verified: ["verified", "tag-ok"], pinned: ["unverified", "tag-dim"], new: ["new key", "tag-warn"],
      changed: ["key changed", "tag-bad"], forged: ["bad signature", "tag-bad"],
    };
    const [text, cls] = map[peer.trust] || ["?", "tag-dim"];
    return el("span", { class: `tag ${cls}` }, text);
  }

  function showKeyAlert(peer) {
    $("#key-alert-text").textContent = peer.trust === "forged"
      ? `The directory entry for ${peer.username} is not signed by this server's key.`
      : `${peer.username} now presents a different identity key than the one pinned in this browser.`;
    $("#key-alert-accept").hidden = peer.trust === "forged";
    $("#key-alert").hidden = false;
    $("#key-alert-accept").onclick = async () => { $("#key-alert").hidden = true; await setVerified(peer, true); };
    $("#key-alert-close").onclick = () => { $("#key-alert").hidden = true; };
  }

  // ---------------------------------------------------------- conversations --
  async function loadConversations() {
    const { conversations } = await GhostAPI.get("/api/conversations");
    for (const c of conversations) {
      const prev = S.convs.get(c.id);
      S.convs.set(c.id, { ...c, unread: prev ? prev.unread : 0 });
      if (!S.next.has(c.id) || S.next.get(c.id) < c.next_counter) S.next.set(c.id, c.next_counter);
    }
    await Promise.all(conversations.map((c) => loadPeer(c.peer.id).catch(() => null)));
    renderContacts();
  }

  function sortedConvs() {
    return [...S.convs.values()].sort((a, b) => (a.last_activity < b.last_activity ? 1 : -1));
  }

  const activePeer = () => (S.active ? S.peers.get(S.convs.get(S.active).peer.id) : null);

  function renderContacts() {
    const list = $("#contacts");
    list.textContent = "";
    const convs = sortedConvs();
    if (!convs.length) { list.append(el("li", { class: "empty" }, "No channels yet.")); return; }
    for (const c of convs) {
      const peer = S.peers.get(c.peer.id);
      const glyph = peer && peer.trust === "verified" ? "✓ " : peer && blocked(peer) ? "⚠ " : "";
      list.append(el("li", {
        class: `contact${c.id === S.active ? " active" : ""}`, role: "button", tabindex: "0",
        onclick: () => openConversation(c.id),
        onkeydown: (e) => { if (e.key === "Enter") openConversation(c.id); },
      },
      peer ? identicon(peer.fp) : el("canvas", { class: "identicon" }),
      el("div", {},
        el("div", { class: "name" }, el("span", { class: `dot${c.peer.online ? " on" : ""}` }), c.peer.username),
        el("div", { class: "meta" }, glyph, ago(c.last_activity))),
      c.unread ? el("span", { class: "unread" }, c.unread) : el("span")));
    }
  }

  async function startChat(user) {
    try {
      const { conversation } = await GhostAPI.post("/api/conversations", { peer_id: user.id });
      S.convs.set(conversation.id, { ...conversation, unread: 0 });
      S.next.set(conversation.id, conversation.next_counter);
      await loadPeer(conversation.peer.id);
      $("#search").value = "";
      $("#results").textContent = "";
      await openConversation(conversation.id);
    } catch (err) { toast("Could not open channel", err.message, "bad"); }
  }

  async function aesFor(convId) {
    if (!S.aes.has(convId)) {
      const peer = await loadPeer(S.convs.get(convId).peer.id);
      S.aes.set(convId, await GhostCrypto.conversationKey(S.keys.ecdhPriv, peer.identity.ecdh_pub, convId));
    }
    return S.aes.get(convId);
  }

  async function openConversation(convId) {
    S.active = convId;
    S.selected = null;
    try { localStorage.setItem("gl.active", convId); } catch { /* storage unavailable */ }
    const conv = S.convs.get(convId);
    conv.unread = 0;
    const peer = await loadPeer(conv.peer.id);
    renderContacts();
    renderHeader();
    renderDossier();
    selectTab("dossier");
    updateCompose();
    if (blocked(peer)) showKeyAlert(peer);

    const box = $("#messages");
    box.textContent = "";
    box.append(el("div", { class: "sys" }, `channel sealed · AES-256-GCM key derived from ECDH(you, ${peer.username})`));
    const { messages, next_counter: nextCounter } = await GhostAPI.get(`/api/conversations/${convId}/messages`);
    S.next.set(convId, Math.max(nextCounter, S.next.get(convId) || 1));
    if (!S.msgs.has(convId)) S.msgs.set(convId, new Map());
    const known = S.msgs.get(convId);
    for (const env of messages) {
      const rec = known.get(env.id) || await decryptEnvelope(env);
      known.set(env.id, rec);
      box.append(renderMessage(rec, false));
    }
    if (!messages.length) box.append(el("div", { class: "sys" }, "no messages yet. say something."));
    box.scrollTop = box.scrollHeight;
    $("#compose-input").focus();
  }

  function cycleConversation(delta) {
    const ids = sortedConvs().map((c) => c.id);
    if (!ids.length) return;
    const i = ids.indexOf(S.active);
    openConversation(ids[(i + delta + ids.length) % ids.length]);
  }

  function renderHeader() {
    const peer = activePeer();
    const head = $("#channel-peer");
    head.textContent = "";
    head.append(identicon(peer.fp), el("span", { class: "name" }, peer.username), trustTag(peer));
    $("#channel-crypto").textContent = "e2e · aes-256-gcm · ecdsa";
  }

  function updateCompose() {
    const peer = activePeer();
    const input = $("#compose-input");
    const disabled = !peer || blocked(peer);
    input.disabled = disabled;
    $("#send-btn").disabled = disabled;
    input.placeholder = !peer ? "Select a channel first"
      : blocked(peer) ? "Sending blocked: verify the new key first"
      : `Message ${peer.username}`;
  }

  // --------------------------------------------------------------- messages --
  async function decryptEnvelope(env) {
    const mine = env.sender_id === S.me.user.id;
    const peer = mine ? null : await loadPeer(env.sender_id);
    const result = await GhostCrypto.openMessage({
      aesKey: await aesFor(env.conversation_id),
      senderEcdsaPub: mine ? S.myEcdsaPub : peer.ecdsaKey,
      envelope: env,
    });
    return { env, mine, who: mine ? S.me.user.username : peer.username, ...result };
  }

  function renderMessage(rec, animate) {
    const { env } = rec;
    const body = el("div", { class: "body" });
    const seal = rec.ok
      ? el("span", { class: "seal ok", title: "ECDSA signature and AES-GCM tag verified" }, "signed ✓")
      : el("span", { class: "seal bad", title: "integrity check failed" }, "forged ✗");
    const node = el("article", {
      class: `msg${rec.mine ? " out" : ""}${rec.ok ? "" : " failed"}`, dataset: { id: env.id }, tabindex: "0",
      onclick: () => selectMessage(rec, node),
      onkeydown: (e) => { if (e.key === "Enter") selectMessage(rec, node); },
    }, el("time", { datetime: env.created_at }, clock(env.created_at)),
       el("div", {}, el("span", { class: "who" }, rec.who), seal), body);

    if (!rec.ok) {
      const failed = Object.entries(rec.checks).filter(([, v]) => !v).map(([k]) => k).join(", ");
      body.textContent = `integrity check failed (${failed}). this message was altered or forged.`;
    } else if (animate) {
      body.classList.add("cipher");
      const cipherText = atob(env.ciphertext.slice(0, 120)).replace(/[^\x21-\x7e]/g, "·");
      scramble(body, rec.plaintext, { from: cipherText, duration: 650 }).then(() => body.classList.remove("cipher"));
    } else {
      body.textContent = rec.plaintext;
    }

    if (env.expires_at) {
      const fill = el("i");
      const label = el("span", { class: "burn-label" });
      node.append(el("div", { class: "burn" }, fill), label);
      rec.burn = { fill, label, node, total: Number(env.aad.split("|")[4]) || 1 };
    }
    rec.node = node;
    return node;
  }

  function tickBurns() {
    const now = Date.now();
    for (const map of S.msgs.values()) {
      for (const rec of map.values()) {
        if (!rec.burn || !rec.node.isConnected) continue;
        const left = (new Date(rec.env.expires_at).getTime() - now) / 1000;
        if (left <= 0) { burnAway(rec); continue; }
        rec.burn.fill.style.transform = `scaleX(${Math.min(1, left / rec.burn.total)})`;
        rec.burn.label.textContent = left > 90 ? `burns in ${Math.ceil(left / 60)}m` : `burns in ${Math.ceil(left)}s`;
      }
    }
  }

  function burnAway(rec) {
    if (rec.burned) return;
    rec.burned = true;
    if (rec.node && rec.node.isConnected) {
      rec.node.classList.add("burning");
      setTimeout(() => rec.node.remove(), 700);
    }
    const map = S.msgs.get(rec.env.conversation_id);
    if (map) map.delete(rec.env.id);
    if (S.selected === rec) { S.selected = null; $("#inspector-packet").textContent = ""; }
  }

  async function onIncoming(env) {
    if (!S.convs.has(env.conversation_id)) await loadConversations();
    const conv = S.convs.get(env.conversation_id);
    if (!conv) return;
    if (!S.msgs.has(conv.id)) S.msgs.set(conv.id, new Map());
    const map = S.msgs.get(conv.id);
    if (map.has(env.id)) return;
    const rec = await decryptEnvelope(env);
    map.set(env.id, rec);
    conv.last_activity = env.created_at;
    if (env.sender_id === S.me.user.id) S.next.set(conv.id, Math.max(S.next.get(conv.id) || 1, env.counter + 1));

    if (conv.id === S.active) {
      const box = $("#messages");
      const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
      box.append(renderMessage(rec, !rec.mine));
      if (atBottom || rec.mine) box.scrollTop = box.scrollHeight;
    } else if (!rec.mine) {
      conv.unread += 1;
      toast(rec.who, rec.ok ? "new encrypted message" : "a message failed its integrity check", rec.ok ? "" : "bad");
    }
    renderContacts();
  }

  async function send(text) {
    const convId = S.active;
    const peer = activePeer();
    if (!convId || !peer || blocked(peer) || !text.trim()) return;
    const ttl = Number($("#ttl").value) || null;
    const aesKey = await aesFor(convId);

    for (let attempt = 0; attempt < 2; attempt++) {
      const counter = S.next.get(convId) || 1;
      const envelope = await GhostCrypto.sealMessage({
        aesKey, ecdsaPriv: S.keys.ecdsaPriv, conversationId: convId, senderId: S.me.user.id,
        counter, ttl, keyVersion: S.me.identity.version, plaintext: text,
      });
      try {
        const { message } = await GhostAPI.post(`/api/conversations/${convId}/messages`, envelope);
        S.next.set(convId, counter + 1);
        const bytes = new TextEncoder().encode(text).length;
        $("#compose-info").textContent =
          `sealed ${bytes} B → ${atob(envelope.ciphertext).length} B · counter #${counter}${ttl ? ` · burns in ${TTL_LABEL[ttl]}` : ""}`;
        await onIncoming(message);
        return;
      } catch (err) {
        if (err.status === 409 && err.data && err.data.next_counter) { S.next.set(convId, err.data.next_counter); continue; }
        toast("Not sent", err.message, "bad");
        return;
      }
    }
  }

  // -------------------------------------------------------------- inspector --
  function selectTab(name) {
    $("#tab-dossier").setAttribute("aria-selected", String(name === "dossier"));
    $("#tab-packet").setAttribute("aria-selected", String(name === "packet"));
    $("#inspector-dossier").hidden = name !== "dossier";
    $("#inspector-packet").hidden = name !== "packet";
  }

  function kv(label, value, cls) {
    return [el("dt", { class: "label" }, label), el("dd", { class: cls || "" }, value)];
  }

  function renderDossier() {
    const box = $("#inspector-dossier");
    box.textContent = "";
    const peer = activePeer();
    if (!peer) return;
    const dirText = { valid: "signed by server ✓", invalid: "signature INVALID", unsupported: "not checkable in this browser", unchecked: "–" };
    box.append(
      el("div", { class: "dossier-head" }, identicon(peer.fp, 56),
        el("div", {}, el("div", { class: "name" }, peer.username), trustTag(peer))),
      el("dl", { class: "kv" },
        kv("Safety number", el("div", { class: "safety" }, peer.safety.map((g) => el("span", {}, g)))),
        kv("Directory entry", dirText[peer.directory], peer.directory === "valid" ? "ok" : peer.directory === "invalid" ? "bad" : ""),
        kv("Key version", `v${peer.identity.version}`),
        kv("ECDH fingerprint", peer.fpEcdh, "mono-sm"),
        kv("ECDSA fingerprint", peer.fpEcdsa, "mono-sm")),
      el("div", { class: `trust-banner ${peer.trust === "verified" ? "ok" : blocked(peer) ? "bad" : ""}` },
        peer.trust === "verified" ? "You compared safety numbers with this contact."
          : blocked(peer) ? "Key mismatch. Sending is blocked."
          : "Compare the safety number with them over a call or in person, then mark verified."),
      el("div", { class: "actions" },
        peer.trust === "verified"
          ? el("button", { class: "btn btn-sm", type: "button", onclick: () => setVerified(peer, false) }, "Unverify")
          : el("button", { class: "btn btn-sm", type: "button", onclick: () => (blocked(peer) ? showKeyAlert(peer) : setVerified(peer, true)) }, "Mark verified"),
        el("button", { class: "btn btn-sm", type: "button", onclick: () => copy(peer.safety.join(" "), "safety number") }, "Copy number")));
  }

  function selectMessage(rec, node) {
    document.querySelectorAll(".msg.selected").forEach((n) => n.classList.remove("selected"));
    node.classList.add("selected");
    S.selected = rec;
    const { env, checks } = rec;
    const ctBytes = atob(env.ciphertext).length;
    const box = $("#inspector-packet");
    box.textContent = "";
    const check = (name, ok) => el("li", {}, name, el("span", { class: ok ? "ok" : "bad" }, ok ? "pass" : "FAIL"));
    box.append(
      el("p", { class: "label" }, `${rec.mine ? "outbound" : "inbound"} envelope · #${env.counter}`),
      el("ul", { class: "check-list" },
        check("AAD bound to channel/sender/counter", checks.aad),
        check("ECDSA P-256 signature", checks.signature),
        check("AES-256-GCM authentication tag", checks.decrypt)),
      el("dl", { class: "kv" },
        kv("Sent", new Date(env.created_at).toLocaleString()),
        kv("Self-destruct", env.expires_at ? new Date(env.expires_at).toLocaleTimeString() : "no"),
        kv("Additional data (AAD)", env.aad, "mono-sm"),
        kv("IV · 96 bit", env.iv, "mono-sm"),
        kv(`Ciphertext · ${ctBytes} B (incl. 16 B tag)`, short(env.ciphertext, 120), "mono-sm"),
        kv("Signature · r‖s", env.signature, "mono-sm")),
      el("div", { class: "actions" },
        el("button", { class: "btn btn-sm", type: "button", onclick: () => copy(JSON.stringify(env, null, 2), "envelope JSON") }, "Copy envelope")),
      el("p", { class: "muted" }, "This is exactly what the server stores. Without the ECDH secret it cannot open it."));
    selectTab("packet");
  }

  // ---------------------------------------------------------- command line --
  function sys(text, kind) {
    const box = $("#messages");
    const empty = $("#empty-channel");
    if (empty) empty.remove();
    box.append(el("div", { class: `sys${kind ? ` ${kind}` : ""}` }, text));
    box.scrollTop = box.scrollHeight;
  }

  async function findUser(handle) {
    const { users } = await GhostAPI.get(`/api/directory?q=${encodeURIComponent(handle)}`);
    return users.find((u) => u.username === handle.toLowerCase());
  }

  const COMMANDS = {
    help: { hint: "list commands", run: () => Object.entries(COMMANDS).forEach(([n, c]) => sys(`/${n.padEnd(12)}${c.hint}`)) },
    msg: { hint: "<handle>  open a channel", run: async (arg) => {
      if (!arg) return sys("usage: /msg <handle>", "bad");
      const user = await findUser(arg);
      return user ? startChat(user) : sys(`no such handle: ${arg}`, "bad");
    } },
    verify: { hint: "mark the current contact verified", run: () => {
      const peer = activePeer();
      if (!peer) return sys("open a channel first", "bad");
      return blocked(peer) ? showKeyAlert(peer) : setVerified(peer, true);
    } },
    burn: { hint: "<30s|5m|1h|24h|off>  self-destruct timer", run: (arg) => {
      const map = { "30s": "30", "5m": "300", "1h": "3600", "24h": "86400", off: "" };
      if (!(arg in map)) return sys("usage: /burn 30s|5m|1h|24h|off", "bad");
      $("#ttl").value = map[arg];
      return sys(arg === "off" ? "self-destruct off" : `new messages burn after ${arg}`, "ok");
    } },
    whoami: { hint: "your identity", run: () => sys(`${S.me.user.username} · ${S.me.user.role} · key v${S.me.identity.version} · 2fa ${S.me.user.totp_enabled ? "on" : "off"}`) },
    fingerprint: { hint: "your key fingerprints", run: async () => {
      sys(`ecdh  ${await GhostCrypto.fingerprint(S.me.identity.ecdh_pub)}`);
      sys(`ecdsa ${await GhostCrypto.fingerprint(S.me.identity.ecdsa_pub)}`);
    } },
    inspect: { hint: "show the contact dossier", run: () => selectTab("dossier") },
    clear: { hint: "clear the screen", run: () => { $("#messages").textContent = ""; } },
    profile: { hint: "sessions, 2fa, passphrase", run: () => location.assign("/profile") },
    admin: { hint: "SOC console (admins)", run: () => location.assign("/admin/") },
    logout: { hint: "sign out and wipe local keys", run: () => logout() },
  };

  async function runCommand(line) {
    const [name, ...rest] = line.replace(/^\//, "").trim().split(/\s+/);
    const cmd = Object.hasOwn(COMMANDS, name.toLowerCase()) ? COMMANDS[name.toLowerCase()] : null;
    if (!cmd) return sys(`unknown command: ${line}  (try /help)`, "bad");
    try { await cmd.run(rest.join(" ")); } catch (err) { sys(err.message, "bad"); }
  }

  // ---------------------------------------------------------------- palette --
  const palette = { items: [], index: 0 };

  async function refreshPalette() {
    const q = $("#palette-input").value.trim().toLowerCase().replace(/^\//, "");
    const items = [];
    for (const c of sortedConvs()) {
      if (!q || c.peer.username.includes(q)) items.push({ label: c.peer.username, hint: "channel", run: () => openConversation(c.id) });
    }
    for (const [name, c] of Object.entries(COMMANDS)) {
      if (!q || name.startsWith(q.split(" ")[0])) items.push({ label: `/${name}`, hint: c.hint, run: () => runCommand(q.startsWith(name) ? q : name) });
    }
    if (q && /^[a-z0-9_]+$/.test(q)) {
      try {
        const { users } = await GhostAPI.get(`/api/directory?q=${encodeURIComponent(q)}`);
        for (const u of users) {
          if (![...S.convs.values()].some((c) => c.peer.id === u.id)) items.push({ label: u.username, hint: "new channel", run: () => startChat(u) });
        }
      } catch { /* offline */ }
    }
    palette.items = items.slice(0, 12);
    palette.index = 0;
    drawPalette();
  }

  function drawPalette() {
    const list = $("#palette-list");
    list.textContent = "";
    palette.items.forEach((item, i) => list.append(el("li", {
      role: "option", "aria-selected": String(i === palette.index),
      onclick: () => { closePalette(); item.run(); },
    }, el("span", {}, item.label), el("span", { class: "label" }, item.hint))));
  }

  function openPalette() { $("#palette").hidden = false; $("#palette-input").value = ""; refreshPalette(); $("#palette-input").focus(); }
  function closePalette() { $("#palette").hidden = true; }

  // ------------------------------------------------------------------ stream --
  function connectStream() {
    const es = new EventSource("/api/stream");
    const state = (text, on) => { $("#link-state").textContent = text; $("#link-dot").className = `dot${on ? " on" : ""}`; };
    es.addEventListener("hello", () => state("live", true));
    es.addEventListener("error", () => state("reconnecting", false));
    es.addEventListener("message", (e) => onIncoming(JSON.parse(e.data)));
    es.addEventListener("conversation", () => loadConversations());
    es.addEventListener("burned", (e) => {
      const { conversation_id: cid, ids } = JSON.parse(e.data);
      const map = S.msgs.get(cid);
      if (map) ids.forEach((id) => { const rec = map.get(id); if (rec) burnAway(rec); });
    });
    const end = () => { es.close(); logout("expired"); };
    es.addEventListener("session_revoked", end);
    es.addEventListener("session_end", end);
  }

  // ------------------------------------------------------------------ wiring --
  function wire() {
    $("#nav-logout").addEventListener("click", () => logout());
    $("#open-palette").addEventListener("click", openPalette);
    $("#tab-dossier").addEventListener("click", () => selectTab("dossier"));
    $("#tab-packet").addEventListener("click", () => selectTab("packet"));

    $("#compose").addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = $("#compose-input");
      const text = input.value;
      input.value = "";
      await send(text);
      input.focus();
    });

    $("#cmd").addEventListener("keydown", async (e) => {
      if (e.key !== "Enter") return;
      const line = e.target.value.trim();
      e.target.value = "";
      if (line) await runCommand(line);
    });

    let searchTimer = null;
    $("#search").addEventListener("input", (e) => {
      clearTimeout(searchTimer);
      const q = e.target.value.trim().toLowerCase();
      searchTimer = setTimeout(async () => {
        const list = $("#results");
        list.textContent = "";
        if (!q) return;
        const { users } = await GhostAPI.get(`/api/directory?q=${encodeURIComponent(q)}`);
        if (!users.length) list.append(el("li", { class: "empty" }, "No handle matches."));
        for (const u of users) {
          list.append(el("li", { class: "contact result", role: "button", tabindex: "0", onclick: () => startChat(u),
                                 onkeydown: (ev) => { if (ev.key === "Enter") startChat(u); } },
            el("span", { class: "label" }, "+"), el("div", { class: "name" }, u.username), el("span", { class: "label" }, "open")));
        }
      }, 150);
    });

    $("#palette-input").addEventListener("input", refreshPalette);
    $("#palette-input").addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { palette.index = Math.min(palette.items.length - 1, palette.index + 1); drawPalette(); e.preventDefault(); }
      if (e.key === "ArrowUp") { palette.index = Math.max(0, palette.index - 1); drawPalette(); e.preventDefault(); }
      if (e.key === "Enter" && palette.items[palette.index]) { const item = palette.items[palette.index]; closePalette(); item.run(); }
    });
    $("#palette").addEventListener("click", (e) => { if (e.target.id === "palette") closePalette(); });

    document.addEventListener("keydown", (e) => {
      const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
      else if (e.key === "Escape") { closePalette(); $("#key-alert").hidden = true; }
      else if (e.altKey && e.key === "ArrowUp") { e.preventDefault(); cycleConversation(-1); }
      else if (e.altKey && e.key === "ArrowDown") { e.preventDefault(); cycleConversation(1); }
      else if (e.key === "/" && !typing) { e.preventDefault(); $("#cmd").focus(); }
      if (Date.now() - S.lastPing > KEEPALIVE_MS) keepalive();
    });
    document.addEventListener("pointerdown", () => { if (Date.now() - S.lastPing > KEEPALIVE_MS) keepalive(); }, { passive: true });
  }

  // -------------------------------------------------------------------- boot --
  async function boot() {
    try { S.me = await GhostAPI.get("/api/auth/me"); } catch { return logout("expired"); }
    S.keys = await GhostKeystore.loadIdentity().catch(() => null);
    if (!S.keys || S.keys.userId !== S.me.user.id) {
      toast("Keys missing", "This browser has no identity for this account. Sign in again.", "bad");
      return setTimeout(() => logout(), 1600);
    }
    if (S.keys.ecdhPub !== S.me.identity.ecdh_pub || S.keys.ecdsaPub !== S.me.identity.ecdsa_pub) {
      toast("Identity mismatch", "The server reports a different public key for you.", "bad");
    }
    S.myEcdsaPub = await GhostCrypto.importEcdsaPublic(S.me.identity.ecdsa_pub);
    S.serverKey = (await GhostAPI.get("/api/server-key")).public_key;

    $("#whoami").textContent = S.me.user.username;
    $("#prompt").textContent = `${S.me.user.username}@ghostline ~$`;
    $("#nav-admin").hidden = S.me.user.role !== "admin";
    applySession(S.me.session);
    tickSession();
    setInterval(tickSession, 1000);
    setInterval(tickBurns, 1000);

    wire();
    connectStream();
    await loadConversations();

    let last = null;
    try { last = localStorage.getItem("gl.active"); } catch { /* storage unavailable */ }
    if (last && S.convs.has(last)) await openConversation(last);
    else if (S.convs.size) await openConversation(sortedConvs()[0].id);
  }

  boot();
})();
