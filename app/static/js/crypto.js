// GhostLine client-side cryptography (Web Crypto API).
//
//   master   = PBKDF2-SHA256(passphrase, kdf_salt, iterations)
//   auth_key = HKDF-SHA256(master, info="ghostline-auth-v1")  -> sent to server (it stores Argon2id(auth_key))
//   wrap_key = HKDF-SHA256(master, info="ghostline-wrap-v1")  -> AES-256-GCM key, never leaves the browser
//
// Identity = ECDH P-256 (encryption) + ECDSA P-256 (signatures). Private keys are
// sealed under wrap_key before upload; once opened they are re-imported as
// NON-extractable CryptoKeys, so even page scripts can't read the raw bytes.
//
// Mirrored in Python by clientsim/__init__.py — keep both in sync.
window.GhostCrypto = (() => {
  "use strict";
  const subtle = window.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const MIN_ITERATIONS = 100_000;          // refuse weak params even if a server offers them
  const HKDF_SALT = new Uint8Array(32);    // fixed zero salt; PBKDF2 already salted the input
  const INFO_AUTH = enc.encode("ghostline-auth-v1");
  const INFO_WRAP = enc.encode("ghostline-wrap-v1");
  const ECDH = { name: "ECDH", namedCurve: "P-256" };
  const ECDSA = { name: "ECDSA", namedCurve: "P-256" };

  const identityAad = (username) => enc.encode(`ghostline-identity-v1|${username}`);

  // --- encoding helpers ------------------------------------------------------
  const b64 = {
    encode(buf) {
      const bytes = new Uint8Array(buf);
      let s = "";
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s);
    },
    decode(str) {
      const s = atob(str);
      const out = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      return out;
    },
  };
  const randomBytes = (n) => window.crypto.getRandomValues(new Uint8Array(n));
  const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");

  // --- key schedule ------------------------------------------------------------
  async function deriveMaster(passphrase, salt, iterations) {
    if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS) {
      throw new Error("refusing weak KDF parameters from server");
    }
    const pw = await subtle.importKey("raw", enc.encode(passphrase.normalize("NFKC")),
                                      "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, pw, 256);
    return subtle.importKey("raw", bits, "HKDF", false, ["deriveBits", "deriveKey"]);
  }

  async function deriveAuthKey(master) {
    const bits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: INFO_AUTH }, master, 256);
    return b64.encode(bits);
  }

  function deriveWrapKey(master) {
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: INFO_WRAP },
      master, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // --- identity ----------------------------------------------------------------
  async function generateIdentity() {
    // Extractable only so the private halves can be sealed once; re-imported non-extractable after.
    const ecdh = await subtle.generateKey(ECDH, true, ["deriveBits"]);
    const ecdsa = await subtle.generateKey(ECDSA, true, ["sign", "verify"]);
    return { ecdh, ecdsa };
  }

  async function publicJwk(key) {
    const j = await subtle.exportKey("jwk", key);
    return { kty: j.kty, crv: j.crv, x: j.x, y: j.y };
  }

  async function privateJwk(key) {
    const j = await subtle.exportKey("jwk", key);
    return { kty: j.kty, crv: j.crv, x: j.x, y: j.y, d: j.d };
  }

  async function importPrivate(payload) {
    return {
      ecdhPriv: await subtle.importKey("jwk", payload.ecdh, ECDH, false, ["deriveBits"]),
      ecdsaPriv: await subtle.importKey("jwk", payload.ecdsa, ECDSA, false, ["sign"]),
    };
  }

  // Seal private keys under wrap_key. Returns the blob for the server and
  // non-extractable copies for local use.
  async function sealIdentity(wrapKey, identity, username) {
    const payload = {
      v: 1,
      ecdh: await privateJwk(identity.ecdh.privateKey),
      ecdsa: await privateJwk(identity.ecdsa.privateKey),
    };
    const iv = randomBytes(12);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: identityAad(username) },
                                    wrapKey, enc.encode(JSON.stringify(payload)));
    return {
      blob: { wrapped_priv: b64.encode(ct), wrap_iv: b64.encode(iv) },
      keys: await importPrivate(payload),
    };
  }

  async function openIdentity(wrapKey, wrappedPriv, wrapIv, username) {
    let plain;
    try {
      plain = await subtle.decrypt(
        { name: "AES-GCM", iv: b64.decode(wrapIv), additionalData: identityAad(username) },
        wrapKey, b64.decode(wrappedPriv));
    } catch {
      throw new Error("identity blob failed AES-GCM authentication (wrong key or tampered)");
    }
    return importPrivate(JSON.parse(dec.decode(plain)));
  }

  // Passphrase change: decrypt under the old wrap_key, re-encrypt under the new one.
  // The private JWKs exist only transiently here; stored CryptoKeys stay non-extractable.
  async function rewrapIdentity(oldWrapKey, newWrapKey, wrappedPriv, wrapIv, username) {
    let plain;
    try {
      plain = await subtle.decrypt(
        { name: "AES-GCM", iv: b64.decode(wrapIv), additionalData: identityAad(username) },
        oldWrapKey, b64.decode(wrappedPriv));
    } catch {
      throw new Error("current passphrase does not open your identity");
    }
    const iv = randomBytes(12);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: identityAad(username) },
                                    newWrapKey, plain);
    return { wrapped_priv: b64.encode(ct), wrap_iv: b64.encode(iv) };
  }

  // SHA-256 over the canonical JWK string the server stores and signs.
  async function fingerprint(canonicalJwk) {
    const digest = await subtle.digest("SHA-256", enc.encode(canonicalJwk));
    return hex(digest).match(/.{4}/g).join(" ");
  }

  async function digestHex(text) {
    return hex(await subtle.digest("SHA-256", enc.encode(text)));
  }

  // --- key directory (server Ed25519 signature) ------------------------------------
  // Canonical payload identical to server_crypto.directory_payload (sorted keys, no spaces).
  async function verifyDirectory(serverKeyB64, entry) {
    const payload = JSON.stringify({
      ecdh_pub: entry.ecdh_pub, ecdsa_pub: entry.ecdsa_pub, user_id: entry.user_id, version: entry.version,
    });
    let key;
    try {
      key = await subtle.importKey("raw", b64.decode(serverKeyB64), { name: "Ed25519" }, false, ["verify"]);
    } catch {
      throw new Error("this browser has no Ed25519 support; cannot verify the key directory");
    }
    return subtle.verify({ name: "Ed25519" }, key, b64.decode(entry.server_sig), enc.encode(payload));
  }

  // --- messages ------------------------------------------------------------------------
  //   K   = HKDF-SHA256(ECDH(my_priv, their_pub), salt=conversation_id, info="ghostline-msg-v1")
  //   ct  = AES-256-GCM(K, iv, plaintext, aad)
  //   sig = ECDSA-P256-SHA256(sender_priv, iv || aad || ct)
  const MSG_INFO = enc.encode("ghostline-msg-v1");

  function importEcdsaPublic(canonicalJwk) {
    return subtle.importKey("jwk", JSON.parse(canonicalJwk), ECDSA, false, ["verify"]);
  }

  async function conversationKey(myEcdhPriv, peerEcdhJwk, conversationId) {
    const peer = await subtle.importKey("jwk", JSON.parse(peerEcdhJwk), ECDH, false, []);
    const shared = await subtle.deriveBits({ name: "ECDH", public: peer }, myEcdhPriv, 256);
    const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode(conversationId), info: MSG_INFO },
      hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  const messageAad = (conv, sender, counter, ttl, version) =>
    `ghostline-msg-v1|${conv}|${sender}|${counter}|${ttl || 0}|${version}`;

  function concat(...parts) {
    const arrays = parts.map((p) => new Uint8Array(p));
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let offset = 0;
    for (const a of arrays) { out.set(a, offset); offset += a.length; }
    return out;
  }

  async function sealMessage({ aesKey, ecdsaPriv, conversationId, senderId, counter, ttl, keyVersion, plaintext }) {
    const iv = randomBytes(12);
    const aad = messageAad(conversationId, senderId, counter, ttl, keyVersion);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) },
                                    aesKey, enc.encode(plaintext));
    const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, ecdsaPriv,
                                  concat(iv, enc.encode(aad), ct));
    return {
      ciphertext: b64.encode(ct), iv: b64.encode(iv), aad, signature: b64.encode(sig),
      counter, ttl: ttl || null, sender_key_version: keyVersion,
    };
  }

  // Verify, then decrypt. Never throws: returns per-check results for the inspector.
  async function openMessage({ aesKey, senderEcdsaPub, envelope }) {
    const checks = { aad: false, signature: false, decrypt: false };
    const expectedAad = messageAad(envelope.conversation_id, envelope.sender_id, envelope.counter,
                                   (envelope.aad.split("|")[4] | 0) || null, envelope.sender_key_version);
    checks.aad = envelope.aad === expectedAad;
    const iv = b64.decode(envelope.iv);
    const ct = b64.decode(envelope.ciphertext);
    try {
      checks.signature = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, senderEcdsaPub,
                                             b64.decode(envelope.signature), concat(iv, enc.encode(envelope.aad), ct));
    } catch { checks.signature = false; }
    let plaintext = null;
    if (checks.signature && checks.aad) {
      try {
        plaintext = dec.decode(await subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: enc.encode(envelope.aad) }, aesKey, ct));
        checks.decrypt = true;
      } catch { checks.decrypt = false; }
    }
    return { plaintext, checks, ok: checks.aad && checks.signature && checks.decrypt };
  }

  // 60-digit safety number over both identities (order-independent), shown as 12 x 5 digits.
  async function safetyNumber(a, b) {
    const [first, second] = [a, b].sort((x, y) => (x.user_id < y.user_id ? -1 : 1));
    const text = [first.user_id, first.ecdh_pub, first.ecdsa_pub,
                  second.user_id, second.ecdh_pub, second.ecdsa_pub].join("|");
    const bytes = new Uint8Array(await subtle.digest("SHA-512", enc.encode(text)));
    const groups = [];
    for (let i = 0; i < 12; i++) {
      let n = 0;
      for (let j = 0; j < 5; j++) n = n * 256 + bytes[i * 5 + j];
      groups.push(String(n % 100000).padStart(5, "0"));
    }
    return groups;
  }

  return {
    b64, randomBytes, deriveMaster, deriveAuthKey, deriveWrapKey,
    generateIdentity, publicJwk, sealIdentity, openIdentity, rewrapIdentity,
    fingerprint, digestHex, verifyDirectory, importEcdsaPublic, conversationKey,
    messageAad, sealMessage, openMessage, safetyNumber,
  };
})();
