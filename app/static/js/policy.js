// Passphrase policy, enforced in the browser: in the zero-knowledge model the
// server never sees the passphrase, so it cannot check it.
window.GhostPolicy = (() => {
  "use strict";
  const USERNAME = /^[a-z0-9_]{3,32}$/;
  const MIN_LENGTH = 12;

  // Common long passwords and keyboard walks that pass a naive length check.
  const DENYLIST = new Set([
    "password1234", "password12345", "password123456", "passwordpassword", "123456789012",
    "1234567890123", "12345678901234", "qwertyuiop12", "qwertyuiopasdf", "qwerty123456",
    "azertyuiop12", "azerty123456", "iloveyou1234", "abcdefghijkl", "abc123abc123",
    "letmein12345", "welcome12345", "administrator", "admin1234567", "trustno1trustno1",
    "monkey123456", "dragon123456", "football1234", "baseball1234", "sunshine1234",
    "superman1234", "princess1234", "000000000000", "111111111111", "changeme1234",
    "ghostline123", "ghostline1234", "correcthorsebatterystaple",
  ]);
  const SEQUENCES = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "azertyuiop"];

  function isSequential(pw) {
    const s = pw.toLowerCase();
    return SEQUENCES.some((seq) => seq.includes(s) || [...seq].reverse().join("").includes(s));
  }

  // Rough entropy estimate (bits) for the strength meter.
  function entropyBits(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    return Math.round(pw.length * Math.log2(Math.max(pool, 1)));
  }

  // Returns a list of human-readable problems (empty = acceptable).
  function checkPassphrase(pw, username) {
    const problems = [];
    const lower = pw.toLowerCase();
    if (pw.length < MIN_LENGTH) problems.push(`passphrase must be at least ${MIN_LENGTH} characters`);
    if (DENYLIST.has(lower.replace(/[\s\-_.]/g, ""))) problems.push("passphrase is on the common-password list");
    if (/^(.)\1+$/.test(pw)) problems.push("passphrase is a single repeated character");
    if (pw.length >= MIN_LENGTH && isSequential(pw)) problems.push("passphrase is a keyboard/alphabet sequence");
    if (username && username.length >= 3 && lower.includes(username.toLowerCase())) {
      problems.push("passphrase must not contain your handle");
    }
    return problems;
  }

  const checkUsername = (u) => (USERNAME.test(u) ? [] : ["handle must be 3-32 chars of [a-z0-9_]"]);

  return { checkPassphrase, checkUsername, entropyBits, MIN_LENGTH };
})();
