// Shared UI helpers. All text goes through textContent; nothing builds HTML strings.
window.GhostUI = (() => {
  "use strict";
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const GLYPHS = "ABCDEF0123456789/+=#%&$@<>[]{}*";

  // el("div", {class: "x", onclick: fn}, "text", childNode, ...)
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else if (k === "class") node.className = v;
      else if (k === "dataset") Object.assign(node.dataset, v);
      else node.setAttribute(k, v === true ? "" : v);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  const $ = (sel, root = document) => root.querySelector(sel);

  // Cipher-to-plaintext reveal: each character cycles through glyphs, then locks in.
  function scramble(node, text, { duration = 520, from = null } = {}) {
    if (reduceMotion || text.length > 600) { node.textContent = text; return Promise.resolve(); }
    const start = performance.now();
    const source = from || text.replace(/\S/g, () => GLYPHS[(Math.random() * GLYPHS.length) | 0]);
    return new Promise((resolve) => {
      function frame(now) {
        const t = Math.min(1, (now - start) / duration);
        const settled = Math.floor(t * text.length);
        let out = text.slice(0, settled);
        for (let i = settled; i < text.length; i++) {
          out += /\s/.test(text[i]) ? text[i]
            : (Math.random() < 0.35 ? GLYPHS[(Math.random() * GLYPHS.length) | 0] : (source[i] || " "));
        }
        node.textContent = out;
        if (t < 1) requestAnimationFrame(frame); else { node.textContent = text; resolve(); }
      }
      requestAnimationFrame(frame);
    });
  }

  // 5x5 mirrored identicon derived from a hex digest (key fingerprint).
  function identicon(hex, size = 28) {
    const canvas = el("canvas", { class: size > 40 ? "identicon lg" : "identicon", width: 5, height: 5,
                                  "aria-hidden": "true" });
    const ctx = canvas.getContext("2d");
    const bytes = hex.replace(/\s/g, "").match(/../g).map((h) => parseInt(h, 16));
    const tones = ["#3f8cff", "#2f6ad0", "#58b6e0", "#3ecf8e", "#8aa0c4"];
    ctx.fillStyle = tones[bytes[0] % tones.length];
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 3; x++) {
        if (bytes[1 + y * 3 + x] & 1) {
          ctx.fillRect(x, y, 1, 1);
          ctx.fillRect(4 - x, y, 1, 1);
        }
      }
    }
    return canvas;
  }

  let toastRoot = null;
  function toast(title, text, kind = "") {
    if (!toastRoot) { toastRoot = el("div", { class: "toasts", role: "status", "aria-live": "polite" }); document.body.append(toastRoot); }
    const node = el("div", { class: `toast ${kind}` }, el("b", {}, title), text || "");
    toastRoot.append(node);
    setTimeout(() => node.remove(), 4200);
  }

  function clock(iso) {
    const d = new Date(iso);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  }

  function ago(iso) {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  function short(text, n = 10) { return text && text.length > n ? `${text.slice(0, n)}…` : text; }

  async function copy(text, what = "value") {
    try { await navigator.clipboard.writeText(text); toast("Copied", what, "ok"); }
    catch { toast("Copy failed", "clipboard not available", "bad"); }
  }

  // One-time-code field: ONE real <input> (so typing, paste and OS autofill all just work)
  // laid invisibly over six display cells.
  function otp(container, onComplete) {
    const input = container.querySelector("input");
    const cells = Array.from({ length: 6 }, () => el("span", { class: "cell", "aria-hidden": "true" }));
    container.append(...cells);

    function render() {
      const v = input.value;
      const focused = document.activeElement === input;
      cells.forEach((cell, i) => {
        cell.textContent = v[i] || "";
        cell.classList.toggle("active", focused && i === Math.min(v.length, 5));
      });
    }
    input.addEventListener("input", () => {
      input.value = input.value.replace(/\D/g, "").slice(0, 6);
      render();
      if (input.value.length === 6) onComplete(input.value);
    });
    input.addEventListener("focus", render);
    input.addEventListener("blur", render);
    render();
    return {
      clear() { input.value = ""; render(); input.focus(); },
      focus() { input.focus(); },
      value: () => input.value,
    };
  }

  return { el, $, scramble, identicon, toast, clock, ago, short, copy, otp, reduceMotion };
})();
