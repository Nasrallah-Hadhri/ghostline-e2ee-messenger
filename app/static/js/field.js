// Auth-page background: a dim field of ciphertext. Around the pointer the
// glyphs "decrypt" into a readable phrase, like a lens passing over the noise.
(() => {
  "use strict";
  const canvas = document.getElementById("field");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const GLYPHS = "0123456789abcdef";
  const PLAIN = "the server only ever sees ciphertext · ";
  const CELL_W = 11;
  const CELL_H = 18;
  const RADIUS = 120;
  const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  let cols = 0, rows = 0, grid = [];
  let mouse = { x: -9999, y: -9999 };
  let dpr = 1;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = innerWidth * dpr;
    canvas.height = innerHeight * dpr;
    canvas.style.width = `${innerWidth}px`;
    canvas.style.height = `${innerHeight}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = "13px 'Plex Mono', monospace";
    ctx.textBaseline = "top";
    cols = Math.ceil(innerWidth / CELL_W);
    rows = Math.ceil(innerHeight / CELL_H);
    grid = Array.from({ length: cols * rows }, () => GLYPHS[(Math.random() * 16) | 0]);
    draw();
  }

  function draw() {
    ctx.clearRect(0, 0, innerWidth, innerHeight);
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const x = c * CELL_W, y = r * CELL_H;
        const d = Math.hypot(x - mouse.x, y - mouse.y);
        const i = r * cols + c;
        if (d < RADIUS) {
          const k = 1 - d / RADIUS;
          ctx.fillStyle = `rgba(63,140,255,${0.25 + k * 0.75})`;
          ctx.fillText(k > 0.35 ? PLAIN[(i + r * 7) % PLAIN.length] : grid[i], x, y);
        } else {
          ctx.fillStyle = "rgba(111,125,150,0.14)";
          ctx.fillText(grid[i], x, y);
        }
      }
    }
  }

  // Slowly mutate a few cells so the noise feels alive without being busy.
  function tick() {
    for (let n = 0; n < Math.max(4, (cols * rows) / 300); n++) {
      grid[(Math.random() * grid.length) | 0] = GLYPHS[(Math.random() * 16) | 0];
    }
    draw();
  }

  addEventListener("resize", resize);
  addEventListener("pointermove", (e) => { mouse = { x: e.clientX, y: e.clientY }; if (still) draw(); }, { passive: true });
  addEventListener("pointerleave", () => { mouse = { x: -9999, y: -9999 }; draw(); });
  document.fonts.ready.then(resize);
  resize();
  if (!still) setInterval(tick, 90);
})();
