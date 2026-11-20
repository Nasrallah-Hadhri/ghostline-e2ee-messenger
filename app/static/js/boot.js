// Step log for long crypto operations: "label … ok", with a cursor on the running step.
// Text is inserted with textContent only (never innerHTML).
window.GhostBoot = (() => {
  "use strict";
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const CLASS = { OK: "ok", FAIL: "fail", WARN: "warn" };

  function tag(row, status) {
    row.classList.remove("run");
    const t = document.createElement("span");
    t.className = CLASS[status] || "";
    t.textContent = ` ${status.toLowerCase()}`;
    row.appendChild(t);
  }

  function line(el, text, status) {
    const row = document.createElement("div");
    row.textContent = text;
    if (status) tag(row, status);
    el.appendChild(row);
    return row;
  }

  // Run each step.task(); print OK / FAIL. Throws the first failure after logging it.
  async function run(el, steps, { clear = true } = {}) {
    if (clear) el.textContent = "";
    for (const step of steps) {
      const row = line(el, step.label);
      row.classList.add("run");
      try {
        await Promise.all([step.task ? step.task() : null, sleep(step.delay ?? 160)]);
        tag(row, "OK");
      } catch (err) {
        tag(row, "FAIL");
        line(el, `  ${err && err.message ? err.message : "operation failed"}`).className = "fail";
        throw err;
      }
    }
  }

  return { run, line, sleep };
})();
