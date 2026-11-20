// JSON API wrapper: same-origin cookies + CSRF header on every request.
window.GhostAPI = (() => {
  "use strict";
  const csrfToken = () => document.querySelector('meta[name="csrf-token"]').content;

  async function request(method, url, body) {
    const res = await fetch(url, {
      method,
      credentials: "same-origin",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken(),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty or non-JSON body */ }
    if (!res.ok) {
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  return {
    get: (url) => request("GET", url),
    post: (url, body = {}) => request("POST", url, body),
  };
})();
