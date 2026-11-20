"""Week 3: passphrase change, own-session management, HTTP security headers."""
import base64
import os

import clientsim
from tests.conftest import PASSPHRASE

NEW_PASSPHRASE = "a-brand-new-passphrase-2026"


def _change_password(api, username, old, new, identity):
    params = api.post("/api/auth/prelogin", {"username": username}).get_json()
    current_auth, _ = clientsim.login_keys(old, params["kdf_salt"], params["kdf_iterations"])
    salt = os.urandom(16)
    master = clientsim.derive_master(new, salt, api.app.config["KDF_ITERATIONS"])
    sealed = clientsim.seal_identity(clientsim.derive_wrap_key(master), identity, username)
    return api.post("/api/auth/password", {
        "current_auth_key": current_auth, "new_auth_key": clientsim.derive_auth_key(master),
        "new_kdf_salt": base64.b64encode(salt).decode(), **sealed})


def test_change_passphrase_rewraps_identity_and_revokes_other_sessions(api, make_api):
    _, identity = api.register("alice")
    other = make_api()
    other.login("alice")

    assert _change_password(api, "alice", PASSPHRASE, NEW_PASSPHRASE, identity).status_code == 200
    assert other.get("/api/auth/me").status_code == 401          # other device logged out
    assert api.get("/api/auth/me").status_code == 200             # this one continues (rotated)

    assert make_api().login("alice", PASSPHRASE)[0].status_code == 401
    resp, wrap_key = make_api().login("alice", NEW_PASSPHRASE)
    body = resp.get_json()["identity"]
    reopened = clientsim.open_identity(wrap_key, body["wrapped_priv"], body["wrap_iv"], "alice")
    assert reopened.ecdsa.private_numbers() == identity.ecdsa.private_numbers()  # same identity


def test_change_passphrase_requires_current(api):
    _, identity = api.register("alice")
    assert _change_password(api, "alice", "not-my-passphrase", NEW_PASSPHRASE, identity).status_code == 403


def test_list_and_revoke_own_sessions(api, make_api):
    api.register("alice")
    laptop = make_api()
    laptop.login("alice")
    listed = api.get("/api/auth/sessions").get_json()["sessions"]
    assert len(listed) == 2 and sum(s["current"] for s in listed) == 1

    other_id = next(s["id"] for s in listed if not s["current"])
    current_id = next(s["id"] for s in listed if s["current"])
    assert api.post(f"/api/auth/sessions/{current_id}/revoke").status_code == 400
    assert api.post(f"/api/auth/sessions/{other_id}/revoke").status_code == 200
    assert laptop.get("/api/auth/me").status_code == 401


def test_security_headers_on_pages(api):
    h = api.get("/").headers
    csp = h["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "object-src 'none'",
                      "frame-ancestors 'none'", "base-uri 'none'"):
        assert directive in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "max-age=31536000" in h["Strict-Transport-Security"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["Referrer-Policy"] == "same-origin"
    assert "camera=()" in h["Permissions-Policy"]


def test_api_responses_are_not_cached(api):
    api.register("alice")
    assert api.get("/api/auth/me").headers["Cache-Control"] == "no-store"


def test_identity_blob_is_own_only(members):
    alice = members["alice"]
    blob = alice.api.get("/api/auth/identity-blob").get_json()["identity"]
    assert blob["user_id"] == alice.id and "wrapped_priv" in blob
    assert members["bob"].api.get("/api/auth/identity-blob").get_json()["identity"]["user_id"] == members["bob"].id
