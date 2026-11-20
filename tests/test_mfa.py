"""Week 3: TOTP second factor (enrolment, login step, replay, brute force, storage)."""
import time

import pyotp

from app.auth import mfa
from app.models import User
from tests.conftest import promote_admin

COOKIE = "__Host-gl_session"


def _enroll(api) -> pyotp.TOTP:
    setup = api.post("/api/2fa/setup").get_json()
    totp = pyotp.TOTP(setup["secret"])
    assert setup["qr_data_uri"].startswith("data:image/svg+xml;base64,")
    assert api.post("/api/2fa/enable", {"code": totp.now()}).status_code == 200
    return totp


def _code_for_next_step(totp):
    return totp.at(time.time() + 30)  # inside the accepted window, different step than now()


def test_enrolment_requires_a_valid_code(api):
    api.register("alice")
    api.post("/api/2fa/setup")
    assert api.post("/api/2fa/enable", {"code": "000000"}).status_code == 400
    assert api.get("/api/auth/me").get_json()["user"]["totp_enabled"] is False


def test_login_with_2fa_full_flow(api, make_api):
    api.register("alice")
    totp = _enroll(api)

    browser = make_api()
    resp, wrap_key = browser.login("alice")
    assert resp.status_code == 200 and resp.get_json() == {"mfa_required": True}
    pending_token = browser.cookie(COOKIE)

    # password-only session grants nothing
    assert browser.get("/api/auth/me").status_code == 401
    assert browser.get("/api/conversations").status_code == 401
    assert browser.get("/terminal").status_code == 302

    assert browser.post("/api/auth/mfa", {"code": "123456"}).status_code == 401
    ok = browser.post("/api/auth/mfa", {"code": _code_for_next_step(totp)})
    assert ok.status_code == 200 and "wrapped_priv" in ok.get_json()["identity"]
    assert browser.cookie(COOKIE) != pending_token  # rotated after the second factor
    assert browser.get("/api/auth/me").status_code == 200


def test_totp_code_cannot_be_replayed(api, make_api):
    api.register("alice")
    totp = _enroll(api)
    code = _code_for_next_step(totp)

    first = make_api()
    first.login("alice")
    assert first.post("/api/auth/mfa", {"code": code}).status_code == 200

    second = make_api()
    second.login("alice")
    assert second.post("/api/auth/mfa", {"code": code}).status_code == 401


def test_mfa_brute_force_locks_account(api, make_api, app):
    api.register("alice")
    _enroll(api)
    browser = make_api()
    browser.login("alice")
    for _ in range(app.config["MFA_MAX_FAILURES"]):
        last = browser.post("/api/auth/mfa", {"code": "000000"})
    assert last.status_code == 423  # account locked, pending session revoked
    # the lockout persists across a fresh login attempt (F-02)
    assert make_api().login("alice")[0].status_code == 423


def test_secret_encrypted_at_rest_and_bound_to_user(api, make_api, db):
    api.register("alice")
    secret = api.post("/api/2fa/setup").get_json()["secret"]
    make_api().register("bob")
    alice, bob = (db.session.execute(db.select(User).filter_by(username=n)).scalar_one() for n in ("alice", "bob"))

    assert secret.encode() not in alice.totp_secret_enc
    assert mfa.decrypt_secret(alice) == secret
    bob.totp_secret_enc = alice.totp_secret_enc  # copy ciphertext to another account
    assert mfa.decrypt_secret(bob) is None       # AAD (user id) mismatch -> GCM tag fails


def test_admins_cannot_disable_2fa(members, db):
    totp = promote_admin(db, "alice")
    resp = members["alice"].api.post("/api/2fa/disable", {"code": totp.now()})
    assert resp.status_code == 403


def test_user_can_disable_2fa_with_code(api):
    api.register("alice")
    totp = _enroll(api)
    assert api.post("/api/2fa/disable", {"code": _code_for_next_step(totp)}).status_code == 200
    assert api.get("/api/auth/me").get_json()["user"]["totp_enabled"] is False


def test_verify_code_rejects_garbage(app, db, api):
    api.register("alice")
    alice = db.session.execute(db.select(User)).scalar_one()
    for junk in (None, 123456, "12345", "abcdef", "1234567", ""):
        assert mfa.verify_code(alice, junk) is False
