"""Week 4 findings, now verified fixed in week 5.

Each F-xx test asserts the secure behaviour and must pass. F-06 was reclassified
as an accepted risk (R-04): detecting tail truncation needs an external anchor,
out of scope for this project. R-01..R-03 document the zero-knowledge trade-offs.
"""
import base64

import pytest

import clientsim
from app import audit, create_app
from app.models import AuditLog, User
from config import get_config
from tests.conftest import Api, Member, promote_admin


def limited_client():
    """A test client whose app has per-IP rate limiting switched on."""
    return Api(create_app("testing", RATELIMIT_ENABLED=True))


# --- F-01 - brute force: account lockout --------------------------------------------------

def test_f01_login_locks_after_repeated_failures(api, make_api):
    api.register("victim")
    statuses = [make_api().login("victim", f"guess-{i:04d}-wrong")[0].status_code for i in range(12)]
    assert 423 in statuses  # account locked
    # a correct passphrase is also refused while locked
    assert make_api().login("victim")[0].status_code == 423


# --- F-02 - TOTP guessing shares one per-account budget ------------------------------------

def test_f02_mfa_budget_is_per_account(api, make_api, app):
    import pyotp
    api.register("victim")
    secret = api.post("/api/2fa/setup").get_json()["secret"]
    api.post("/api/2fa/enable", {"code": pyotp.TOTP(secret).now()})

    checked_guesses = 0
    for _round in range(3):  # attacker restarts the login flow to try to refill the budget
        make_api().login("victim")
        attacker = make_api()
        attacker.login("victim")
        for _ in range(app.config["MFA_MAX_FAILURES"] + 2):
            body = attacker.post("/api/auth/mfa", {"code": "000000"}).get_json()
            if body.get("error") == "invalid code":
                checked_guesses += 1
    assert checked_guesses <= app.config["MFA_MAX_FAILURES"]


# --- F-03 - oversized request body --------------------------------------------------------

def test_f03_oversized_body_rejected(api):
    assert api.post("/api/auth/prelogin", {"username": "x", "pad": "A" * (512 * 1024)}).status_code == 413


# --- F-04 - message counter is bounded ----------------------------------------------------

def test_f04_huge_counter_is_a_validation_error(members):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    assert alice.send(bob, conv, 2**70, "overflow").status_code == 400


# --- F-05 - admin input validation --------------------------------------------------------

def test_f05_admin_inputs_validated(members, db):
    promote_admin(db, "alice")
    alice = members["alice"].api
    assert alice.get("/api/admin/audit?limit=abc").status_code == 400
    resp = alice.client.open(f"/api/admin/users/{members['bob'].id}/role", method="POST", data="[1]",
                             content_type="application/json",
                             headers={"X-CSRFToken": alice.csrf(), "Referer": "https://localhost/"})
    assert resp.status_code == 400


# --- F-07 - registration is throttled -----------------------------------------------------

def test_f07_registration_is_throttled():
    c = limited_client()
    statuses = [c.register(f"bot{i:03d}")[0].status_code for i in range(8)]
    assert 429 in statuses


# --- F-08 - concurrent live streams are capped --------------------------------------------

def test_f08_stream_count_is_capped(members, app):
    alice = members["alice"].api
    cap = app.config["MAX_STREAMS_PER_USER"]
    # hold the streams open (buffered=False) so they stay subscribed while we add more
    held = [alice.client.get("/api/stream", buffered=False) for _ in range(cap)]
    assert all(r.status_code == 200 for r in held)
    assert alice.client.get("/api/stream", buffered=False).status_code == 429
    for r in held:
        r.close()


# --- F-09 - debugger off by default -------------------------------------------------------

def test_f09_debugger_off_by_default(monkeypatch):
    monkeypatch.delenv("GHOSTLINE_DEBUG", raising=False)
    assert get_config("development").DEBUG is False


# --- F-10 - server banner suppressed ------------------------------------------------------

def test_f10_no_server_version_banner(api):
    assert api.get("/").headers.get("Server") == "GhostLine"


# --- Accepted risks (documented, not fixed) -----------------------------------------------

def test_r04_audit_tail_truncation_is_an_accepted_risk(app, db):
    """R-04: the HMAC chain detects edits/deletes/reorders of existing rows, but
    deleting the newest rows only shortens a valid chain. Detecting that needs an
    external anchor (e.g. publishing the head HMAC); out of scope here."""
    for i in range(5):
        audit.record("test.event", details={"i": i})
    db.session.execute(db.delete(AuditLog).filter(AuditLog.id >= 4))
    db.session.commit()
    assert audit.verify_chain()["ok"] is True  # truncation not detected (known limitation)


def test_r01_passphrase_policy_is_client_side_only(api):
    """R-01: the server never sees the passphrase, so a user scripting the API can
    pick a weak one. Only that user's own account is affected."""
    assert api.register("weakling", "123")[0].status_code == 201


def test_r02_db_theft_allows_offline_guessing(api, db):
    """R-02: a stolen DB row (kdf_salt + wrapped_priv) permits offline guessing at
    PBKDF2 cost. Lockout does not help offline; a strong passphrase does."""
    api.register("alice", "summer2026")
    user = db.session.execute(db.select(User)).scalar_one()
    blob = user.current_key
    found = None
    for guess in ("password", "letmein", "summer2026"):
        master = clientsim.derive_master(guess, base64.b64decode(user.kdf_salt), user.kdf_iterations)
        try:
            clientsim.open_identity(clientsim.derive_wrap_key(master), blob.wrapped_priv, blob.wrap_iv, "alice")
            found = guess
            break
        except Exception:
            continue
    assert found == "summer2026"


def test_r03_first_contact_is_trust_on_first_use(members):
    """R-03: a first-seen key is checked only against the server's signature;
    safety-number comparison closes the gap."""
    entry = members["alice"].api.get(f"/api/users/{members['bob'].id}/identity").get_json()["identity"]
    assert entry["server_sig"]
