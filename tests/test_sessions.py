"""Week 2: server-side sessions (hashing, rotation, revocation, timeouts)."""
from datetime import timedelta

from app.auth.sessions import hash_token
from app.models import AuthSession, utcnow

COOKIE = "__Host-gl_session"


def _only_session(db):
    return db.session.execute(db.select(AuthSession).filter_by(revoked=False)).scalar_one()


def test_token_stored_only_as_sha256(api, db):
    api.register("alice")
    token = api.cookie(COOKIE)
    session = _only_session(db)
    assert session.token_hash == hash_token(token)
    assert token not in session.token_hash


def test_me_requires_session(api):
    assert api.get("/api/auth/me").status_code == 401
    api.register("alice")
    me = api.get("/api/auth/me").get_json()
    assert me["user"]["username"] == "alice"
    assert "wrapped_priv" not in me["identity"]
    assert 0 < me["session"]["idle_remaining_s"] <= 15 * 60


def test_protected_pages_redirect_when_anonymous(api):
    for path in ("/terminal", "/admin/"):
        resp = api.get(path)
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/")


def test_login_rotates_session_token(api, make_api):
    api.register("alice")
    first = api.cookie(COOKIE)
    api.login("alice")
    second = api.cookie(COOKIE)
    assert first != second

    stale = make_api()
    stale.client.set_cookie(COOKIE, first, domain="localhost", secure=True)
    assert stale.get("/api/auth/me").status_code == 401


def test_logout_revokes_server_side(api, make_api):
    api.register("alice")
    stolen = api.cookie(COOKIE)
    assert api.logout().status_code == 200
    assert api.cookie(COOKIE) is None

    attacker = make_api()
    attacker.client.set_cookie(COOKIE, stolen, domain="localhost", secure=True)
    assert attacker.get("/api/auth/me").status_code == 401


def test_idle_timeout(api, db):
    api.register("alice")
    session = _only_session(db)
    session.last_seen = utcnow() - timedelta(minutes=16)
    db.session.commit()
    assert api.get("/api/auth/me").status_code == 401
    assert api.cookie(COOKIE) is None  # stale cookie cleared


def test_absolute_timeout(api, db):
    api.register("alice")
    session = _only_session(db)
    session.expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    assert api.get("/api/auth/me").status_code == 401


def test_forged_token_rejected(api):
    api.register("alice")
    api.client.set_cookie(COOKIE, "A" * 43, domain="localhost", secure=True)
    assert api.get("/api/auth/me").status_code == 401


def test_logout_requires_csrf(api):
    api.register("alice")
    assert api.post("/api/auth/logout", csrf=False).status_code == 400
    assert api.get("/api/auth/me").status_code == 200
