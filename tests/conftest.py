import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import clientsim  # noqa: E402
from app import create_app  # noqa: E402
from app.extensions import db as _db  # noqa: E402

PASSPHRASE = "correct-horse-battery-staple"


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def db(app):
    return _db


class Api:
    """Test client that behaves like the browser: HTTPS, CSRF header, same-origin Referer."""

    def __init__(self, app):
        self.app = app
        self.client = app.test_client()
        self._csrf = None

    def csrf(self) -> str:
        if self._csrf is None:
            html = self.get("/register").get_data(as_text=True)
            self._csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
        return self._csrf

    def _request(self, method, url, **kw):
        # Fresh app context per request (as in production): the fixture keeps one
        # open for DB assertions, and Flask would otherwise share `g` across clients.
        with self.app.app_context():
            return self.client.open(url, method=method, **kw)

    def get(self, url, **kw):
        return self._request("GET", url, **kw)

    def post(self, url, json=None, csrf=True, headers=None):
        hdrs = {"Referer": "https://localhost/"}
        if csrf:
            hdrs["X-CSRFToken"] = self.csrf()
        hdrs.update(headers or {})
        return self._request("POST", url, json=json if json is not None else {}, headers=hdrs)

    def cookie(self, name):
        c = self.client.get_cookie(name)
        return c.value if c else None

    # High-level flows, done exactly like the browser does them
    def register(self, username, passphrase=PASSPHRASE, **overrides):
        payload, identity = clientsim.registration_payload(
            username, passphrase, self.app.config["KDF_ITERATIONS"])
        payload.update(overrides)
        return self.post("/api/auth/register", payload), identity

    def login(self, username, passphrase=PASSPHRASE):
        params = self.post("/api/auth/prelogin", {"username": username}).get_json()
        auth_key, wrap_key = clientsim.login_keys(passphrase, params["kdf_salt"], params["kdf_iterations"])
        resp = self.post("/api/auth/login", {"username": username, "auth_key": auth_key})
        return resp, wrap_key

    def logout(self):
        return self.post("/api/auth/logout")


@pytest.fixture
def api(app):
    return Api(app)


@pytest.fixture
def make_api(app):
    """Factory for extra independent browsers (separate cookie jars)."""
    return lambda: Api(app)


class Member:
    """A logged-in browser plus its private identity (what only the client knows)."""

    def __init__(self, api: Api, username: str):
        resp, self.identity = api.register(username)
        assert resp.status_code == 201, resp.get_json()
        self.api = api
        self.username = username
        self.id = resp.get_json()["user"]["id"]
        self.public = resp.get_json()["identity"]

    def open_conversation(self, peer: "Member") -> str:
        resp = self.api.post("/api/conversations", {"peer_id": peer.id})
        assert resp.status_code in (200, 201), resp.get_json()
        return resp.get_json()["conversation"]["id"]

    def envelope(self, peer: "Member", conv_id: str, counter: int, text: str, ttl=None) -> dict:
        return clientsim.seal_message(self.identity, peer.public["ecdh_pub"], conv_id, self.id,
                                      counter, text, ttl=ttl)

    def send(self, peer: "Member", conv_id: str, counter: int, text: str, ttl=None):
        return self.api.post(f"/api/conversations/{conv_id}/messages",
                             self.envelope(peer, conv_id, counter, text, ttl))


@pytest.fixture
def members(make_api):
    return {name: Member(make_api(), name) for name in ("alice", "bob", "charlie")}


def promote_admin(db, username: str, with_2fa: bool = True):
    """Make `username` an admin directly in the DB; returns a pyotp.TOTP for it (or None)."""
    import pyotp

    from app.auth import mfa
    from app.models import ROLE_ADMIN, User

    user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one()
    user.role = ROLE_ADMIN
    totp = None
    if with_2fa:
        secret = pyotp.random_base32()
        user.totp_secret_enc = mfa.encrypt_secret(user, secret)
        user.totp_enabled = True
        totp = pyotp.TOTP(secret)
    db.session.commit()
    return totp
