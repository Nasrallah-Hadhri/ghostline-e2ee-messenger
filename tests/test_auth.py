"""Week 2: zero-knowledge registration + login, Argon2id storage, input validation."""
import base64
import json

import pytest

import clientsim
from app.models import ROLE_USER, User, UserKey
from app.server_crypto import verify_directory_entry
from tests.conftest import PASSPHRASE


# --- Registration -------------------------------------------------------------

def test_register_creates_user_with_argon2id_and_signed_keys(app, api, db):
    resp, _ = api.register("alice")
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["user"]["username"] == "alice" and body["user"]["role"] == ROLE_USER

    user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    assert user.auth_hash.startswith("$argon2id$")
    assert PASSPHRASE not in user.auth_hash

    key = user.current_key
    assert verify_directory_entry(app.extensions["signing_key"].public_key(), key.server_sig,
                                  user_id=user.id, version=1,
                                  ecdh_pub=key.ecdh_pub, ecdsa_pub=key.ecdsa_pub)


def test_server_never_stores_plaintext_secrets(api, db):
    payload, identity = clientsim.registration_payload("alice", PASSPHRASE, 1000)
    api.post("/api/auth/register", payload)

    rows = []
    for table in ("users", "user_keys", "sessions"):
        rows += db.session.execute(db.text(f"SELECT * FROM {table}")).all()
    dump = json.dumps([[str(v) for v in row] for row in rows])
    assert PASSPHRASE not in dump
    assert payload["auth_key"] not in dump                           # only Argon2id(auth_key)
    assert clientsim.jwk(identity.ecdsa, private=True)["d"] not in dump  # private keys only wrapped


def test_register_sets_hardened_session_cookie(api):
    resp, _ = api.register("alice")
    cookie = next(h for h in resp.headers.getlist("Set-Cookie") if h.startswith("__Host-gl_session="))
    for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
        assert flag in cookie
    assert "Domain" not in cookie


def test_mass_assignment_role_is_ignored(api, db):
    resp, _ = api.register("mallory", role="admin", is_disabled=False)
    assert resp.status_code == 201
    assert resp.get_json()["user"]["role"] == ROLE_USER
    assert db.session.execute(db.select(User.role).filter_by(username="mallory")).scalar_one() == ROLE_USER


def test_duplicate_handle_rejected(api, make_api):
    assert api.register("alice")[0].status_code == 201
    assert make_api().register("alice")[0].status_code == 409


@pytest.mark.parametrize("username", ["ab", "Has Space", "x" * 33, "<script>", "admin'--", ""])
def test_invalid_handles_rejected(api, username):
    assert api.register(username)[0].status_code == 400


def test_uploading_private_key_is_rejected(api):
    payload, identity = clientsim.registration_payload("alice", PASSPHRASE, 1000)
    payload["identity"]["ecdsa_pub"] = clientsim.jwk(identity.ecdsa, private=True)
    resp = api.post("/api/auth/register", payload)
    assert resp.status_code == 400
    assert "private key material" in resp.get_json()["error"]


def test_invalid_curve_point_rejected(api):
    payload, _ = clientsim.registration_payload("alice", PASSPHRASE, 1000)
    payload["identity"]["ecdh_pub"]["y"] = clientsim.b64url_e(b"\x01" * 32)
    resp = api.post("/api/auth/register", payload)
    assert resp.status_code == 400 and "curve" in resp.get_json()["error"]


@pytest.mark.parametrize("field,value", [
    ("auth_key", base64.b64encode(b"short").decode()),
    ("auth_key", "not base64!!"),
    ("kdf_salt", base64.b64encode(b"x" * 8).decode()),
    ("kdf_iterations", 10),
    ("kdf_iterations", "1000"),
])
def test_malformed_crypto_fields_rejected(api, field, value):
    assert api.register("alice", **{field: value})[0].status_code == 400


def test_register_requires_csrf_token(api):
    payload, _ = clientsim.registration_payload("alice", PASSPHRASE, 1000)
    resp = api.post("/api/auth/register", payload, csrf=False)
    assert resp.status_code == 400
    assert "csrf" in resp.get_json()["error"]


# --- Login ----------------------------------------------------------------------

def test_full_login_unwraps_same_identity(api, make_api):
    _, identity = api.register("alice")
    browser2 = make_api()
    resp, wrap_key = browser2.login("alice")
    assert resp.status_code == 200
    body = resp.get_json()

    recovered = clientsim.open_identity(wrap_key, body["identity"]["wrapped_priv"],
                                        body["identity"]["wrap_iv"], "alice")
    assert recovered.ecdsa.private_numbers() == identity.ecdsa.private_numbers()
    assert recovered.ecdh.private_numbers() == identity.ecdh.private_numbers()


def test_wrong_passphrase_and_unknown_user_look_identical(api, make_api):
    api.register("alice")
    wrong, _ = make_api().login("alice", "not-the-right-passphrase")
    ghost, _ = make_api().login("nobody_here")
    assert wrong.status_code == ghost.status_code == 401
    assert wrong.get_json() == ghost.get_json() == {"error": "invalid credentials"}


def test_prelogin_does_not_reveal_which_handles_exist(api):
    api.register("alice")
    real = api.post("/api/auth/prelogin", {"username": "alice"}).get_json()
    fake1 = api.post("/api/auth/prelogin", {"username": "nobody"}).get_json()
    fake2 = api.post("/api/auth/prelogin", {"username": "nobody"}).get_json()

    assert set(real) == set(fake1)
    assert real["kdf_iterations"] == fake1["kdf_iterations"]
    assert len(base64.b64decode(fake1["kdf_salt"])) == len(base64.b64decode(real["kdf_salt"])) == 16
    assert fake1 == fake2  # stable, so repeated probing reveals nothing


def test_tampered_identity_blob_fails_authentication(api, make_api, db):
    api.register("alice")
    key = db.session.execute(db.select(UserKey)).scalar_one()
    blob = bytearray(base64.b64decode(key.wrapped_priv))
    blob[0] ^= 1
    key.wrapped_priv = base64.b64encode(bytes(blob)).decode()
    db.session.commit()

    resp, wrap_key = make_api().login("alice")
    body = resp.get_json()
    with pytest.raises(Exception):  # AES-GCM tag check fails
        clientsim.open_identity(wrap_key, body["identity"]["wrapped_priv"], body["identity"]["wrap_iv"], "alice")


def test_disabled_account_cannot_login(api, make_api, db):
    api.register("alice")
    db.session.execute(db.update(User).values(is_disabled=True))
    db.session.commit()
    assert make_api().login("alice")[0].status_code == 403


def test_login_sql_injection_payloads_fail_safely(api):
    api.register("alice")
    for probe in ("alice'--", "' OR '1'='1", "alice\" OR 1=1 --"):
        resp = api.post("/api/auth/login", {"username": probe, "auth_key": base64.b64encode(b"\0" * 32).decode()})
        assert resp.status_code == 401
