"""Week 1: app boots, schema enforces its invariants, server signing works."""
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.models import AuditLog, Conversation, Message, User, utcnow
from app.server_crypto import sign_directory_entry, verify_directory_entry
from config import get_config
from tests.conftest import promote_admin


def make_user(db, name, role="user"):
    user = User(username=name, auth_hash="x", kdf_salt="s", kdf_iterations=1000, role=role)
    db.session.add(user)
    db.session.commit()
    return user


# --- App / pages -----------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/register"])
def test_public_pages_render(api, path):
    resp = api.get(path)
    assert resp.status_code == 200
    assert b"GhostLine" in resp.data


@pytest.mark.parametrize("path", ["/terminal", "/profile"])
def test_app_pages_render_when_logged_in(api, path):
    api.register("alice")
    assert api.get(path).status_code == 200


def test_unknown_route_uses_themed_404(api):
    resp = api.get("/nope")
    assert resp.status_code == 404
    assert b"NODE NOT FOUND" in resp.data


def test_unknown_api_route_returns_json(api):
    resp = api.get("/api/nope")
    assert resp.status_code == 404 and resp.get_json() == {"error": "node not found"}


def test_pages_have_no_inline_scripts(api, db):
    # Week 3 enforces CSP script-src 'self'; keep templates compatible from day one.
    pages = {p: api.get(p).data.decode() for p in ("/", "/register")}
    api.register("alice")
    promote_admin(db, "alice")
    pages.update({p: api.get(p).data.decode() for p in ("/terminal", "/profile", "/admin/")})
    assert all(pages.values())
    for path, html in pages.items():
        for chunk in html.split("<script")[1:]:
            assert "src=" in chunk.split(">", 1)[0], f"inline <script> on {path}"


def test_flask_cookie_is_hardened(app):
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"
    assert app.config["AUTH_COOKIE_NAME"].startswith("__Host-")


def test_missing_secret_refuses_to_start(monkeypatch):
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv("SECRET_KEY", "x")
    with pytest.raises(RuntimeError, match="AUDIT_HMAC_KEY"):
        get_config("development")


# --- Schema ----------------------------------------------------------------

def test_all_tables_created(db):
    tables = set(inspect(db.engine).get_table_names())
    assert {"users", "user_keys", "sessions", "conversations",
            "messages", "audit_log", "invites"} <= tables


def test_user_ids_are_random_uuids(db):
    a, b = make_user(db, "alice"), make_user(db, "bob")
    assert len(a.id) == 36 and a.id != b.id


def test_username_unique(db):
    make_user(db, "alice")
    with pytest.raises(IntegrityError):
        make_user(db, "alice")


def test_role_restricted_to_known_values(db):
    with pytest.raises(IntegrityError):
        make_user(db, "mallory", role="superuser")


def test_lock_state(db):
    u = make_user(db, "alice")
    assert not u.is_locked()
    u.locked_until = utcnow() + timedelta(minutes=5)
    assert u.is_locked()


def test_conversation_pair_is_unique_and_ordered(db):
    a, b = make_user(db, "alice"), make_user(db, "bob")
    ua, ub = Conversation.ordered_pair(b.id, a.id)
    conv = Conversation(user_a=ua, user_b=ub)
    db.session.add(conv)
    db.session.commit()
    assert conv.has_participant(a.id) and conv.peer_of(a.id) == b.id

    db.session.add(Conversation(user_a=ua, user_b=ub))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    db.session.add(Conversation(user_a=ub, user_b=ua))  # wrong order violates CHECK
    with pytest.raises(IntegrityError):
        db.session.commit()


def test_message_counter_cannot_repeat(db):
    """DB-level replay protection: same (conversation, sender, counter) is rejected."""
    a, b = make_user(db, "alice"), make_user(db, "bob")
    conv = Conversation(user_a=min(a.id, b.id), user_b=max(a.id, b.id))
    db.session.add(conv)
    db.session.commit()

    def msg(counter):
        return Message(conversation_id=conv.id, sender_id=a.id, ciphertext="c",
                       iv="i", aad="a", signature="s", counter=counter)

    db.session.add_all([msg(1), msg(2)])
    db.session.commit()
    db.session.add(msg(2))
    with pytest.raises(IntegrityError):
        db.session.commit()


def test_foreign_keys_enforced(db):
    db.session.add(Message(conversation_id="does-not-exist", sender_id="nobody",
                           ciphertext="c", iv="i", aad="a", signature="s", counter=1))
    with pytest.raises(IntegrityError):
        db.session.commit()


def test_audit_hmac_unique(db):
    db.session.add(AuditLog(action="x", prev_hmac="0" * 64, hmac="a" * 64))
    db.session.add(AuditLog(action="y", prev_hmac="a" * 64, hmac="a" * 64))
    with pytest.raises(IntegrityError):
        db.session.commit()


# --- Server key-directory signatures (Ed25519) -----------------------------

def test_directory_signature_roundtrip_and_tamper_detection():
    key = Ed25519PrivateKey.generate()
    entry = dict(user_id="u1", version=1, ecdh_pub='{"kty":"EC"}', ecdsa_pub='{"kty":"EC"}')
    sig = sign_directory_entry(key, **entry)

    assert verify_directory_entry(key.public_key(), sig, **entry)
    assert not verify_directory_entry(key.public_key(), sig, **{**entry, "ecdh_pub": '{"evil":1}'})
    assert not verify_directory_entry(key.public_key(), sig, **{**entry, "version": 2})
    assert not verify_directory_entry(Ed25519PrivateKey.generate().public_key(), sig, **entry)
