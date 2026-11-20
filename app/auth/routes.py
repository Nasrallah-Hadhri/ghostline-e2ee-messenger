"""Authentication: pages + JSON API.

prelogin -> login (-> mfa) -> me / sessions / password / 2fa / logout

Defences (week 5): per-IP rate limits on the auth endpoints and per-account
lockout after repeated failures (covers both password and TOTP guessing).
"""
from datetime import timedelta

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request, url_for

from .. import audit
from ..authz import login_required
from ..extensions import db, limiter
from ..models import ROLE_ADMIN, AuthSession, User, UserKey, utcnow
from . import mfa, sessions
from .security import (AUTH_KEY_BYTES, KDF_SALT_BYTES, MAX_WRAPPED_BYTES, WRAP_IV_BYTES,
                       ValidationError, b64e, decode_b64, fake_kdf_salt, hash_auth_key,
                       needs_rehash, normalize_username, verify_auth_key)
from .service import UsernameTaken, register_user

bp = Blueprint("auth", __name__)

INVALID_CREDENTIALS = "invalid credentials"
ACCOUNT_LOCKED = "too many failed attempts; try again later"


def _login_limit():
    return current_app.config["RATELIMIT_LOGIN"]


def _register_limit():
    return current_app.config["RATELIMIT_REGISTER"]


def register_failure(user: User) -> bool:
    """Count one auth failure (password or TOTP). Returns True once the account locks."""
    user.failed_attempts += 1
    if user.failed_attempts >= current_app.config["MAX_FAILED_LOGINS"]:
        user.locked_until = utcnow() + current_app.config["LOCKOUT_DURATION"]
        return True
    return False


def clear_failures(user: User) -> None:
    user.failed_attempts = 0
    user.locked_until = None


# --- Pages -------------------------------------------------------------------

@bp.get("/")
def login():
    if g.user:
        return redirect(url_for("chat.terminal"))
    return render_template("login.html")


@bp.get("/register")
def register():
    if g.user:
        return redirect(url_for("chat.terminal"))
    return render_template("register.html")


@bp.get("/profile")
@login_required
def profile():
    return render_template("profile.html")


# --- Helpers -----------------------------------------------------------------

def _json_body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def user_json(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role,
            "totp_enabled": user.totp_enabled}


def identity_json(key: UserKey, include_wrapped: bool = False) -> dict:
    data = {"user_id": key.user_id, "version": key.version, "ecdh_pub": key.ecdh_pub,
            "ecdsa_pub": key.ecdsa_pub, "server_sig": key.server_sig}
    if include_wrapped:
        data.update(wrapped_priv=key.wrapped_priv, wrap_iv=key.wrap_iv)
    return data


def _auth_response(user: User, status: int = 200):
    return jsonify(user=user_json(user),
                   identity=identity_json(user.current_key, include_wrapped=True),
                   session=sessions.session_info(g.auth_session)), status


def _replace_current_session(user: User, mfa_pending: bool = False) -> None:
    """Rotate: revoke whatever session the browser had, issue a brand-new token."""
    if g.get("auth_session") is not None or g.get("pending_session") is not None:
        sessions.end_session()
    sessions.start_session(user, mfa_pending=mfa_pending)


# --- Registration / login ---------------------------------------------------------

@bp.post("/api/auth/prelogin")
@limiter.limit(_login_limit)
def prelogin():
    """Return the KDF salt for a handle. Unknown handles get a stable fake salt."""
    try:
        username = normalize_username(_json_body().get("username"))
    except ValidationError:
        username = None

    user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none() \
        if username else None
    if user:
        return jsonify(kdf_salt=user.kdf_salt, kdf_iterations=user.kdf_iterations)
    return jsonify(kdf_salt=fake_kdf_salt(username or ""),
                   kdf_iterations=current_app.config["KDF_ITERATIONS"])


@bp.post("/api/auth/register")
@limiter.limit(_register_limit)
def register_api():
    try:
        user = register_user(_json_body())
    except ValidationError as err:
        return jsonify(error=str(err)), 400
    except UsernameTaken:
        return jsonify(error="handle unavailable"), 409

    _replace_current_session(user)
    db.session.commit()
    audit.record("auth.register", target=user.id, actor_id=user.id, details={"username": user.username})
    return _auth_response(user, 201)


@bp.post("/api/auth/login")
@limiter.limit(_login_limit)
def login_api():
    data = _json_body()
    raw_name = data.get("username") if isinstance(data.get("username"), str) else ""
    try:
        username = normalize_username(raw_name)
        auth_key = decode_b64(data.get("auth_key"), "auth_key", length=AUTH_KEY_BYTES)
    except ValidationError:
        verify_auth_key(None, b"\0" * AUTH_KEY_BYTES)  # same cost as a real attempt
        audit.record("auth.login.fail", details={"username": raw_name[:32], "why": "malformed"})
        return jsonify(error=INVALID_CREDENTIALS), 401

    user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

    # Account lockout: refuse before spending work, with the same generic message.
    if user and user.is_locked():
        audit.record("auth.login.locked", target=user.id, details={"username": username})
        return jsonify(error=ACCOUNT_LOCKED), 423

    if not verify_auth_key(user.auth_hash if user else None, auth_key):
        locked = register_failure(user) if user else False
        db.session.commit()
        audit.record("auth.login.fail", target=user.id if user else None,
                     details={"username": username, "why": "bad credentials", "locked": locked})
        return jsonify(error=ACCOUNT_LOCKED if locked else INVALID_CREDENTIALS), 423 if locked else 401
    if user.is_disabled:
        audit.record("auth.login.fail", target=user.id, details={"username": username, "why": "disabled"})
        return jsonify(error="account disabled"), 403

    if needs_rehash(user.auth_hash):
        user.auth_hash = hash_auth_key(auth_key)

    if user.totp_enabled:
        clear_failures(user)  # password proven; TOTP step has its own budget below
        _replace_current_session(user, mfa_pending=True)
        db.session.commit()
        audit.record("auth.login.password_ok", target=user.id, actor_id=user.id)
        return jsonify(mfa_required=True)

    clear_failures(user)
    user.last_login = utcnow()
    _replace_current_session(user)
    db.session.commit()
    audit.record("auth.login.ok", target=user.id, actor_id=user.id)
    return _auth_response(user)


@bp.post("/api/auth/mfa")
@limiter.limit(_login_limit)
def mfa_api():
    """Second step: exchange a valid TOTP code for a full session."""
    pending: AuthSession | None = g.get("pending_session")
    if pending is None:
        return jsonify(error="no pending authentication"), 401
    user = pending.user
    if user.is_locked():
        sessions.end_session()
        db.session.commit()
        return jsonify(error=ACCOUNT_LOCKED), 423

    if not mfa.verify_code(user, _json_body().get("code")):
        # Count TOTP guesses against the same per-account budget as passwords, so
        # restarting the login flow cannot refill it.
        locked = register_failure(user)
        if locked:
            sessions.end_session()
        db.session.commit()
        audit.record("auth.mfa.fail", target=user.id, actor_id=user.id,
                     details={"failures": user.failed_attempts, "locked": locked})
        if locked:
            return jsonify(error=ACCOUNT_LOCKED), 423
        return jsonify(error="invalid code"), 401

    clear_failures(user)
    user.last_login = utcnow()
    _replace_current_session(user)  # privilege change -> new token
    db.session.commit()
    audit.record("auth.login.ok", target=user.id, actor_id=user.id, details={"mfa": True})
    return _auth_response(user)


@bp.post("/api/auth/logout")
def logout_api():
    if g.user is None and g.get("pending_session") is None:
        return jsonify(error="authentication required"), 401
    actor = g.user.id if g.user else g.pending_session.user_id
    sessions.end_session()
    db.session.commit()
    audit.record("auth.logout", actor_id=actor)
    return jsonify(ok=True)


@bp.get("/api/auth/me")
@login_required
def me():
    return jsonify(user=user_json(g.user), identity=identity_json(g.user.current_key),
                   session=sessions.session_info(g.auth_session))


@bp.get("/api/auth/identity-blob")
@login_required
def identity_blob():
    """The caller's own sealed identity (opaque without their wrap_key); used to re-seal on passphrase change."""
    return jsonify(identity=identity_json(g.user.current_key, include_wrapped=True))


# --- Passphrase change ------------------------------------------------------------

@bp.post("/api/auth/password")
@login_required
def change_password():
    """Client proves the old passphrase, uploads a new auth_key + identity re-sealed under the new wrap_key."""
    data = _json_body()
    user = g.user
    try:
        current = decode_b64(data.get("current_auth_key"), "current_auth_key", length=AUTH_KEY_BYTES)
        new_key = decode_b64(data.get("new_auth_key"), "new_auth_key", length=AUTH_KEY_BYTES)
        new_salt = decode_b64(data.get("new_kdf_salt"), "new_kdf_salt", length=KDF_SALT_BYTES)
        wrapped = decode_b64(data.get("wrapped_priv"), "wrapped_priv", max_length=MAX_WRAPPED_BYTES)
        wrap_iv = decode_b64(data.get("wrap_iv"), "wrap_iv", length=WRAP_IV_BYTES)
    except ValidationError as err:
        return jsonify(error=str(err)), 400

    if not verify_auth_key(user.auth_hash, current):
        audit.record("auth.password.fail", target=user.id)
        return jsonify(error="current passphrase is incorrect"), 403

    user.auth_hash = hash_auth_key(new_key)
    user.kdf_salt = b64e(new_salt)
    user.kdf_iterations = current_app.config["KDF_ITERATIONS"]
    key = user.current_key
    key.wrapped_priv, key.wrap_iv = b64e(wrapped), b64e(wrap_iv)

    revoked = sessions.revoke_all(user.id, except_id=g.auth_session.id)
    _replace_current_session(user)
    db.session.commit()
    audit.record("auth.password.change", target=user.id, details={"other_sessions_revoked": revoked})
    return _auth_response(user)


# --- Own sessions ----------------------------------------------------------------------

@bp.get("/api/auth/sessions")
@login_required
def list_sessions():
    rows = db.session.execute(
        db.select(AuthSession)
        .filter_by(user_id=g.user.id, revoked=False, mfa_pending=False)
        .filter(AuthSession.expires_at > utcnow())
        .order_by(AuthSession.last_seen.desc())).scalars()
    return jsonify(sessions=[{
        "id": s.id, "ip": s.ip, "user_agent": s.user_agent,
        "created_at": s.created_at.isoformat() + "Z", "last_seen": s.last_seen.isoformat() + "Z",
        "current": s.id == g.auth_session.id,
    } for s in rows])


@bp.post("/api/auth/sessions/<session_id>/revoke")
@login_required
def revoke_session(session_id):
    # Object-level check: only the caller's own sessions are visible (else 404, not 403)
    s = db.session.execute(db.select(AuthSession).filter_by(id=session_id, user_id=g.user.id)).scalar_one_or_none()
    if s is None or s.revoked:
        return jsonify(error="node not found"), 404
    if s.id == g.auth_session.id:
        return jsonify(error="use logout to end the current session"), 400
    sessions.revoke(s)
    db.session.commit()
    audit.record("session.revoke", target=s.id)
    return jsonify(ok=True)


# --- Two-factor enrolment --------------------------------------------------------------

@bp.post("/api/2fa/setup")
@login_required
def totp_setup():
    if g.user.totp_enabled:
        return jsonify(error="two-factor already enabled"), 409
    data = mfa.begin_setup(g.user)
    db.session.commit()
    return jsonify(data)


@bp.post("/api/2fa/enable")
@login_required
def totp_enable():
    user = g.user
    if user.totp_enabled:
        return jsonify(error="two-factor already enabled"), 409
    if not mfa.verify_code(user, _json_body().get("code")):
        return jsonify(error="invalid code"), 400
    user.totp_enabled = True
    _replace_current_session(user)  # privilege change -> new token
    db.session.commit()
    audit.record("mfa.enable", target=user.id)
    return jsonify(ok=True, user=user_json(user))


@bp.post("/api/2fa/disable")
@login_required
def totp_disable():
    user = g.user
    if not user.totp_enabled:
        return jsonify(error="two-factor is not enabled"), 409
    if user.role == ROLE_ADMIN:
        return jsonify(error="two-factor is mandatory for admins"), 403
    if not mfa.verify_code(user, _json_body().get("code")):
        return jsonify(error="invalid code"), 400
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = None
    db.session.commit()
    audit.record("mfa.disable", target=user.id)
    return jsonify(ok=True, user=user_json(user))
