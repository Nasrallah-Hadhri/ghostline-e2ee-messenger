"""Server-side session store.

The cookie carries a random 256-bit token; the DB keeps only SHA-256(token),
so a leaked database can't be replayed as cookies. Sessions expire after an
idle period and an absolute lifetime, and can be revoked server-side.

A session created after the password step of a 2FA account is "mfa_pending":
it authenticates nothing except the /api/auth/mfa endpoint.
"""
import hashlib
import secrets
from datetime import timedelta

from flask import Flask, current_app, g, request

from ..events import broker
from ..extensions import db
from ..models import AuthSession, User, utcnow

LAST_SEEN_RESOLUTION = timedelta(seconds=15)  # avoid a DB write on every request


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user: User, mfa_pending: bool = False) -> AuthSession:
    """Create a fresh session (always a new token: prevents session fixation)."""
    cfg = current_app.config
    now = utcnow()
    token = secrets.token_urlsafe(32)
    lifetime = cfg["MFA_PENDING_TIMEOUT"] if mfa_pending else cfg["SESSION_ABSOLUTE_TIMEOUT"]
    session = AuthSession(
        token_hash=hash_token(token),
        user_id=user.id,
        created_at=now,
        last_seen=now,
        expires_at=now + lifetime,
        ip=request.remote_addr,
        user_agent=(request.user_agent.string or "")[:256],
        mfa_pending=mfa_pending,
    )
    db.session.add(session)
    g.new_auth_token = token
    if mfa_pending:
        g.user, g.auth_session, g.pending_session = None, None, session
    else:
        g.user, g.auth_session, g.pending_session = user, session, None
    return session


def revoke(session: AuthSession) -> None:
    session.revoked = True
    broker.publish(session.user_id, "session_revoked", {"session_id": session.id})


def revoke_all(user_id: str, except_id: str | None = None) -> int:
    sessions = db.session.execute(
        db.select(AuthSession).filter_by(user_id=user_id, revoked=False)).scalars().all()
    count = 0
    for s in sessions:
        if s.id != except_id:
            revoke(s)
            count += 1
    return count


def end_session() -> None:
    """Revoke the current (full or pending) session and clear the cookie."""
    for s in (g.get("auth_session"), g.get("pending_session")):
        if s is not None:
            revoke(s)
    g.user = g.auth_session = g.pending_session = None
    g.clear_auth_cookie = True


def session_info(session: AuthSession) -> dict:
    cfg = current_app.config
    now = utcnow()
    idle_left = cfg["SESSION_IDLE_TIMEOUT"] - (now - session.last_seen)
    abs_left = session.expires_at - now
    return {
        "id": session.id,
        "idle_remaining_s": max(0, int(min(idle_left, abs_left).total_seconds())),
        "absolute_remaining_s": max(0, int(abs_left.total_seconds())),
        "idle_timeout_s": int(cfg["SESSION_IDLE_TIMEOUT"].total_seconds()),
    }


def _is_valid(session: AuthSession | None, now) -> bool:
    return (
        session is not None
        and not session.revoked
        and session.expires_at > now
        and now - session.last_seen <= current_app.config["SESSION_IDLE_TIMEOUT"]
        and not session.user.is_disabled
    )


def load_session() -> None:
    g.user = g.auth_session = g.pending_session = g.new_auth_token = None
    g.clear_auth_cookie = False
    if request.endpoint == "static":
        return

    token = request.cookies.get(current_app.config["AUTH_COOKIE_NAME"])
    if not token:
        return

    now = utcnow()
    session = db.session.execute(
        db.select(AuthSession).filter_by(token_hash=hash_token(token))
    ).scalar_one_or_none()

    if not _is_valid(session, now):
        g.clear_auth_cookie = True
        return

    if session.mfa_pending:
        g.pending_session = session  # not authenticated yet
        return

    if now - session.last_seen >= LAST_SEEN_RESOLUTION:
        session.last_seen = now
        db.session.commit()
    g.user, g.auth_session = session.user, session


def apply_session_cookie(response):
    cfg = current_app.config
    name = cfg["AUTH_COOKIE_NAME"]
    if g.get("new_auth_token"):
        response.set_cookie(
            name, g.new_auth_token,
            max_age=int(cfg["SESSION_ABSOLUTE_TIMEOUT"].total_seconds()),
            secure=True, httponly=True, samesite="Strict", path="/",
        )
    elif g.get("clear_auth_cookie"):
        response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="Strict")
    return response


def init_app(app: Flask) -> None:
    app.before_request(load_session)
    app.after_request(apply_session_cookie)
