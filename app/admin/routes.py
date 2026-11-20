"""Admin SOC console: page + API. Every endpoint requires role=admin AND 2FA (see authz).

Admins manage accounts, sessions and the audit chain. They cannot read
messages: the vault endpoint returns exactly what the server stores.
"""
from datetime import timedelta

from flask import Blueprint, g, jsonify, render_template, request
from sqlalchemy import func

from .. import audit
from ..auth import sessions
from ..authz import admin_required
from ..extensions import db
from ..models import ROLE_ADMIN, ROLES, AuditLog, AuthSession, Conversation, Message, User, utcnow

bp = Blueprint("admin", __name__)

NOT_FOUND = ({"error": "node not found"}, 404)


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _live_sessions_query():
    return (db.select(AuthSession)
            .filter_by(revoked=False, mfa_pending=False)
            .filter(AuthSession.expires_at > utcnow()))


def _admin_count() -> int:
    return db.session.execute(
        db.select(func.count()).select_from(User).filter_by(role=ROLE_ADMIN, is_disabled=False)).scalar()


@bp.get("/admin/")
@admin_required
def console():
    return render_template("admin/console.html")


@bp.get("/api/admin/stats")
@admin_required
def stats():
    day_ago = utcnow() - timedelta(hours=24)
    count = lambda q: db.session.execute(q).scalar()  # noqa: E731
    return jsonify(
        users=count(db.select(func.count()).select_from(User)),
        live_sessions=count(db.select(func.count()).select_from(_live_sessions_query().subquery())),
        failed_logins_24h=count(db.select(func.count()).select_from(AuditLog)
                                .filter(AuditLog.action == "auth.login.fail", AuditLog.ts >= day_ago)),
        denied_24h=count(db.select(func.count()).select_from(AuditLog)
                         .filter(AuditLog.action == "authz.denied", AuditLog.ts >= day_ago)),
        disabled=count(db.select(func.count()).select_from(User).filter_by(is_disabled=True)),
        messages_stored=count(db.select(func.count()).select_from(Message)),
        audit_entries=count(db.select(func.count()).select_from(AuditLog)),
    )


@bp.get("/api/admin/users")
@admin_required
def users():
    rows = db.session.execute(db.select(User).order_by(User.created_at)).scalars()
    return jsonify(users=[{
        "id": u.id, "username": u.username, "role": u.role, "totp_enabled": u.totp_enabled,
        "disabled": u.is_disabled, "locked": u.is_locked(), "created_at": _iso(u.created_at),
        "last_login": _iso(u.last_login), "self": u.id == g.user.id,
    } for u in rows])


def _target_user(user_id) -> User | None:
    return db.session.get(User, user_id)


@bp.post("/api/admin/users/<user_id>/<action>")
@admin_required
def user_action(user_id, action):
    user = _target_user(user_id)
    if user is None:
        return NOT_FOUND
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    elif not isinstance(body, dict):
        return jsonify(error="request body must be a JSON object"), 400

    if action in ("disable", "role") and user.id == g.user.id:
        return jsonify(error="you cannot do that to your own account"), 400

    if action == "disable":
        if user.role == ROLE_ADMIN and _admin_count() <= 1:
            return jsonify(error="cannot disable the last admin"), 400
        user.is_disabled = True
        revoked = sessions.revoke_all(user.id)
        details = {"sessions_revoked": revoked}
    elif action == "enable":
        user.is_disabled = False
        details = {}
    elif action == "unlock":
        user.failed_attempts = 0
        user.locked_until = None
        details = {}
    elif action == "role":
        role = body.get("role")
        if role not in ROLES:
            return jsonify(error="unknown role"), 400
        if user.role == ROLE_ADMIN and role != ROLE_ADMIN and _admin_count() <= 1:
            return jsonify(error="cannot demote the last admin"), 400
        details = {"from": user.role, "to": role}
        user.role = role
        sessions.revoke_all(user.id)  # privilege change: force a fresh login
    elif action == "logout":
        details = {"sessions_revoked": sessions.revoke_all(user.id)}
    else:
        return NOT_FOUND

    db.session.commit()
    audit.record(f"admin.user.{action}", target=user.id, details={"username": user.username, **details})
    return jsonify(ok=True)


@bp.get("/api/admin/sessions")
@admin_required
def live_sessions():
    rows = db.session.execute(_live_sessions_query().order_by(AuthSession.last_seen.desc())).scalars()
    return jsonify(sessions=[{
        "id": s.id, "username": s.user.username, "ip": s.ip, "user_agent": s.user_agent,
        "created_at": _iso(s.created_at), "last_seen": _iso(s.last_seen),
        "current": s.id == g.auth_session.id,
    } for s in rows])


@bp.post("/api/admin/sessions/<session_id>/revoke")
@admin_required
def revoke_session(session_id):
    s = db.session.get(AuthSession, session_id)
    if s is None or s.revoked:
        return NOT_FOUND
    sessions.revoke(s)
    db.session.commit()
    audit.record("admin.session.revoke", target=s.id, details={"username": s.user.username})
    return jsonify(ok=True)


@bp.get("/api/admin/audit")
@admin_required
def audit_log():
    raw = request.args.get("limit", "200")
    if not raw.isdigit():
        return jsonify(error="limit must be a non-negative integer"), 400
    limit = min(int(raw), 1000)
    rows = db.session.execute(db.select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).scalars().all()
    names = dict(db.session.execute(db.select(User.id, User.username)).all())
    return jsonify(entries=[{
        "id": e.id, "ts": _iso(e.ts), "actor": names.get(e.actor_id, e.actor_id),
        "action": e.action, "target": names.get(e.target, e.target), "ip": e.ip,
        "details": e.details, "hmac": e.hmac, "prev_hmac": e.prev_hmac,
    } for e in rows])


@bp.post("/api/admin/audit/verify")
@admin_required
def audit_verify():
    result = audit.verify_chain()
    audit.record("admin.audit.verify", details={"ok": result["ok"], "count": result["count"],
                                                "broken_at": result["broken_at"]})
    return jsonify(result)


@bp.get("/api/admin/vault")
@admin_required
def vault():
    """Exactly what the server stores for recent messages: metadata + opaque ciphertext."""
    rows = db.session.execute(db.select(Message).order_by(Message.created_at.desc()).limit(50)).scalars().all()
    names = dict(db.session.execute(db.select(User.id, User.username)).all())
    out = []
    for m in rows:
        conv = db.session.get(Conversation, m.conversation_id)
        out.append({
            "id": m.id, "from": names.get(m.sender_id), "to": names.get(conv.peer_of(m.sender_id)),
            "counter": m.counter, "iv": m.iv, "ciphertext": m.ciphertext, "signature": m.signature,
            "created_at": _iso(m.created_at), "expires_at": _iso(m.expires_at),
        })
    return jsonify(messages=out)
