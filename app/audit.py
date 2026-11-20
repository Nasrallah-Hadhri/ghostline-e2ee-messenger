"""Tamper-evident audit log (HMAC-SHA256 hash chain).

    hmac_n = HMAC(AUDIT_HMAC_KEY, hmac_{n-1} || canonical(entry_n))

Editing, deleting or reordering any row breaks every link after it, and
without AUDIT_HMAC_KEY an attacker with DB access cannot recompute the chain.
(Truncating the newest rows is only detectable against an external copy of
the head HMAC; the console displays the head for that purpose.)
"""
import hashlib
import hmac as _hmac
import json
import threading
from datetime import datetime

from flask import current_app, g, has_request_context, request

from .extensions import db
from .models import AuditLog, utcnow

GENESIS = "0" * 64
_append_lock = threading.Lock()  # serialises "read head -> append" so the chain never forks


def _canonical(ts: datetime, actor_id, action, target, ip, details: str) -> bytes:
    return json.dumps([ts.isoformat(timespec="microseconds"), actor_id, action, target, ip, details],
                      separators=(",", ":")).encode()


def _mac(prev_hmac: str, entry: bytes) -> str:
    key = current_app.config["AUDIT_HMAC_KEY"]
    return _hmac.new(key, prev_hmac.encode() + entry, hashlib.sha256).hexdigest()


def record(action: str, target: str | None = None, details: dict | None = None,
           actor_id: str | None = None) -> AuditLog:
    """Append an entry. NOTE: commits the current DB session (call after your own changes)."""
    if actor_id is None and has_request_context() and g.get("user") is not None:
        actor_id = g.user.id
    ip = request.remote_addr if has_request_context() else None
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))

    with _append_lock:
        head = db.session.execute(db.select(AuditLog.hmac).order_by(AuditLog.id.desc()).limit(1)).scalar()
        prev = head or GENESIS
        ts = utcnow()
        entry = AuditLog(ts=ts, actor_id=actor_id, action=action, target=target, ip=ip,
                         details=details_json, prev_hmac=prev,
                         hmac=_mac(prev, _canonical(ts, actor_id, action, target, ip, details_json)))
        db.session.add(entry)
        db.session.commit()
    return entry


def verify_chain() -> dict:
    """Walk the whole chain. Returns {"ok", "count", "head", "broken_at", "reason"}."""
    prev = GENESIS
    count = 0
    rows = db.session.execute(db.select(AuditLog).order_by(AuditLog.id)).scalars()
    for entry in rows:
        count += 1
        if entry.prev_hmac != prev:
            return {"ok": False, "count": count, "head": prev, "broken_at": entry.id,
                    "reason": "link mismatch (row deleted, inserted or reordered)"}
        expected = _mac(prev, _canonical(entry.ts, entry.actor_id, entry.action, entry.target,
                                         entry.ip, entry.details))
        if not _hmac.compare_digest(expected, entry.hmac):
            return {"ok": False, "count": count, "head": prev, "broken_at": entry.id,
                    "reason": "hmac mismatch (row contents modified)"}
        prev = entry.hmac
    return {"ok": True, "count": count, "head": prev, "broken_at": None, "reason": None}
