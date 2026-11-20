"""Week 3: HMAC-chained audit log."""
from app import audit
from app.models import AuditLog
from tests.conftest import promote_admin


def _fill(n=5):
    for i in range(n):
        audit.record("test.event", target=f"t{i}", details={"i": i})


def test_chain_links_and_verifies(app, db):
    _fill()
    rows = db.session.execute(db.select(AuditLog).order_by(AuditLog.id)).scalars().all()
    assert rows[0].prev_hmac == audit.GENESIS
    assert all(rows[i].prev_hmac == rows[i - 1].hmac for i in range(1, len(rows)))
    result = audit.verify_chain()
    assert result["ok"] and result["count"] == 5 and result["head"] == rows[-1].hmac


def test_modified_row_is_detected(app, db):
    _fill()
    row = db.session.get(AuditLog, 3)
    row.details = '{"i":999}'  # attacker with DB access edits history
    db.session.commit()
    result = audit.verify_chain()
    assert not result["ok"] and result["broken_at"] == 3 and "modified" in result["reason"]


def test_deleted_row_is_detected(app, db):
    _fill()
    db.session.delete(db.session.get(AuditLog, 2))
    db.session.commit()
    result = audit.verify_chain()
    assert not result["ok"] and result["broken_at"] == 3 and "link" in result["reason"]


def test_forged_row_without_key_is_detected(app, db):
    _fill(2)
    head = db.session.get(AuditLog, 2)
    db.session.add(AuditLog(action="admin.user.role", target="x", details="{}",
                            prev_hmac=head.hmac, hmac="f" * 64))
    db.session.commit()
    assert audit.verify_chain()["broken_at"] == 3


def test_auth_events_are_recorded(api, make_api, db):
    api.register("alice")
    make_api().login("alice", "wrong-passphrase-123")
    make_api().login("alice")
    actions = [a for (a,) in db.session.execute(db.select(AuditLog.action).order_by(AuditLog.id))]
    assert actions == ["auth.register", "auth.login.fail", "auth.login.ok"]
    assert audit.verify_chain()["ok"]


def test_admin_can_verify_chain_via_api(members, db):
    promote_admin(db, "alice")
    resp = members["alice"].api.post("/api/admin/audit/verify")
    assert resp.status_code == 200 and resp.get_json()["ok"]
    entries = members["alice"].api.get("/api/admin/audit").get_json()["entries"]
    assert entries[0]["action"] == "admin.audit.verify"
