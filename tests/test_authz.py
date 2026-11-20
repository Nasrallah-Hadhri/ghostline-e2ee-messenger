"""Week 3: vertical + horizontal access control, admin actions."""
from app.models import AuditLog, User
from tests.conftest import promote_admin


def test_anonymous_gets_401_on_admin_api(api):
    assert api.get("/api/admin/users").status_code == 401


def test_user_cannot_reach_admin_and_attempt_is_audited(members, db):
    alice = members["alice"].api
    assert alice.get("/admin/").status_code == 403
    resp = alice.get("/api/admin/users")
    assert resp.status_code == 403 and resp.get_json() == {"error": "access denied"}
    assert alice.post("/api/admin/users/x/role", {"role": "admin"}).status_code == 403

    denied = db.session.execute(db.select(AuditLog).filter_by(action="authz.denied")).scalars().all()
    assert len(denied) == 3


def test_admin_without_2fa_is_sent_to_enrolment(members, db):
    promote_admin(db, "alice", with_2fa=False)
    alice = members["alice"].api
    resp = alice.get("/api/admin/users")
    assert resp.status_code == 403 and resp.get_json()["code"] == "mfa_setup_required"
    page = alice.get("/admin/")
    assert page.status_code == 302 and "/profile?setup2fa=1" in page.headers["Location"]


def test_admin_with_2fa_has_access(members, db):
    promote_admin(db, "alice")
    alice = members["alice"].api
    users = alice.get("/api/admin/users").get_json()["users"]
    assert {u["username"] for u in users} == {"alice", "bob", "charlie"}
    for path in ("stats", "sessions", "audit", "vault"):
        assert alice.get(f"/api/admin/{path}").status_code == 200


def test_idor_conversation_of_others_is_invisible(members):
    alice, bob, charlie = members["alice"], members["bob"], members["charlie"]
    conv = alice.open_conversation(bob)
    assert alice.send(bob, conv, 1, "for bob only").status_code == 201

    # charlie knows the UUID (e.g. sniffed from a screenshot): still nothing
    assert charlie.api.get(f"/api/conversations/{conv}/messages").status_code == 404
    forged = charlie.envelope(bob, conv, 1, "injected")
    assert charlie.api.post(f"/api/conversations/{conv}/messages", forged).status_code == 404
    assert conv not in [c["id"] for c in charlie.api.get("/api/conversations").get_json()["conversations"]]


def test_cannot_revoke_someone_elses_session(members, db):
    from app.models import AuthSession
    bob_session = db.session.execute(
        db.select(AuthSession).join(User).filter(User.username == "bob")).scalar_one()
    resp = members["alice"].api.post(f"/api/auth/sessions/{bob_session.id}/revoke")
    assert resp.status_code == 404
    assert members["bob"].api.get("/api/auth/me").status_code == 200


def test_admin_disable_kills_sessions_and_blocks_login(members, db, make_api):
    promote_admin(db, "alice")
    bob = members["bob"]
    assert members["alice"].api.post(f"/api/admin/users/{bob.id}/disable").status_code == 200
    assert bob.api.get("/api/auth/me").status_code == 401
    assert make_api().login("bob")[0].status_code == 403


def test_role_change_forces_relogin(members, db):
    promote_admin(db, "alice")
    bob = members["bob"]
    assert members["alice"].api.post(f"/api/admin/users/{bob.id}/role", {"role": "admin"}).status_code == 200
    assert bob.api.get("/api/auth/me").status_code == 401


def test_admin_guard_rails(members, db):
    promote_admin(db, "alice")
    alice = members["alice"]
    assert alice.api.post(f"/api/admin/users/{alice.id}/disable").status_code == 400
    assert alice.api.post(f"/api/admin/users/{alice.id}/role", {"role": "user"}).status_code == 400
    assert alice.api.post(f"/api/admin/users/{members['bob'].id}/role", {"role": "root"}).status_code == 400
    assert alice.api.post(f"/api/admin/users/{members['bob'].id}/explode").status_code == 404
    assert alice.api.post("/api/admin/users/not-a-user/disable").status_code == 404


def test_admin_actions_require_csrf(members, db):
    promote_admin(db, "alice")
    resp = members["alice"].api.post(f"/api/admin/users/{members['bob'].id}/disable", csrf=False)
    assert resp.status_code == 400


def test_vault_shows_only_ciphertext(members, db):
    promote_admin(db, "alice")
    bob, charlie = members["bob"], members["charlie"]
    conv = bob.open_conversation(charlie)
    bob.send(charlie, conv, 1, "the eagle lands at midnight")

    vault = members["alice"].api.get("/api/admin/vault").get_json()["messages"]
    assert len(vault) == 1 and vault[0]["from"] == "bob" and vault[0]["to"] == "charlie"
    assert "eagle" not in str(vault)
