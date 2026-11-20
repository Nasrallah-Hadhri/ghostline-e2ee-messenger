"""Week 3: E2E envelopes, server-side validation, replay protection, self-destruct."""
import base64
import json
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import clientsim
from app.chat.service import purge_expired
from app.events import Broker
from app.models import Message, utcnow
from app.server_crypto import verify_directory_entry


def test_round_trip_alice_to_bob(members):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    assert alice.send(bob, conv, 1, "hello bob, it's encrypted").status_code == 201

    msgs = bob.api.get(f"/api/conversations/{conv}/messages").get_json()["messages"]
    assert len(msgs) == 1
    plain = clientsim.open_message(bob.identity, alice.public["ecdh_pub"], alice.public["ecdsa_pub"], msgs[0])
    assert plain == "hello bob, it's encrypted"


def test_database_never_contains_plaintext(members, db):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    alice.send(bob, conv, 1, "launch codes 0000")
    dump = json.dumps([str(r) for r in db.session.execute(db.text("SELECT * FROM messages")).all()])
    assert "launch codes" not in dump
    assert base64.b64encode(b"launch codes").decode()[:12] not in dump


def test_replay_and_stale_counters_rejected(members, db):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    envelope = alice.envelope(bob, conv, 1, "pay 10 euros")
    url = f"/api/conversations/{conv}/messages"
    assert alice.api.post(url, envelope).status_code == 201

    replay = alice.api.post(url, envelope)  # Burp Repeater: same request again
    assert replay.status_code == 409 and replay.get_json()["next_counter"] == 2
    assert alice.send(bob, conv, 3, "skips are fine").status_code == 201
    assert alice.send(bob, conv, 2, "going backwards is not").status_code == 409
    assert db.session.execute(db.select(db.func.count()).select_from(Message)).scalar() == 2


def test_tampered_ciphertext_rejected_by_server(members):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    env = alice.envelope(bob, conv, 1, "original")
    raw = bytearray(base64.b64decode(env["ciphertext"]))
    raw[0] ^= 0x01
    env["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    resp = alice.api.post(f"/api/conversations/{conv}/messages", env)
    assert resp.status_code == 400 and "signature" in resp.get_json()["error"]


def test_sender_spoofing_in_aad_rejected(members):
    alice, bob, charlie = members["alice"], members["bob"], members["charlie"]
    conv = alice.open_conversation(bob)
    # alice claims (inside the AAD) that bob wrote it
    env = clientsim.seal_message(alice.identity, bob.public["ecdh_pub"], conv, bob.id, 1, "hi")
    resp = alice.api.post(f"/api/conversations/{conv}/messages", env)
    assert resp.status_code == 400 and "aad" in resp.get_json()["error"]


def test_signature_from_another_key_rejected(members):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    env = alice.envelope(bob, conv, 1, "hi")
    impostor = clientsim.generate_identity()
    data = base64.b64decode(env["iv"]) + env["aad"].encode() + base64.b64decode(env["ciphertext"])
    env["signature"] = base64.b64encode(clientsim.sign_raw(impostor.ecdsa, data)).decode()
    assert alice.api.post(f"/api/conversations/{conv}/messages", env).status_code == 400


def test_recipient_detects_server_side_tampering(members, db):
    """Even if a malicious server edits a stored row, the recipient's checks fail."""
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    alice.send(bob, conv, 1, "transfer 10")
    row = db.session.execute(db.select(Message)).scalar_one()
    forged = clientsim.seal_message(alice.identity, bob.public["ecdh_pub"], conv, alice.id, 1, "transfer 9999")
    row.ciphertext = forged["ciphertext"]  # ciphertext swapped, signature/iv left
    db.session.commit()

    msg = bob.api.get(f"/api/conversations/{conv}/messages").get_json()["messages"][0]
    try:
        clientsim.open_message(bob.identity, alice.public["ecdh_pub"], alice.public["ecdsa_pub"], msg)
        raise AssertionError("tampering went unnoticed")
    except ValueError as err:
        assert "signature" in str(err)


def test_input_validation(members, app):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    url = f"/api/conversations/{conv}/messages"
    cases = [
        {"ttl": 7},                                   # not an allowed TTL
        {"counter": 0},
        {"counter": "1"},
        {"iv": base64.b64encode(b"short").decode()},
        {"signature": base64.b64encode(b"x" * 10).decode()},
        {"sender_key_version": 2},
        {"ciphertext": "A" * (app.config["MAX_CIPHERTEXT_B64"] + 4)},
    ]
    for override in cases:
        env = alice.envelope(bob, conv, 1, "x")
        env.update(override)
        assert alice.api.post(url, env).status_code == 400, override


def test_self_destruct_hides_then_purges(members, db):
    alice, bob = members["alice"], members["bob"]
    conv = alice.open_conversation(bob)
    assert alice.send(bob, conv, 1, "burn after reading", ttl=30).status_code == 201
    assert alice.send(bob, conv, 2, "keep me").status_code == 201
    row = db.session.execute(db.select(Message).filter_by(counter=1)).scalar_one()
    assert row.expires_at is not None

    row.expires_at = utcnow() - timedelta(seconds=1)  # time passes
    db.session.commit()
    burned_id = row.id
    visible = bob.api.get(f"/api/conversations/{conv}/messages").get_json()["messages"]
    assert [m["counter"] for m in visible] == [2]

    purged = purge_expired()
    assert purged and purged[0][1] == [burned_id]
    assert db.session.execute(db.select(db.func.count()).select_from(Message)).scalar() == 1


def test_conversation_rules(members):
    alice, bob = members["alice"], members["bob"]
    first = alice.api.post("/api/conversations", {"peer_id": bob.id})
    again = bob.api.post("/api/conversations", {"peer_id": alice.id})
    assert first.status_code == 201 and again.status_code == 200
    assert first.get_json()["conversation"]["id"] == again.get_json()["conversation"]["id"]
    assert alice.api.post("/api/conversations", {"peer_id": alice.id}).status_code == 400
    assert alice.api.post("/api/conversations", {"peer_id": "nope"}).status_code == 404


def test_directory_and_signed_identities(members):
    alice = members["alice"]
    found = alice.api.get("/api/directory?q=b").get_json()["users"]
    assert [u["username"] for u in found] == ["bob"]
    assert "alice" not in [u["username"] for u in alice.api.get("/api/directory").get_json()["users"]]
    assert alice.api.get("/api/directory?q=%25").get_json()["users"] == []  # LIKE wildcard escaped

    key = alice.api.get("/api/server-key").get_json()
    entry = alice.api.get(f"/api/users/{members['bob'].id}/identity").get_json()["identity"]
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key"]))
    assert verify_directory_entry(pub, entry["server_sig"], user_id=entry["user_id"], version=entry["version"],
                                  ecdh_pub=entry["ecdh_pub"], ecdsa_pub=entry["ecdsa_pub"])


def test_stream_requires_session(api):
    assert api.get("/api/stream").status_code == 401


def test_broker_delivers_only_to_subscriber():
    b = Broker()
    qa, qb = b.subscribe("a"), b.subscribe("b")
    b.publish("a", "message", {"x": 1})
    assert qa.get_nowait() == ("message", {"x": 1}) and qb.empty()
    b.unsubscribe("a", qa)
    assert not b.online("a") and b.online("b")
