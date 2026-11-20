"""Messaging: terminal page, key directory, conversations, envelopes, live stream."""
import base64

from cryptography.hazmat.primitives import serialization
from flask import Blueprint, current_app, g, jsonify, render_template, request
from sqlalchemy import func

from .. import audit, events
from ..auth.routes import identity_json
from ..auth.security import ValidationError
from ..authz import login_required
from ..events import broker
from ..extensions import db
from ..models import Conversation, Message, User
from .service import ReplayError, message_json, next_counter, not_expired, store_message

bp = Blueprint("chat", __name__)


@bp.get("/terminal")
@login_required
def terminal():
    return render_template("terminal.html")


# --- Helpers -------------------------------------------------------------------------

def _json_body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _active_user(user_id: str) -> User | None:
    user = db.session.get(User, user_id) if isinstance(user_id, str) else None
    return user if user and not user.is_disabled else None


def _own_conversation(conversation_id: str) -> Conversation | None:
    """Object-level authorization: a conversation only exists for its two participants."""
    conv = db.session.get(Conversation, conversation_id)
    if conv is None or not conv.has_participant(g.user.id):
        return None
    return conv


def _conversation_json(conv: Conversation) -> dict:
    peer = db.session.get(User, conv.peer_of(g.user.id))
    last = db.session.execute(
        db.select(func.max(Message.created_at)).filter_by(conversation_id=conv.id).filter(not_expired())
    ).scalar()
    return {
        "id": conv.id,
        "peer": {"id": peer.id, "username": peer.username, "online": broker.online(peer.id)},
        "created_at": conv.created_at.isoformat() + "Z",
        "last_activity": (last or conv.created_at).isoformat() + "Z",
        "next_counter": next_counter(conv.id, g.user.id),
    }


NOT_FOUND = ({"error": "node not found"}, 404)


# --- Directory ------------------------------------------------------------------------

@bp.get("/api/server-key")
@login_required
def server_key():
    """Ed25519 key that signs directory entries (raw 32 bytes, base64, + PEM)."""
    pub = current_app.extensions["signing_key"].public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return jsonify(alg="Ed25519", public_key=base64.b64encode(raw).decode(), pem=pem.decode())


@bp.get("/api/directory")
@login_required
def directory():
    q = request.args.get("q", "").strip().lower()[:32]
    query = db.select(User).filter(User.id != g.user.id, User.is_disabled.is_(False))
    if q:
        query = query.filter(User.username.startswith(q, autoescape=True))
    users = db.session.execute(query.order_by(User.username).limit(10)).scalars()
    return jsonify(users=[{"id": u.id, "username": u.username} for u in users])


@bp.get("/api/users/<user_id>/identity")
@login_required
def user_identity(user_id):
    user = _active_user(user_id)
    if user is None:
        return NOT_FOUND
    return jsonify(username=user.username, identity=identity_json(user.current_key))


# --- Conversations ---------------------------------------------------------------------

@bp.get("/api/conversations")
@login_required
def list_conversations():
    convs = db.session.execute(
        db.select(Conversation).filter((Conversation.user_a == g.user.id) | (Conversation.user_b == g.user.id))
    ).scalars().all()
    data = sorted((_conversation_json(c) for c in convs), key=lambda c: c["last_activity"], reverse=True)
    return jsonify(conversations=data)


@bp.post("/api/conversations")
@login_required
def open_conversation():
    peer = _active_user(_json_body().get("peer_id"))
    if peer is None:
        return NOT_FOUND
    if peer.id == g.user.id:
        return jsonify(error="cannot open a channel with yourself"), 400

    a, b = Conversation.ordered_pair(g.user.id, peer.id)
    conv = db.session.execute(db.select(Conversation).filter_by(user_a=a, user_b=b)).scalar_one_or_none()
    created = conv is None
    if created:
        conv = Conversation(user_a=a, user_b=b)
        db.session.add(conv)
        db.session.commit()
        audit.record("conversation.open", target=conv.id)
        broker.publish(peer.id, "conversation", {"id": conv.id})
    return jsonify(conversation=_conversation_json(conv)), 201 if created else 200


@bp.get("/api/conversations/<conversation_id>/messages")
@login_required
def list_messages(conversation_id):
    conv = _own_conversation(conversation_id)
    if conv is None:
        return NOT_FOUND
    limit = current_app.config["MESSAGE_PAGE_SIZE"]
    rows = db.session.execute(
        db.select(Message).filter_by(conversation_id=conv.id).filter(not_expired())
        .order_by(Message.created_at.desc(), Message.counter.desc()).limit(limit)
    ).scalars().all()
    return jsonify(messages=[message_json(m) for m in reversed(rows)],
                   next_counter=next_counter(conv.id, g.user.id))


@bp.post("/api/conversations/<conversation_id>/messages")
@login_required
def send_message(conversation_id):
    conv = _own_conversation(conversation_id)
    if conv is None:
        return NOT_FOUND
    peer = _active_user(conv.peer_of(g.user.id))
    if peer is None:
        return jsonify(error="recipient is unavailable"), 409
    try:
        msg = store_message(conv, g.user, _json_body())
    except ValidationError as err:
        audit.record("message.reject", target=conv.id, details={"why": str(err)})
        return jsonify(error=str(err)), 400
    except ReplayError as err:
        audit.record("message.replay", target=conv.id, details={"next_counter": err.next_counter})
        return jsonify(error="replay detected: counter already used", next_counter=err.next_counter), 409

    payload = message_json(msg)
    for uid in (conv.user_a, conv.user_b):
        broker.publish(uid, "message", payload)
    return jsonify(message=payload), 201


# --- Live push --------------------------------------------------------------------------

@bp.get("/api/stream")
@login_required
def stream():
    return events.stream(g.user.id, g.auth_session.id)
