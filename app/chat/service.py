"""Message envelope validation, storage and expiry.

The server can't read messages, but it still enforces everything it *can*:
  * the sender is a participant (object-level authorization)
  * AAD binds conversation, sender, counter, TTL and key version
  * counter strictly increases per (conversation, sender)  -> replay rejected
  * the ECDSA signature verifies under the sender's registered key
    (recipients verify again; they don't trust the server)
"""
import base64
import json
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from flask import current_app
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from ..auth.security import ValidationError, decode_b64
from ..extensions import db
from ..models import Conversation, Message, User, utcnow

AAD_PREFIX = "ghostline-msg-v1"


class ReplayError(Exception):
    def __init__(self, next_counter: int):
        super().__init__("counter already used")
        self.next_counter = next_counter


def expected_aad(conversation_id: str, sender_id: str, counter: int, ttl: int | None, key_version: int) -> str:
    return f"{AAD_PREFIX}|{conversation_id}|{sender_id}|{counter}|{ttl or 0}|{key_version}"


def not_expired():
    return or_(Message.expires_at.is_(None), Message.expires_at > utcnow())


def next_counter(conversation_id: str, sender_id: str) -> int:
    last = db.session.execute(
        db.select(func.max(Message.counter)).filter_by(conversation_id=conversation_id, sender_id=sender_id)
    ).scalar()
    return (last or 0) + 1


def _public_key(jwk_json: str) -> ec.EllipticCurvePublicKey:
    jwk = json.loads(jwk_json)

    def coord(v):
        return int.from_bytes(base64.urlsafe_b64decode(v + "="), "big")

    return ec.EllipticCurvePublicNumbers(coord(jwk["x"]), coord(jwk["y"]), ec.SECP256R1()).public_key()


def verify_envelope_signature(ecdsa_pub: str, iv: bytes, aad: str, ciphertext: bytes, signature: bytes) -> bool:
    """Web Crypto emits raw r||s (IEEE P1363); `cryptography` wants DER."""
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    try:
        _public_key(ecdsa_pub).verify(encode_dss_signature(r, s), iv + aad.encode() + ciphertext,
                                      ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def store_message(conv: Conversation, sender: User, data: dict) -> Message:
    cfg = current_app.config

    counter = data.get("counter")
    if type(counter) is not int or counter < 1 or counter > current_app.config["MAX_COUNTER"]:
        raise ValidationError("counter must be a positive integer within range")
    ttl = data.get("ttl")
    if ttl is not None and ttl not in cfg["MESSAGE_TTL_CHOICES"]:
        raise ValidationError("ttl not allowed")
    key_version = data.get("sender_key_version")
    key = sender.current_key
    if key_version != key.version:
        raise ValidationError("sender_key_version is not the current key")

    ct_b64 = data.get("ciphertext")
    if not isinstance(ct_b64, str) or len(ct_b64) > cfg["MAX_CIPHERTEXT_B64"]:
        raise ValidationError("ciphertext missing or too large")
    ciphertext = decode_b64(ct_b64, "ciphertext")
    if len(ciphertext) < 17:  # at least 1 byte + 16-byte GCM tag
        raise ValidationError("ciphertext too short")
    iv = decode_b64(data.get("iv"), "iv", length=12)
    signature = decode_b64(data.get("signature"), "signature", length=64)

    aad = data.get("aad")
    if aad != expected_aad(conv.id, sender.id, counter, ttl, key.version):
        raise ValidationError("aad does not match envelope metadata")
    if not verify_envelope_signature(key.ecdsa_pub, iv, aad, ciphertext, signature):
        raise ValidationError("signature does not verify under sender key")

    expected = next_counter(conv.id, sender.id)
    if counter < expected:
        raise ReplayError(expected)

    now = utcnow()
    msg = Message(conversation_id=conv.id, sender_id=sender.id, ciphertext=ct_b64,
                  iv=data["iv"], aad=aad, signature=data["signature"], counter=counter,
                  sender_key_version=key.version, created_at=now,
                  expires_at=now + timedelta(seconds=ttl) if ttl else None)
    db.session.add(msg)
    try:
        db.session.commit()
    except IntegrityError:  # concurrent send with the same counter
        db.session.rollback()
        raise ReplayError(next_counter(conv.id, sender.id)) from None
    return msg


def message_json(m: Message) -> dict:
    return {
        "id": m.id, "conversation_id": m.conversation_id, "sender_id": m.sender_id,
        "ciphertext": m.ciphertext, "iv": m.iv, "aad": m.aad, "signature": m.signature,
        "counter": m.counter, "sender_key_version": m.sender_key_version,
        "created_at": m.created_at.isoformat() + "Z",
        "expires_at": m.expires_at.isoformat() + "Z" if m.expires_at else None,
    }


def purge_expired() -> list[tuple[str, list[str], tuple[str, str]]]:
    """Hard-delete expired messages. Returns (conversation_id, message_ids, participants)."""
    now = utcnow()
    rows = db.session.execute(
        db.select(Message.id, Message.conversation_id).filter(Message.expires_at <= now)).all()
    if not rows:
        return []
    by_conv: dict[str, list[str]] = {}
    for mid, cid in rows:
        by_conv.setdefault(cid, []).append(mid)
    db.session.execute(db.delete(Message).filter(Message.id.in_([r[0] for r in rows])))
    db.session.commit()
    out = []
    for cid, ids in by_conv.items():
        conv = db.session.get(Conversation, cid)
        if conv:
            out.append((cid, ids, (conv.user_a, conv.user_b)))
    return out
