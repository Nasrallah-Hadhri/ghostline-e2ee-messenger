"""Account creation, shared by the register API and scripts/seed.py."""
from flask import current_app
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import ROLE_USER, User, UserKey
from ..server_crypto import sign_directory_entry
from .security import (AUTH_KEY_BYTES, KDF_SALT_BYTES, MAX_WRAPPED_BYTES, WRAP_IV_BYTES,
                       ValidationError, b64e, canonical_public_jwk, decode_b64, hash_auth_key,
                       normalize_username)


class UsernameTaken(Exception):
    pass


def register_user(payload: dict, role: str = ROLE_USER) -> User:
    """Validate a client registration payload and persist user + signed key directory entry.

    Only whitelisted fields are read; `role` comes from the caller, never from the payload.
    """
    if not isinstance(payload, dict):
        raise ValidationError("JSON object required")

    username = normalize_username(payload.get("username"))
    auth_key = decode_b64(payload.get("auth_key"), "auth_key", length=AUTH_KEY_BYTES)
    kdf_salt = decode_b64(payload.get("kdf_salt"), "kdf_salt", length=KDF_SALT_BYTES)

    iterations = payload.get("kdf_iterations")
    if type(iterations) is not int or iterations != current_app.config["KDF_ITERATIONS"]:
        raise ValidationError("kdf_iterations does not match server policy")

    identity = payload.get("identity")
    if not isinstance(identity, dict):
        raise ValidationError("identity object required")
    ecdh_pub = canonical_public_jwk(identity.get("ecdh_pub"), "ecdh_pub")
    ecdsa_pub = canonical_public_jwk(identity.get("ecdsa_pub"), "ecdsa_pub")
    if ecdh_pub == ecdsa_pub:
        raise ValidationError("encryption and signing keys must differ")
    wrapped = decode_b64(identity.get("wrapped_priv"), "wrapped_priv", max_length=MAX_WRAPPED_BYTES)
    wrap_iv = decode_b64(identity.get("wrap_iv"), "wrap_iv", length=WRAP_IV_BYTES)

    if db.session.execute(db.select(User.id).filter_by(username=username)).first():
        raise UsernameTaken(username)

    user = User(username=username, auth_hash=hash_auth_key(auth_key), kdf_salt=b64e(kdf_salt),
                kdf_iterations=iterations, role=role)
    db.session.add(user)
    db.session.flush()  # assigns user.id, which the server signature covers

    signature = sign_directory_entry(current_app.extensions["signing_key"], user_id=user.id,
                                     version=1, ecdh_pub=ecdh_pub, ecdsa_pub=ecdsa_pub)
    db.session.add(UserKey(user_id=user.id, version=1, ecdh_pub=ecdh_pub, ecdsa_pub=ecdsa_pub,
                           wrapped_priv=b64e(wrapped), wrap_iv=b64e(wrap_iv), server_sig=signature))
    try:
        db.session.flush()
    except IntegrityError:  # lost a race on the unique username
        db.session.rollback()
        raise UsernameTaken(username) from None
    return user
