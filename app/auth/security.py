"""Credential handling: Argon2id, pre-login KDF parameters, strict input validation.

Zero-knowledge model: the browser turns the passphrase into
    master   = PBKDF2-SHA256(passphrase, kdf_salt, iterations)
    auth_key = HKDF(master, "ghostline-auth-v1")   -> sent to the server
    wrap_key = HKDF(master, "ghostline-wrap-v1")   -> never leaves the browser
The server only ever sees auth_key and stores Argon2id(auth_key).
"""
import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.asymmetric import ec
from flask import current_app

AUTH_KEY_BYTES = 32
KDF_SALT_BYTES = 16
WRAP_IV_BYTES = 12
MAX_WRAPPED_BYTES = 2048

ALLOWED_JWK_MEMBERS = {"kty", "crv", "x", "y", "ext", "key_ops"}


class ValidationError(ValueError):
    """Client input rejected; the message is safe to return to the client."""


# --- Argon2id --------------------------------------------------------------

def _hasher() -> PasswordHasher:
    cfg = current_app.config
    return PasswordHasher(time_cost=cfg["ARGON2_TIME_COST"], memory_cost=cfg["ARGON2_MEMORY_KIB"],
                          parallelism=cfg["ARGON2_PARALLELISM"], type=Type.ID)


def _dummy_hash() -> str:
    # Verified against when the username doesn't exist, so both paths cost one Argon2id run.
    cache = current_app.extensions.setdefault("ghostline", {})
    if "dummy_hash" not in cache:
        cache["dummy_hash"] = _hasher().hash(secrets.token_bytes(AUTH_KEY_BYTES))
    return cache["dummy_hash"]


def hash_auth_key(auth_key: bytes) -> str:
    return _hasher().hash(auth_key)


def verify_auth_key(stored_hash: str | None, auth_key: bytes) -> bool:
    """Constant-work verification: unknown users still pay for one Argon2id verify."""
    try:
        return _hasher().verify(stored_hash or _dummy_hash(), auth_key) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher().check_needs_rehash(stored_hash)


# --- Pre-login --------------------------------------------------------------

def fake_kdf_salt(username: str) -> str:
    """Deterministic per-username salt for accounts that don't exist (anti-enumeration)."""
    key = current_app.config["PRELOGIN_SALT_KEY"]
    digest = hmac.new(key, b"prelogin|" + username.encode(), hashlib.sha256).digest()
    return b64e(digest[:KDF_SALT_BYTES])


# --- Input validation -------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def decode_b64(value, field: str, length: int | None = None, max_length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field}: base64 string required")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValidationError(f"{field}: invalid base64") from None
    if length is not None and len(raw) != length:
        raise ValidationError(f"{field}: expected {length} bytes")
    if max_length is not None and len(raw) > max_length:
        raise ValidationError(f"{field}: too large")
    return raw


def _b64url_coord(value, field: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValidationError(f"{field}: invalid P-256 coordinate")
    return base64.urlsafe_b64decode(value + "=")


def normalize_username(value) -> str:
    if not isinstance(value, str):
        raise ValidationError("handle required")
    username = value.strip().lower()
    if not re.fullmatch(current_app.config["USERNAME_PATTERN"], username):
        raise ValidationError("handle must be 3-32 chars of [a-z0-9_]")
    return username


def canonical_public_jwk(jwk, field: str) -> str:
    """Validate an EC P-256 public JWK and return its canonical JSON string.

    The canonical string is what gets stored, signed by the server and
    fingerprinted by clients, so every party hashes identical bytes.
    """
    if not isinstance(jwk, dict):
        raise ValidationError(f"{field}: JWK object required")
    if "d" in jwk:
        raise ValidationError(f"{field}: private key material must never be uploaded")
    if set(jwk) - ALLOWED_JWK_MEMBERS:
        raise ValidationError(f"{field}: unexpected JWK members")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValidationError(f"{field}: only EC P-256 keys are accepted")

    x = _b64url_coord(jwk.get("x"), field)
    y = _b64url_coord(jwk.get("y"), field)
    try:
        ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                      ec.SECP256R1()).public_key()
    except ValueError:
        raise ValidationError(f"{field}: point is not on the P-256 curve") from None

    return json.dumps({"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
                      sort_keys=True, separators=(",", ":"))
