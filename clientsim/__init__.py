"""Python reference implementation of the GhostLine browser crypto (app/static/js/crypto.js).

Used by scripts/seed.py and the test-suite to behave exactly like a real browser
client. Any change to the JS key schedule or blob format must be mirrored here.
"""
import base64
import hashlib
import json
import os
import unicodedata
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_SALT = bytes(32)
INFO_AUTH = b"ghostline-auth-v1"
INFO_WRAP = b"ghostline-wrap-v1"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def b64url_e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- Key schedule -------------------------------------------------------------

def derive_master(passphrase: str, salt: bytes, iterations: int) -> bytes:
    data = unicodedata.normalize("NFKC", passphrase).encode()
    return hashlib.pbkdf2_hmac("sha256", data, salt, iterations, 32)


def _hkdf(master: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=info).derive(master)


def derive_auth_key(master: bytes) -> str:
    return b64e(_hkdf(master, INFO_AUTH))


def derive_wrap_key(master: bytes) -> bytes:
    return _hkdf(master, INFO_WRAP)


# --- Identity keys --------------------------------------------------------------

@dataclass
class Identity:
    ecdh: ec.EllipticCurvePrivateKey
    ecdsa: ec.EllipticCurvePrivateKey


def generate_identity() -> Identity:
    return Identity(ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1()))


def jwk(key: ec.EllipticCurvePrivateKey, private: bool = False) -> dict:
    nums = key.public_key().public_numbers()
    out = {"kty": "EC", "crv": "P-256",
           "x": b64url_e(nums.x.to_bytes(32, "big")), "y": b64url_e(nums.y.to_bytes(32, "big"))}
    if private:
        out["d"] = b64url_e(key.private_numbers().private_value.to_bytes(32, "big"))
    return out


def identity_aad(username: str) -> bytes:
    return f"ghostline-identity-v1|{username}".encode()


def seal_identity(wrap_key: bytes, identity: Identity, username: str) -> dict:
    payload = json.dumps({"v": 1, "ecdh": jwk(identity.ecdh, True), "ecdsa": jwk(identity.ecdsa, True)})
    iv = os.urandom(12)
    ct = AESGCM(wrap_key).encrypt(iv, payload.encode(), identity_aad(username))
    return {"wrapped_priv": b64e(ct), "wrap_iv": b64e(iv)}


def open_identity(wrap_key: bytes, wrapped_priv: str, wrap_iv: str, username: str) -> Identity:
    payload = json.loads(AESGCM(wrap_key).decrypt(b64d(wrap_iv), b64d(wrapped_priv), identity_aad(username)))

    def load(j):
        return ec.derive_private_key(int.from_bytes(b64url_d(j["d"]), "big"), ec.SECP256R1())

    return Identity(load(payload["ecdh"]), load(payload["ecdsa"]))


# --- Request payloads -------------------------------------------------------------

def registration_payload(username: str, passphrase: str, iterations: int) -> tuple[dict, Identity]:
    salt = os.urandom(16)
    master = derive_master(passphrase, salt, iterations)
    identity = generate_identity()
    payload = {
        "username": username,
        "auth_key": derive_auth_key(master),
        "kdf_salt": b64e(salt),
        "kdf_iterations": iterations,
        "identity": {
            "ecdh_pub": jwk(identity.ecdh),
            "ecdsa_pub": jwk(identity.ecdsa),
            **seal_identity(derive_wrap_key(master), identity, username),
        },
    }
    return payload, identity


def login_keys(passphrase: str, kdf_salt: str, iterations: int) -> tuple[str, bytes]:
    """From /api/auth/prelogin output, compute (auth_key to send, wrap_key to keep)."""
    master = derive_master(passphrase, b64d(kdf_salt), iterations)
    return derive_auth_key(master), derive_wrap_key(master)


# --- Messages (mirror of GhostCrypto.sealMessage / openMessage) ----------------------------

MSG_INFO = b"ghostline-msg-v1"


def _pub_from_jwk(j) -> ec.EllipticCurvePublicKey:
    if isinstance(j, str):
        j = json.loads(j)
    return ec.EllipticCurvePublicNumbers(int.from_bytes(b64url_d(j["x"]), "big"),
                                         int.from_bytes(b64url_d(j["y"]), "big"),
                                         ec.SECP256R1()).public_key()


def conversation_key(my_ecdh: ec.EllipticCurvePrivateKey, peer_ecdh_pub, conversation_id: str) -> bytes:
    shared = my_ecdh.exchange(ec.ECDH(), _pub_from_jwk(peer_ecdh_pub))  # raw x-coordinate, like Web Crypto deriveBits
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=conversation_id.encode(), info=MSG_INFO).derive(shared)


def message_aad(conversation_id: str, sender_id: str, counter: int, ttl, key_version: int) -> str:
    return f"ghostline-msg-v1|{conversation_id}|{sender_id}|{counter}|{ttl or 0}|{key_version}"


def sign_raw(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """ECDSA P-256/SHA-256 as Web Crypto emits it: raw r||s (64 bytes)."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(pub_jwk, signature: bytes, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        _pub_from_jwk(pub_jwk).verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def seal_message(identity: Identity, peer_ecdh_pub, conversation_id: str, sender_id: str, counter: int,
                 plaintext: str, ttl=None, key_version: int = 1) -> dict:
    key = conversation_key(identity.ecdh, peer_ecdh_pub, conversation_id)
    iv = os.urandom(12)
    aad = message_aad(conversation_id, sender_id, counter, ttl, key_version)
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), aad.encode())
    sig = sign_raw(identity.ecdsa, iv + aad.encode() + ct)
    return {"ciphertext": b64e(ct), "iv": b64e(iv), "aad": aad, "signature": b64e(sig),
            "counter": counter, "ttl": ttl, "sender_key_version": key_version}


def open_message(identity: Identity, peer_ecdh_pub, sender_ecdsa_pub, envelope: dict) -> str:
    iv, ct, sig = b64d(envelope["iv"]), b64d(envelope["ciphertext"]), b64d(envelope["signature"])
    if not verify_raw(sender_ecdsa_pub, sig, iv + envelope["aad"].encode() + ct):
        raise ValueError("signature invalid")
    key = conversation_key(identity.ecdh, peer_ecdh_pub, envelope["conversation_id"])
    return AESGCM(key).decrypt(iv, ct, envelope["aad"].encode()).decode()
