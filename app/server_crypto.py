"""Server-side Ed25519 signing of the public-key directory ("PKI light").

The key is generated with OpenSSL by scripts/gen_certs.sh. Clients verify these
signatures before pinning a contact's keys, so a tampered DB row is detectable.
"""
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def load_signing_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError(f"{path} is not an Ed25519 private key")
    return key


def public_key_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def directory_payload(user_id: str, version: int, ecdh_pub: str, ecdsa_pub: str) -> bytes:
    """Canonical bytes that get signed; the browser rebuilds the exact same string."""
    return json.dumps(
        {"ecdh_pub": ecdh_pub, "ecdsa_pub": ecdsa_pub, "user_id": user_id, "version": version},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def sign_directory_entry(key: Ed25519PrivateKey, **entry) -> str:
    return base64.b64encode(key.sign(directory_payload(**entry))).decode()


def verify_directory_entry(public_key: Ed25519PublicKey, signature_b64: str, **entry) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64), directory_payload(**entry))
        return True
    except (InvalidSignature, ValueError):
        return False
