"""TOTP second factor (RFC 6238).

The shared secret is encrypted at rest with AES-256-GCM under DATA_ENC_KEY
(server-side encryption), bound to the user id via AAD so a ciphertext can't be
swapped between accounts. Each time-step is accepted at most once.
"""
import base64
import hmac
import io
import os
import re
import time

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

from ..models import User

STEP_S = 30
WINDOW = 1  # accept the previous / current / next step (clock skew)


def _aad(user: User) -> bytes:
    return f"ghostline-totp-v1|{user.id}".encode()


def encrypt_secret(user: User, secret: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(current_app.config["DATA_ENC_KEY"]).encrypt(nonce, secret.encode(), _aad(user))


def decrypt_secret(user: User) -> str | None:
    blob = user.totp_secret_enc
    if not blob:
        return None
    try:
        return AESGCM(current_app.config["DATA_ENC_KEY"]).decrypt(blob[:12], blob[12:], _aad(user)).decode()
    except InvalidTag:
        return None


def begin_setup(user: User) -> dict:
    """Generate a fresh (not yet enabled) secret; returns what the enrolment screen needs."""
    secret = pyotp.random_base32()
    user.totp_secret_enc = encrypt_secret(user, secret)
    user.totp_last_step = None
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username,
                                              issuer_name=current_app.config["TOTP_ISSUER"])
    svg = io.BytesIO()
    qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2).save(svg)
    return {"secret": secret, "otpauth_uri": uri,
            "qr_data_uri": "data:image/svg+xml;base64," + base64.b64encode(svg.getvalue()).decode()}


def verify_code(user: User, code, now: float | None = None) -> bool:
    """Check a 6-digit code; on success records the step so it can't be replayed."""
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code.strip()):
        return False
    secret = decrypt_secret(user)
    if secret is None:
        return False
    totp = pyotp.TOTP(secret)
    current = int((now if now is not None else time.time()) // STEP_S)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if hmac.compare_digest(totp.at(step * STEP_S), code.strip()):
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False  # replayed (or older) code
            user.totp_last_step = step
            return True
    return False
