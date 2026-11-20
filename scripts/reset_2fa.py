"""Give an account a fresh TOTP secret (e.g. when the authenticator app entry is lost or stale).

    python scripts/reset_2fa.py admin

Writes the new secret and a QR code (SVG) to instance/ (git-ignored); scan it,
then delete the old "GhostLine" entry from the authenticator app.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pyotp  # noqa: E402
import qrcode  # noqa: E402
import qrcode.image.svg  # noqa: E402

from app import create_app  # noqa: E402
from app.audit import record  # noqa: E402
from app.auth import mfa  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import User  # noqa: E402


def main(username: str) -> None:
    app = create_app()
    with app.app_context():
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        if user is None:
            sys.exit(f"[!] no such user: {username}")
        secret = pyotp.random_base32()
        user.totp_secret_enc = mfa.encrypt_secret(user, secret)
        user.totp_enabled = True
        user.totp_last_step = None
        user.failed_attempts = 0
        user.locked_until = None
        record("mfa.reset", target=user.id, details={"by": "cli"})
        db.session.commit()

        uri = pyotp.TOTP(secret).provisioning_uri(name=user.username,
                                                  issuer_name=app.config["TOTP_ISSUER"])
        out = Path(app.instance_path)
        qr = out / f"2fa-{username}.svg"
        qrcode.make(uri, image_factory=qrcode.image.svg.SvgFillImage, box_size=10, border=4).save(qr)
        (out / f"2fa-{username}.txt").write_text(f"{username}\nsecret: {secret}\nuri: {uri}\n")
        print(f"[+] new 2FA secret for {username}")
        print(f"[*] scan {qr}  (secret also in {qr.with_suffix('.txt')})")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "admin")
