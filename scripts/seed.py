"""Seed demo accounts: 1 admin + 3 users.

Accounts are created exactly like the browser would (client-side key schedule
via clientsim), so they can log in through the real UI. Random passphrases are
written to instance/seed_credentials.txt (git-ignored); nothing is hard-coded.

Usage: python scripts/seed.py [--reset]
"""
import argparse
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.auth.service import UsernameTaken, register_user  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import ROLE_ADMIN, ROLE_USER  # noqa: E402
from clientsim import registration_payload  # noqa: E402

ACCOUNTS = [("admin", ROLE_ADMIN), ("alice", ROLE_USER), ("bob", ROLE_USER), ("charlie", ROLE_USER)]
WORDS = ("cipher ghost proxy vector kernel shadow socket packet signal static vault orbit "
         "falcon raven onyx neon pulse matrix nova zero echo delta sigma photon").split()


def passphrase() -> str:
    return "-".join(secrets.choice(WORDS) for _ in range(4)) + f"-{secrets.randbelow(100):02d}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reset", action="store_true", help="drop and recreate all tables first")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        if args.reset:
            db.drop_all()
            db.create_all()

        lines = []
        for username, role in ACCOUNTS:
            secret = passphrase()
            payload, _ = registration_payload(username, secret, app.config["KDF_ITERATIONS"])
            try:
                register_user(payload, role=role)
                db.session.commit()
            except UsernameTaken:
                db.session.rollback()
                print(f"[=] {username} already exists, skipped (use --reset to recreate)")
                continue
            lines.append(f"{username:10} {role:6} {secret}")
            print(f"[+] {username} ({role})")

        if lines:
            out = Path(app.instance_path) / "seed_credentials.txt"
            with out.open("w" if args.reset else "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            print(f"[*] Passphrases written to {out}")


if __name__ == "__main__":
    main()
