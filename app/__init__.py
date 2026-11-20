"""GhostLine application factory."""
import os
import threading
import time

import click
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import get_config

from .extensions import csrf, db, limiter
from .server_crypto import load_signing_key

# Strict CSP: no inline script/style, no third-party origins at all.
CSP = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": "'self' data:",      # data: only for the server-generated 2FA QR code
    "font-src": "'self'",
    "connect-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'none'",
    "form-action": "'self'",
    "frame-ancestors": "'none'",
}


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    # SQLite ignores FOREIGN KEY constraints unless this is enabled per connection.
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_app(config_name: str | None = None, **overrides) -> Flask:
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(config_name))
    app.config.update(overrides)  # test hook: flip RATELIMIT_ENABLED etc. before extensions bind
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    Talisman(
        app,
        force_https=app.config["FORCE_HTTPS"],
        strict_transport_security=True,
        strict_transport_security_max_age=app.config["HSTS_MAX_AGE"],
        content_security_policy=CSP,
        frame_options="DENY",
        referrer_policy="same-origin",  # CSRF "SSL strict" mode needs a same-origin Referer
        session_cookie_secure=True,
        session_cookie_http_only=True,
        session_cookie_samesite="Strict",  # Talisman would otherwise downgrade our cookie to Lax
        permissions_policy={"camera": "()", "microphone": "()", "geolocation": "()",
                            "payment": "()", "usb": "()"},
    )

    if app.config["SIGNING_KEY"]:
        app.extensions["signing_key"] = load_signing_key(app.config["SIGNING_KEY"])
    elif app.testing:
        app.extensions["signing_key"] = Ed25519PrivateKey.generate()
    else:
        raise RuntimeError("SIGNING_KEY not configured. Run: bash scripts/gen_certs.sh")

    from .auth import sessions
    sessions.init_app(app)

    from .admin.routes import bp as admin_bp
    from .auth.routes import bp as auth_bp
    from .chat.routes import bp as chat_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(admin_bp)

    @app.after_request
    def _harden_response(response):
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["Server"] = "GhostLine"  # don't advertise Werkzeug/Python versions
        return response

    _register_error_handlers(app)
    _register_cli(app)

    with app.app_context():
        db.create_all()

    # Started on the first request: the debug reloader's watcher process imports the
    # app too but never serves, so it never starts a second worker.
    if not app.testing:
        start_lock = threading.Lock()

        @app.before_request
        def _ensure_purge_worker():
            if "purge_worker" not in app.extensions:
                with start_lock:
                    if "purge_worker" not in app.extensions:
                        app.extensions["purge_worker"] = _start_purge_worker(app)

    return app


def _start_purge_worker(app: Flask) -> threading.Thread:
    from .chat.service import purge_expired
    from .events import broker

    def loop():
        while True:
            time.sleep(app.config["PURGE_INTERVAL_S"])
            try:
                with app.app_context():
                    for conv_id, ids, participants in purge_expired():
                        for uid in participants:
                            broker.publish(uid, "burned", {"conversation_id": conv_id, "ids": ids})
                    db.session.remove()
            except Exception:  # keep the worker alive; next tick retries
                app.logger.exception("purge worker failed")

    worker = threading.Thread(target=loop, name="ghostline-purge", daemon=True)
    worker.start()
    return worker


def _register_error_handlers(app: Flask) -> None:
    messages = {
        400: "MALFORMED REQUEST",
        401: "AUTHENTICATION REQUIRED",
        403: "ACCESS DENIED",
        404: "NODE NOT FOUND",
        405: "METHOD NOT ALLOWED",
        413: "REQUEST TOO LARGE",
        423: "ACCOUNT LOCKED",
        429: "RATE LIMIT EXCEEDED",
        500: "INTERNAL FAULT",
    }

    def render(code: int, message: str):
        if request.path.startswith("/api/"):
            return jsonify(error=message.lower()), code
        return render_template("errors/error.html", code=code, message=message), code

    def handler(err):
        code = getattr(err, "code", 500) or 500
        return render(code, messages.get(code, "ERROR"))

    for code in messages:
        app.register_error_handler(code, handler)
    app.register_error_handler(CSRFError, lambda err: render(400, "CSRF VALIDATION FAILED"))


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    @click.option("--drop", is_flag=True, help="Drop all tables first (destroys data).")
    def init_db(drop: bool) -> None:
        """Create the database tables."""
        if drop:
            db.drop_all()
        db.create_all()
        click.echo(f"[+] Database ready: {app.config['SQLALCHEMY_DATABASE_URI']}")
