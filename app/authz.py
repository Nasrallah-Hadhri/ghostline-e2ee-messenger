"""Server-side access control decorators.

Every check here runs on the server; hiding buttons in the UI is cosmetic only.
"""
from functools import wraps

from flask import abort, g, jsonify, redirect, request, url_for

from .models import ROLE_ADMIN


def _is_api() -> bool:
    return request.path.startswith("/api/")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            if _is_api():
                return jsonify(error="authentication required"), 401
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(role: str):
    """Vertical access control. Admins must also have 2FA enabled."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            from . import audit  # local import: audit imports models/extensions

            if g.user.role != role:
                audit.record("authz.denied", target=request.path[:64],
                             details={"method": request.method, "role": g.user.role})
                abort(403)
            if role == ROLE_ADMIN and not g.user.totp_enabled:
                if _is_api():
                    return jsonify(error="two-factor authentication required for admins",
                                   code="mfa_setup_required"), 403
                return redirect(url_for("auth.profile", setup2fa=1))
            return view(*args, **kwargs)
        return wrapped
    return decorator


admin_required = role_required(ROLE_ADMIN)
