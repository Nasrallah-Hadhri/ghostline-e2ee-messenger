"""Start GhostLine over HTTPS with the OpenSSL-issued certificate."""
import os
import sys

from werkzeug.serving import WSGIRequestHandler

from app import create_app


class QuietHandler(WSGIRequestHandler):
    """Let the application set the Server header (one value); don't add Werkzeug's own."""

    def send_header(self, keyword, value):
        if keyword.lower() == "server":
            return
        super().send_header(keyword, value)


app = create_app()

if __name__ == "__main__":
    cert, key = app.config["TLS_CERT"], app.config["TLS_KEY"]
    if not (os.path.exists(cert) and os.path.exists(key)):
        sys.exit("[!] TLS certificate missing. Run: bash scripts/gen_certs.sh")

    print(f"[*] GhostLine listening on https://localhost:{app.config['PORT']}")
    # Werkzeug dev server: threaded so long-lived SSE streams don't block other requests.
    app.run(host=app.config["HOST"], port=app.config["PORT"], ssl_context=(cert, key),
            debug=app.debug, threaded=True, request_handler=QuietHandler)
