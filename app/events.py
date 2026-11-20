"""In-process event broker + Server-Sent Events stream.

Push is one-way (server -> browser). Every write still goes through the REST
API, so CSRF, authorization and validation stay in one place.
"""
import json
import queue
import threading
from collections import defaultdict

from flask import Response, current_app

from .extensions import db
from .models import AuthSession, utcnow

HEARTBEAT_S = 15


class Broker:
    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: dict[str, set[queue.Queue]] = defaultdict(set)

    def count(self, user_id: str) -> int:
        with self._lock:
            return len(self._subscribers.get(user_id, ()))

    def subscribe(self, user_id: str, limit: int | None = None) -> queue.Queue | None:
        q: queue.Queue = queue.Queue(maxsize=256)
        with self._lock:
            if limit is not None and len(self._subscribers[user_id]) >= limit:
                return None  # too many concurrent streams for this account
            self._subscribers[user_id].add(q)
        return q

    def unsubscribe(self, user_id: str, q: queue.Queue) -> None:
        with self._lock:
            self._subscribers[user_id].discard(q)
            if not self._subscribers[user_id]:
                del self._subscribers[user_id]

    def publish(self, user_id: str, event: str, data: dict) -> None:
        with self._lock:
            targets = list(self._subscribers.get(user_id, ()))
        for q in targets:
            try:
                q.put_nowait((event, data))
            except queue.Full:  # slow client: drop rather than block the request
                pass

    def online(self, user_id: str) -> bool:
        with self._lock:
            return bool(self._subscribers.get(user_id))


broker = Broker()


def _session_still_valid(session_id: str) -> bool:
    s = db.session.get(AuthSession, session_id)
    if s is None or s.revoked or s.expires_at <= utcnow():
        return False
    return utcnow() - s.last_seen <= current_app.config["SESSION_IDLE_TIMEOUT"]


def stream(user_id: str, session_id: str) -> Response:
    app = current_app._get_current_object()
    q = broker.subscribe(user_id, limit=app.config["MAX_STREAMS_PER_USER"])
    if q is None:
        return Response(json.dumps({"error": "too many live connections"}), status=429,
                        mimetype="application/json")

    def frame(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"

    def generate():
        try:
            yield "retry: 3000\n\n"
            yield frame("hello", {"session_id": session_id})
            while True:
                try:
                    event, data = q.get(timeout=HEARTBEAT_S)
                except queue.Empty:
                    with app.app_context():
                        valid = _session_still_valid(session_id)
                        db.session.remove()
                    if not valid:
                        yield frame("session_end", {"reason": "expired"})
                        return
                    yield ": ping\n\n"
                    continue
                if event == "session_revoked" and data.get("session_id") not in (None, session_id):
                    continue  # another of this user's sessions
                yield frame(event, data)
                if event == "session_revoked":
                    return
        finally:
            broker.unsubscribe(user_id, q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
