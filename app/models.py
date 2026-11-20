"""GhostLine database schema.

Design rules:
  * Every ID that can appear in a URL is a random UUIDv4 (no guessable sequences -> harder IDOR).
  * The server never stores a password, a plaintext message, or a private key in the clear.
  * All timestamps are naive UTC (SQLite has no timezone type).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (Boolean, CheckConstraint, DateTime, ForeignKey, Integer, LargeBinary,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .extensions import db

ROLE_USER = "user"
ROLE_ADMIN = "admin"
ROLES = (ROLE_USER, ROLE_ADMIN)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_uuid() -> str:
    return str(uuid.uuid4())


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)

    # Argon2id hash of the client-derived auth_key (never the password itself)
    auth_hash: Mapped[str] = mapped_column(String(255))
    # Salt + iterations for the client-side PBKDF2 (password -> master key)
    kdf_salt: Mapped[str] = mapped_column(String(64))
    kdf_iterations: Mapped[int] = mapped_column(Integer)

    role: Mapped[str] = mapped_column(String(10), default=ROLE_USER)

    # TOTP secret, AES-256-GCM encrypted with DATA_ENC_KEY (nonce || ciphertext || tag)
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Last accepted TOTP time-step: a code can never be used twice (replay protection)
    totp_last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Account control
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    keys: Mapped[list["UserKey"]] = relationship(back_populates="user", cascade="all, delete-orphan",
                                                 order_by="UserKey.version")
    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (CheckConstraint(f"role IN {ROLES}", name="ck_users_role"),)

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def current_key(self) -> "UserKey | None":
        return self.keys[-1] if self.keys else None

    def is_locked(self, now: datetime | None = None) -> bool:
        return self.locked_until is not None and self.locked_until > (now or utcnow())

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


class UserKey(db.Model):
    """A user's E2E identity. Public keys are plaintext JWK; private keys are wrapped client-side."""
    __tablename__ = "user_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)

    ecdh_pub: Mapped[str] = mapped_column(Text)      # JWK, P-256 (encryption)
    ecdsa_pub: Mapped[str] = mapped_column(Text)     # JWK, P-256 (signatures)

    # AES-GCM(wrap_key, {ecdh_priv, ecdsa_priv}) produced in the browser; server can't open it
    wrapped_priv: Mapped[str] = mapped_column(Text)  # base64
    wrap_iv: Mapped[str] = mapped_column(String(32))  # base64, 96-bit

    # Ed25519 signature by the server over (user_id, version, ecdh_pub, ecdsa_pub)
    server_sig: Mapped[str] = mapped_column(String(128))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped[User] = relationship(back_populates="keys")

    __table_args__ = (UniqueConstraint("user_id", "version", name="uq_user_key_version"),)


class AuthSession(db.Model):
    """Server-side session. The cookie holds a random token; only its SHA-256 is stored."""
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)  # absolute expiry

    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)

    mfa_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_failures: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(back_populates="sessions")


class Conversation(db.Model):
    """1:1 channel. user_a < user_b so each pair has exactly one row."""
    __tablename__ = "conversations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_a: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    user_b: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    messages: Mapped[list["Message"]] = relationship(back_populates="conversation",
                                                     cascade="all, delete-orphan",
                                                     order_by="Message.created_at")

    __table_args__ = (
        UniqueConstraint("user_a", "user_b", name="uq_conversation_pair"),
        CheckConstraint("user_a < user_b", name="ck_conversation_order"),
    )

    @staticmethod
    def ordered_pair(u1: str, u2: str) -> tuple[str, str]:
        return (u1, u2) if u1 < u2 else (u2, u1)

    def has_participant(self, user_id: str) -> bool:
        return user_id in (self.user_a, self.user_b)

    def peer_of(self, user_id: str) -> str:
        return self.user_b if user_id == self.user_a else self.user_a


class Message(db.Model):
    """Opaque E2E envelope. The server can route and expire it, never read it."""
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), index=True)
    sender_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    ciphertext: Mapped[str] = mapped_column(Text)        # base64 AES-256-GCM output (incl. tag)
    iv: Mapped[str] = mapped_column(String(32))          # base64, 96-bit
    aad: Mapped[str] = mapped_column(Text)               # conv_id|sender_id|counter|timestamp
    signature: Mapped[str] = mapped_column(String(128))  # base64 ECDSA P-256 (r||s)
    sender_key_version: Mapped[int] = mapped_column(Integer, default=1)

    # Strictly increasing per (conversation, sender): replay protection
    counter: Mapped[int] = mapped_column(Integer)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    conversation: Mapped[Conversation] = relationship(back_populates="messages")

    __table_args__ = (UniqueConstraint("conversation_id", "sender_id", "counter", name="uq_message_counter"),)


class AuditLog(db.Model):
    """Append-only, HMAC-chained: hmac_n = HMAC(key, hmac_{n-1} || fields_n)."""
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    details: Mapped[str] = mapped_column(Text, default="{}")  # canonical JSON

    prev_hmac: Mapped[str] = mapped_column(String(64))
    hmac: Mapped[str] = mapped_column(String(64), unique=True)


class Invite(db.Model):
    """Optional invite-only registration. Only the SHA-256 of the code is stored."""
    __tablename__ = "invites"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
