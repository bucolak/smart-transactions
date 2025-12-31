"""Email-delivered security tokens for OTP, MFA, and reset flows."""
from __future__ import annotations

import enum
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Index, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from .base import TenantMixin, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .user import User


class EmailTokenPurpose(str, enum.Enum):
    """Supported use cases for email tokens."""

    REGISTRATION_VERIFY = "registration_verify"
    LOGIN_MFA = "login_mfa"
    PASSWORD_RESET = "password_reset"
    ORG_INVITE = "org_invite"
    BILLING_NOTICE = "billing_notice"


class EmailToken(TenantMixin, TimestampMixin, db.Model):
    """Tenant-bound email tokens with expiry and attempt controls."""

    __tablename__ = "email_tokens"
    __table_args__ = (
        UniqueConstraint("public_id", name="uq_email_tokens_public_id"),
        Index("ix_email_tokens_lookup", "organization_id", "purpose", "user_id"),
        Index("ix_email_tokens_expires", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(
        db.String(64), nullable=False, default=lambda: uuid4().hex
    )
    user_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    purpose: Mapped[EmailTokenPurpose] = mapped_column(
        db.Enum(EmailTokenPurpose, native_enum=False, validate_strings=True, name="email_token_purpose"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(db.String(128), nullable=False)
    salt: Mapped[str] = mapped_column(db.String(64), nullable=False)
    destination_email: Mapped[str] = mapped_column(db.String(255), nullable=False)
    delivery_channel: Mapped[str] = mapped_column(db.String(32), nullable=False, server_default=text("'email'"))
    expires_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(db.Integer, nullable=False, default=0, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(db.Integer, nullable=False, default=5, server_default=text("5"))
    request_ip: Mapped[str | None] = mapped_column(db.String(64), nullable=True)
    meta: Mapped[str | None] = mapped_column("metadata", db.Text, nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)

    user: Mapped["User | None"] = relationship("User", back_populates="email_tokens")

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() >= self.expires_at

    @property
    def is_consumed(self) -> bool:
        return self.consumed_at is not None

    def remaining_attempts(self) -> int:
        return max((self.max_attempts or 0) - (self.attempts or 0), 0)

    def consume(self) -> None:
        self.consumed_at = datetime.utcnow()

    def increment_attempts(self) -> None:
        self.attempts = (self.attempts or 0) + 1

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<EmailToken {self.purpose.value} for {self.destination_email}>"
