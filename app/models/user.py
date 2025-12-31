"""User model representing SaaS accounts scoped to organizations."""
from __future__ import annotations

import enum
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Index, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

from ..extensions import db
from .base import TenantMixin, TimestampMixin
from .email_token import EmailToken

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .organization import Organization


class UserRole(str, enum.Enum):
    """System-wide role definitions."""

    ADMIN = "admin"
    STANDARD = "standard"


class User(TenantMixin, TimestampMixin, db.Model):
    """Tenant-bound user with role enforcement and activity tracking."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("organization_id", "email", name="uq_users_email_per_org"),
        Index("ix_users_role_org", "organization_id", "role"),
        Index("ix_users_is_active", "is_active"),
        Index("ix_users_is_verified", "is_verified"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(db.String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(db.String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        db.Enum(UserRole, native_enum=False, validate_strings=True, name="user_role"),
        nullable=False,
        default=UserRole.STANDARD,
    )
    is_active: Mapped[bool] = mapped_column(db.Boolean, nullable=False, server_default=text("1"))
    is_verified: Mapped[bool] = mapped_column(db.Boolean, nullable=False, server_default=text("0"))
    email_verified_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(db.Boolean, nullable=False, server_default=text("1"))
    last_login_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="users", lazy="joined"
    )

    email_tokens: Mapped[list[EmailToken]] = relationship(
        "EmailToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def set_password(self, raw_password: str) -> None:
        """Hash and store a password using Werkzeug's PBKDF2 implementation."""
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """Validate a password against the stored hash."""
        return check_password_hash(self.password_hash, raw_password)

    def mark_login(self) -> None:
        """Record the last login timestamp for auditing."""
        self.last_login_at = datetime.utcnow()

    def mark_verified(self) -> None:
        """Mark the user's email as verified and activate the account."""
        self.is_verified = True
        self.is_active = True
        self.email_verified_at = datetime.utcnow()

    def __repr__(self) -> str:  # pragma: no cover - repr helper
        return f"<User {self.email} @ org {self.organization_id}>"
