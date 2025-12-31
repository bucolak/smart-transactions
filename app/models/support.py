"""Support and legal contact models with tenant awareness."""
from __future__ import annotations

import enum
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Index, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from .base import TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing helpers
    from .organization import Organization
    from .user import User


class SupportStatus(str, enum.Enum):
    """Lifecycle state for support requests."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class SupportRequest(TimestampMixin, db.Model):
    """Support ticket raised by a user or guest with optional tenant context."""

    __tablename__ = "support_requests"
    __table_args__ = (
        UniqueConstraint("public_id", name="uq_support_requests_public_id"),
        Index("ix_support_org", "organization_id", "status"),
        Index("ix_support_email", "email"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(db.String(36), nullable=False, default=lambda: str(uuid4()))
    organization_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    user_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    full_name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    email: Mapped[str] = mapped_column(db.String(255), nullable=False)
    subject: Mapped[str] = mapped_column(db.String(255), nullable=False)
    category: Mapped[str] = mapped_column(db.String(64), nullable=False, server_default=text("'General Inquiry'"))
    message: Mapped[str] = mapped_column(db.Text, nullable=False)
    status: Mapped[SupportStatus] = mapped_column(
        db.Enum(SupportStatus, native_enum=False, validate_strings=True, name="support_status"),
        nullable=False,
        default=SupportStatus.OPEN,
        server_default=text("'open'"),
    )
    user_role_snapshot: Mapped[str | None] = mapped_column(db.String(32), nullable=True)
    organization_name_snapshot: Mapped[str | None] = mapped_column(db.String(255), nullable=True)
    request_ip: Mapped[str | None] = mapped_column(db.String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(db.String(255), nullable=True)

    organization: Mapped["Organization | None"] = relationship("Organization")
    user: Mapped["User | None"] = relationship("User")

    def mark_acknowledged(self) -> None:
        self.status = SupportStatus.ACKNOWLEDGED

    def mark_resolved(self) -> None:
        self.status = SupportStatus.RESOLVED

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SupportRequest {self.public_id} {self.status.value}>"
