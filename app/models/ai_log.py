"""AI operations monitoring models with tenant isolation."""
from __future__ import annotations

import enum
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Index, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from .base import TenantMixin, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing helpers
    from .user import User


class AIStatus(str, enum.Enum):
    """Status lifecycle for AI interactions."""

    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"


class AIInteractionLog(TenantMixin, TimestampMixin, db.Model):
    """Audit log of AI operations executed within an organization."""

    __tablename__ = "ai_interaction_logs"
    __table_args__ = (
        Index("ix_ai_logs_status", "organization_id", "status"),
        Index("ix_ai_logs_user", "organization_id", "triggered_by_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    operation_name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    context: Mapped[str | None] = mapped_column(db.Text, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(db.Text, nullable=True)
    status: Mapped[AIStatus] = mapped_column(
        db.Enum(AIStatus, native_enum=False, validate_strings=True, name="ai_status"),
        nullable=False,
        default=AIStatus.PENDING,
        server_default=text("'pending'"),
    )
    duration_ms: Mapped[int | None] = mapped_column(db.Integer, nullable=True)
    triggered_by_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    triggered_by: Mapped["User | None"] = relationship("User", foreign_keys=[triggered_by_id])

    def mark_result(self, status: AIStatus, summary: str | None = None, duration_ms: int | None = None) -> None:
        """Update status and summary for the log entry."""
        self.status = status
        self.result_summary = summary
        self.duration_ms = duration_ms
        if status == AIStatus.SUCCESS:
            self.context = self.context or ""

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AIInteractionLog {self.id} {self.operation_name} {self.status}>"
