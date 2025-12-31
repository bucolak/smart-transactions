"""Finance and billing models supporting per-tenant isolation."""
from __future__ import annotations

import enum
from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Index, Numeric, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from .base import TenantMixin, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .user import User


class InvoiceStatus(str, enum.Enum):
    """Lifecycle states for invoices/billing records."""

    PENDING = "pending"
    PAID = "paid"
    OVERDUE = "overdue"


class Invoice(TenantMixin, TimestampMixin, db.Model):
    """Tenant-scoped invoice or billing record."""

    __tablename__ = "invoices"
    __table_args__ = (
        Index("ix_invoices_status", "organization_id", "status"),
        Index("ix_invoices_dates", "organization_id", "due_date"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(db.String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(db.Text, nullable=True)
    amount: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False, server_default=text("0"))
    currency: Mapped[str] = mapped_column(db.String(8), nullable=False, server_default=text("'USD'"))
    status: Mapped[InvoiceStatus] = mapped_column(
        db.Enum(InvoiceStatus, native_enum=False, validate_strings=True, name="invoice_status"),
        nullable=False,
        default=InvoiceStatus.PENDING,
        server_default=text("'pending'"),
    )
    issue_date: Mapped[date | None] = mapped_column(db.Date, nullable=True)
    due_date: Mapped[date | None] = mapped_column(db.Date, nullable=True)
    paid_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    created_by: Mapped["User | None"] = relationship("User", foreign_keys=[created_by_id])

    def mark_paid(self) -> None:
        """Convenience helper to mark invoice as paid."""
        self.status = InvoiceStatus.PAID
        self.paid_at = datetime.utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Invoice {self.id} {self.title} {self.amount}>"
