"""Subscription and billing models for tenant-scoped licensing."""
from __future__ import annotations

import enum
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import Index, Numeric, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from .base import TenantMixin, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .organization import Organization
    from .user import User


class SubscriptionStatus(str, enum.Enum):
    """Lifecycle states for an organization's subscription."""

    TRIAL = "trial"
    ACTIVE = "active_paid"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


class PaymentProvider(str, enum.Enum):
    """Payment gateways supported by the platform."""

    STRIPE = "stripe"
    RAZORPAY = "razorpay"


class PaymentStatus(str, enum.Enum):
    """Payment transaction states."""

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class SubscriptionPlan(TimestampMixin, db.Model):
    """Commercial plan definition with base and per-seat pricing."""

    __tablename__ = "subscription_plans"
    __table_args__ = (UniqueConstraint("name", name="uq_subscription_plans_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(db.String(128), nullable=False)
    currency: Mapped[str] = mapped_column(db.String(8), nullable=False, server_default=text("'USD'"))
    base_fee: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    per_member_fee: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    is_active: Mapped[bool] = mapped_column(db.Boolean, nullable=False, server_default=text("1"))
    description: Mapped[str | None] = mapped_column(db.Text, nullable=True)

    subscriptions: Mapped[list["OrganizationSubscription"]] = relationship(
        "OrganizationSubscription",
        back_populates="plan",
        cascade="save-update",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SubscriptionPlan {self.name} {self.currency}>"


class OrganizationSubscription(TimestampMixin, db.Model):
    """Per-organization subscription state and licensed capacity."""

    __tablename__ = "organization_subscriptions"
    __table_args__ = (
        UniqueConstraint("organization_id", name="uq_subscription_org_unique"),
        Index("ix_subscription_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    plan_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("subscription_plans.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[SubscriptionStatus] = mapped_column(
        db.Enum(SubscriptionStatus, native_enum=False, validate_strings=True, name="subscription_status"),
        nullable=False,
        default=SubscriptionStatus.TRIAL,
        server_default=text("'trial'"),
    )
    trial_starts_at: Mapped[datetime] = mapped_column(db.DateTime, nullable=False, default=datetime.utcnow)
    trial_ends_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)
    trial_member_limit: Mapped[int] = mapped_column(db.Integer, nullable=False, default=5, server_default=text("5"))
    purchased_member_limit: Mapped[int] = mapped_column(db.Integer, nullable=False, default=0, server_default=text("0"))
    current_member_count: Mapped[int] = mapped_column(db.Integer, nullable=False, default=0, server_default=text("0"))
    currency: Mapped[str] = mapped_column(db.String(8), nullable=False, server_default=text("'USD'"))
    payment_provider: Mapped[PaymentProvider | None] = mapped_column(
        db.Enum(PaymentProvider, native_enum=False, validate_strings=True, name="payment_provider"),
        nullable=True,
    )
    last_payment_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="subscription", lazy="joined"
    )
    plan: Mapped[SubscriptionPlan | None] = relationship("SubscriptionPlan", back_populates="subscriptions")
    transactions: Mapped[list["PaymentTransaction"]] = relationship(
        "PaymentTransaction",
        back_populates="subscription",
        cascade="save-update",
        order_by="PaymentTransaction.created_at.desc()",
    )

    @property
    def allowed_member_limit(self) -> int:
        """Return the seat capacity available to the organization."""
        purchased = self.purchased_member_limit or 0
        trial_cap = self.trial_member_limit or 0
        if self.status == SubscriptionStatus.ACTIVE and purchased > 0:
            return purchased
        return max(trial_cap, purchased)

    def can_add_members(self, additional: int = 1) -> bool:
        """Check whether additional members fit within capacity."""
        return (self.current_member_count or 0) + max(additional, 0) <= self.allowed_member_limit

    def mark_paid(self, *, member_limit: int, provider: PaymentProvider, currency: str) -> None:
        """Activate subscription after a verified payment."""
        self.status = SubscriptionStatus.ACTIVE
        self.purchased_member_limit = max(member_limit, 0)
        self.payment_provider = provider
        self.currency = currency
        self.last_payment_at = datetime.utcnow()

    def set_trial_defaults(self, *, trial_days: int = 14, trial_limit: int = 5, currency: str = "USD") -> None:
        """Initialize a predictable trial window and free capacity."""
        self.status = SubscriptionStatus.TRIAL
        self.trial_starts_at = datetime.utcnow()
        self.trial_ends_at = datetime.utcnow() + timedelta(days=trial_days)
        self.trial_member_limit = trial_limit
        self.currency = currency

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<OrgSubscription org={self.organization_id} status={self.status.value}>"


class PaymentTransaction(TenantMixin, TimestampMixin, db.Model):
    """Payment transaction record linked to an organization subscription."""

    __tablename__ = "payment_transactions"
    __table_args__ = (
        Index("ix_payment_provider", "organization_id", "provider"),
        Index("ix_payment_status", "organization_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("organization_subscriptions.id", ondelete="SET NULL"),
        nullable=True,
    )
    provider: Mapped[PaymentProvider] = mapped_column(
        db.Enum(PaymentProvider, native_enum=False, validate_strings=True, name="payment_provider_txn"),
        nullable=False,
    )
    status: Mapped[PaymentStatus] = mapped_column(
        db.Enum(PaymentStatus, native_enum=False, validate_strings=True, name="payment_status"),
        nullable=False,
        default=PaymentStatus.PENDING,
        server_default=text("'pending'"),
    )
    amount: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(db.String(8), nullable=False, server_default=text("'USD'"))
    member_limit: Mapped[int] = mapped_column(db.Integer, nullable=False)
    base_fee: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    per_member_fee: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    description: Mapped[str | None] = mapped_column(db.String(255), nullable=True)
    provider_payment_id: Mapped[str | None] = mapped_column(db.String(128), nullable=True, index=True)
    provider_order_id: Mapped[str | None] = mapped_column(db.String(128), nullable=True, index=True)
    provider_signature: Mapped[str | None] = mapped_column(db.String(255), nullable=True)
    receipt_email: Mapped[str | None] = mapped_column(db.String(255), nullable=True)
    raw_details: Mapped[str | None] = mapped_column(db.Text, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    subscription: Mapped[OrganizationSubscription | None] = relationship(
        "OrganizationSubscription", back_populates="transactions"
    )
    created_by: Mapped["User | None"] = relationship("User", foreign_keys=[created_by_id])

    def mark_success(self, *, payment_id: str | None = None, signature: str | None = None) -> None:
        """Mark the transaction as successfully settled."""
        self.status = PaymentStatus.SUCCEEDED
        if payment_id:
            self.provider_payment_id = payment_id
        if signature:
            self.provider_signature = signature

    def mark_failed(self, reason: str | None = None) -> None:
        """Mark the transaction as failed and attach reason."""
        self.status = PaymentStatus.FAILED
        if reason:
            self.raw_details = reason[:4000]

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<PaymentTxn {self.provider.value} {self.status.value} {self.amount}>"
