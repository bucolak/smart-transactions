"""Shared model mixins for multi-tenant enforcement and auditing."""
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Mapped, declared_attr, mapped_column

from ..extensions import db


class TimestampMixin:
    """Adds immutable creation and managed update timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        db.DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class TenantMixin:
    """Enforces organization ownership on every tenant-scoped record."""

    @declared_attr.directive
    def organization_id(cls) -> Mapped[int]:  # noqa: D401 - SQLAlchemy pattern
        return mapped_column(
            db.Integer,
            db.ForeignKey("organizations.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        )

    @classmethod
    def scoped_to_org(cls, organization_id: int):
        """Restrict queries to a specific organization to avoid cross-tenant leaks."""
        return cls.query.filter_by(organization_id=organization_id)
