"""Organization model representing tenant boundaries for the SaaS platform."""
from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Index, UniqueConstraint, event, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from .base import TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .user import User


class Organization(TimestampMixin, db.Model):
    """A tenant organization with lifecycle controls and branding metadata."""

    __tablename__ = "organizations"
    __table_args__ = (
        UniqueConstraint("public_id", name="uq_organizations_public_id"),
        UniqueConstraint("slug", name="uq_organizations_slug"),
        UniqueConstraint("contact_email", name="uq_organizations_contact_email"),
        Index("ix_organizations_is_active", "is_active"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(
        db.String(36), nullable=False, default=lambda: str(uuid4())
    )
    name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    slug: Mapped[str] = mapped_column(db.String(255), nullable=False)
    contact_email: Mapped[str] = mapped_column(db.String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(db.Boolean, nullable=False, server_default=text("1"))
    logo_url: Mapped[str | None] = mapped_column(db.String(512), nullable=True)
    brand_color: Mapped[str | None] = mapped_column(db.String(32), nullable=True)

    users: Mapped[list["User"]] = relationship(
        "User",
        back_populates="organization",
        cascade="save-update, merge",
        passive_deletes=True,
    )

    def deactivate(self):
        """Softly disable an organization without destructive deletes."""
        self.is_active = False

    def __repr__(self) -> str:  # pragma: no cover - repr helper
        return f"<Organization {self.slug}>"


@event.listens_for(Organization, "before_delete")
def _block_hard_delete(mapper, connection, target):  # pragma: no cover - safety hook
    """Disallow destructive organization deletes to protect tenant data."""
    raise ValueError("Organizations cannot be hard-deleted; deactivate instead.")
