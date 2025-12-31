"""Project and task models with tenant isolation and ownership metadata."""
from __future__ import annotations

import enum
from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Index, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db
from .base import TenantMixin, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing helpers
    from .user import User


class ProjectStatus(str, enum.Enum):
    """Lifecycle states for projects."""

    PLANNING = "planning"
    ACTIVE = "active"
    ON_HOLD = "on_hold"
    COMPLETED = "completed"


class TaskStatus(str, enum.Enum):
    """Task progress states."""

    TODO = "todo"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class TaskPriority(str, enum.Enum):
    """Task urgency levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Project(TenantMixin, TimestampMixin, db.Model):
    """Organization-scoped project grouping multiple tasks."""

    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_project_name_per_org"),
        Index("ix_projects_status", "organization_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(db.String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(db.Text, nullable=True)
    status: Mapped[ProjectStatus] = mapped_column(
        db.Enum(ProjectStatus, native_enum=False, validate_strings=True, name="project_status"),
        nullable=False,
        default=ProjectStatus.ACTIVE,
        server_default=text("'active'"),
    )
    due_date: Mapped[date | None] = mapped_column(db.Date, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    created_by: Mapped["User" | None] = relationship("User", foreign_keys=[created_by_id])
    tasks: Mapped[list["Task"]] = relationship(
        "Task",
        back_populates="project",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Task.due_date.nulls_last()",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Project {self.id} {self.name}>"


class Task(TenantMixin, TimestampMixin, db.Model):
    """Work item linked to a project and optionally assigned to a user."""

    __tablename__ = "tasks"
    __table_args__ = (
        Index("ix_tasks_status", "organization_id", "status"),
        Index("ix_tasks_assignee", "organization_id", "assignee_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        db.Integer,
        db.ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(db.String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(db.Text, nullable=True)
    status: Mapped[TaskStatus] = mapped_column(
        db.Enum(TaskStatus, native_enum=False, validate_strings=True, name="task_status"),
        nullable=False,
        default=TaskStatus.TODO,
        server_default=text("'todo'"),
    )
    priority: Mapped[TaskPriority] = mapped_column(
        db.Enum(TaskPriority, native_enum=False, validate_strings=True, name="task_priority"),
        nullable=False,
        default=TaskPriority.MEDIUM,
        server_default=text("'medium'"),
    )
    due_date: Mapped[date | None] = mapped_column(db.Date, nullable=True)
    assignee_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by_id: Mapped[int | None] = mapped_column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(db.DateTime, nullable=True)

    project: Mapped[Project] = relationship("Project", back_populates="tasks", lazy="joined")
    assignee: Mapped["User" | None] = relationship("User", foreign_keys=[assignee_id])
    created_by: Mapped["User" | None] = relationship("User", foreign_keys=[created_by_id])

    def mark_complete(self) -> None:
        """Mark task as completed and set timestamp."""
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Task {self.id} {self.title}>"
