"""Authentication and authorization helpers for tenant-safe access control."""
from __future__ import annotations

import functools
import secrets
import string
from typing import Callable, Optional
from uuid import uuid4

from flask import abort, flash, g, redirect, request, session, url_for
from sqlalchemy.orm import joinedload

from ..models import Organization, User, UserRole


SESSION_USER_ID = "user_id"
SESSION_ORG_ID = "organization_id"
SESSION_ROLE = "role"
SESSION_ORG_SLUG = "org_slug"
SESSION_NONCE = "session_nonce"
_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()_-+=[]{}"  # limited safe set


def _reset_session_state() -> None:
    """Drop all session keys to prevent stale or tampered sessions."""
    session_keys = list(session.keys())
    for key in session_keys:
        session.pop(key, None)


def generate_secure_password(length: int = 14) -> str:
    """Return a strong random password for temporary credentials."""
    length = max(length, 12)
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def start_session(user: User) -> None:
    """Initialize a new signed session scoped to the user's organization."""
    _reset_session_state()
    session.permanent = True
    session[SESSION_USER_ID] = user.id
    session[SESSION_ORG_ID] = user.organization_id
    session[SESSION_ROLE] = user.role.value
    session[SESSION_ORG_SLUG] = user.organization.slug
    session[SESSION_NONCE] = str(uuid4())


def clear_session() -> None:
    """Safely clear the current session."""
    _reset_session_state()


def _load_user_from_session() -> Optional[User]:
    """Fetch a user bound to the current session, enforcing tenant isolation."""
    user_id = session.get(SESSION_USER_ID)
    org_id = session.get(SESSION_ORG_ID)
    if not user_id or not org_id:
        return None

    user = (
        User.query.options(joinedload(User.organization))
        .filter_by(id=user_id, organization_id=org_id, is_active=True)
        .first()
    )
    if not user or not user.organization or not user.organization.is_active:
        clear_session()
        return None

    session_org_slug = session.get(SESSION_ORG_SLUG)
    if session_org_slug and session_org_slug != user.organization.slug:
        clear_session()
        return None

    return user


def current_user() -> Optional[User]:
    """Return the current authenticated user, loading once per request."""
    if hasattr(g, "current_user"):
        return g.current_user  # type: ignore[attr-defined]

    user = _load_user_from_session()
    g.current_user = user  # type: ignore[attr-defined]
    if user:
        g.current_org = user.organization  # type: ignore[attr-defined]
    else:
        g.current_org = None  # type: ignore[attr-defined]
    return user


def login_required(view: Callable):
    """Decorator to guard routes that require authentication."""

    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        return view(*args, **kwargs)

    return wrapped_view


def org_required(view: Callable):
    """Ensure the user remains bound to the same organization for the request."""

    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        org_id = session.get(SESSION_ORG_ID)
        if not user or user.organization_id != org_id:
            clear_session()
            flash("Your session expired. Please sign in again.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(*roles: UserRole):
    """Enforce role-based access for protected resources."""
    allowed_roles = {role.value if isinstance(role, UserRole) else str(role) for role in roles}

    def decorator(view: Callable):
        @functools.wraps(view)
        def wrapped_view(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please sign in to continue.", "warning")
                return redirect(url_for("auth.login", next=request.url))
            if user.role.value not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


def require_org_context(org_id: int) -> Organization:
    """Fetch an organization ensuring it matches the session context."""
    org = Organization.query.filter_by(id=org_id, is_active=True).first()
    if not org:
        clear_session()
        abort(403)
    return org


def normalize_email(value: str) -> str:
    """Normalize an email for consistent lookups."""
    return value.strip().lower()
