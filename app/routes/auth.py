"""Authentication and onboarding routes for the multi-tenant SaaS."""
from __future__ import annotations

import re
from typing import Optional

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from sqlalchemy import or_  # type: ignore
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import Organization, User, UserRole
from ..utils.auth import clear_session, normalize_email, start_session
from ..utils.files import save_logo_file

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _slugify(value: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return base or "org"


def _unique_org_slug(name: str) -> str:
    base = _slugify(name)
    slug = base
    counter = 1
    while Organization.query.filter_by(slug=slug).first():
        counter += 1
        slug = f"{base}-{counter}"
    return slug


def _sanitize_brand_color(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if not re.match(r"^#(?:[0-9a-fA-F]{6})$", cleaned):
        return None
    return cleaned.lower()


def _find_org(identifier: str) -> Optional[Organization]:
    normalized = identifier.strip().lower()
    return (
        Organization.query.filter(Organization.is_active.is_(True))
        .filter(or_(Organization.slug == normalized, Organization.contact_email == normalized))
        .first()
    )


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html", form={})

    org_name = request.form.get("organization_name", "").strip()
    org_email = normalize_email(request.form.get("organization_email", ""))
    admin_name = request.form.get("admin_name", "").strip()
    admin_email = normalize_email(request.form.get("admin_email", ""))
    password = request.form.get("password", "")
    tagline = request.form.get("tagline", "").strip() or None
    description = request.form.get("description", "").strip() or None
    brand_color = _sanitize_brand_color(request.form.get("brand_color")) or "#2563eb"
    logo_url_input = request.form.get("logo_url", "").strip()
    logo_file = request.files.get("logo_file")
    org_slug = _unique_org_slug(org_name) if org_name else "org"

    errors = []
    if not org_name:
        errors.append("Organization name is required.")
    if not org_email:
        errors.append("Organization email is required.")
    if not admin_name:
        errors.append("Admin name is required.")
    if not admin_email:
        errors.append("Admin email is required.")
    if not password or len(password) < 12:
        errors.append("Password must be at least 12 characters for security.")
    if request.form.get("brand_color") and not _sanitize_brand_color(request.form.get("brand_color")):
        errors.append("Brand color must be a valid 6-digit hex color (e.g., #2563eb).")

    logo_value: str | None = None
    if logo_file and logo_file.filename:
        stored_name, upload_error = save_logo_file(
            logo_file,
            org_slug,
            current_app.config.get("UPLOAD_FOLDER"),
            current_app.config.get("ALLOWED_LOGO_EXTENSIONS", []),
        )
        if upload_error:
            errors.append(upload_error)
        else:
            logo_value = stored_name
    elif logo_url_input:
        if not re.match(r"^https?://", logo_url_input):
            errors.append("Logo URL must start with http or https.")
        else:
            logo_value = logo_url_input

    if Organization.query.filter(or_(Organization.name == org_name, Organization.contact_email == org_email)).first():
        errors.append("An organization with this name or email already exists.")

    if errors:
        for message in errors:
            flash(message, "danger")
        return render_template(
            "auth/register.html",
            form={
                "organization_name": org_name,
                "organization_email": org_email,
                "admin_name": admin_name,
                "admin_email": admin_email,
                "tagline": tagline or "",
                "description": description or "",
                "brand_color": request.form.get("brand_color", ""),
                "logo_url": logo_url_input,
            },
        )

    try:
        organization = Organization(
            name=org_name,
            contact_email=org_email,
            slug=org_slug,
            logo_url=logo_value,
            brand_color=brand_color,
            tagline=tagline,
            description=description,
        )
        admin_user = User(
            email=admin_email,
            full_name=admin_name,
            role=UserRole.ADMIN,
            organization=organization,
        )
        admin_user.set_password(password)

        db.session.add(organization)
        db.session.add(admin_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Registration failed due to a unique constraint. Please adjust details and retry.", "danger")
        return render_template(
            "auth/register.html",
            form={
                "organization_name": org_name,
                "organization_email": org_email,
                "admin_name": admin_name,
                "admin_email": admin_email,
                "tagline": tagline or "",
                "description": description or "",
                "brand_color": request.form.get("brand_color", ""),
                "logo_url": logo_url_input,
            },
        )

    start_session(admin_user)
    flash("Organization created successfully. Welcome to your new workspace.", "success")
    return redirect(url_for("main.onboarding"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth/login.html", org_hint=request.args.get("org", ""))

    org_identifier = request.form.get("organization", "").strip()
    email = normalize_email(request.form.get("email", ""))
    password = request.form.get("password", "")

    if not org_identifier or not email or not password:
        flash("All fields are required to sign in.", "danger")
        return render_template("auth/login.html", org_hint=org_identifier, email=email)

    organization = _find_org(org_identifier)
    if not organization:
        flash("Invalid credentials. Please verify your organization and try again.", "danger")
        return render_template("auth/login.html", org_hint=org_identifier, email=email)

    user = User.query.filter_by(organization_id=organization.id, email=email, is_active=True).first()
    if not user or not user.check_password(password):
        flash("Invalid credentials. Please verify your details and try again.", "danger")
        return render_template("auth/login.html", org_hint=org_identifier, email=email)

    user.mark_login()
    db.session.commit()
    start_session(user)
    flash(f"Welcome back, {user.full_name.split(' ')[0]}!", "success")

    next_url = request.args.get("next")
    return redirect(next_url or url_for("main.dashboard"))


@auth_bp.route("/logout")
def logout():
    clear_session()
    flash("You have been signed out securely.", "info")
    return redirect(url_for("auth.login"))
