"""Public-facing routes and authenticated dashboard plus onboarding flows."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, send_from_directory, url_for
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import Organization, User, UserRole
from ..utils.auth import generate_secure_password, login_required, normalize_email, org_required, role_required
from ..utils.files import save_logo_file

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def home():
    return render_template("home.html")


@main_bp.route("/health")
def health_check():
    return {"status": "ok"}


@main_bp.route("/dashboard")
@login_required
@org_required
def dashboard():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    users_q = User.scoped_to_org(org.id)
    total_users = users_q.count()
    active_users = users_q.filter_by(is_active=True).count()
    inactive_users = max(total_users - active_users, 0)
    admin_users = users_q.filter_by(role=UserRole.ADMIN).count()

    last_login_user = (
        users_q.filter(User.last_login_at.isnot(None))
        .order_by(User.last_login_at.desc())
        .first()
    )
    org_age_days = (datetime.utcnow() - org.created_at).days if org.created_at else 0

    last_login_display = None
    if last_login_user and last_login_user.last_login_at:
        last_login_display = last_login_user.last_login_at.strftime("%b %d, %Y %H:%M UTC")

    growth_rows = (
        db.session.query(func.strftime("%Y-%m", User.created_at).label("month"), func.count(User.id))
        .filter(User.organization_id == org.id)
        .group_by("month")
        .order_by("month")
        .all()
    )
    user_growth = [
        {
            "label": _format_month_label(month_value),
            "value": count,
        }
        for month_value, count in growth_rows
    ]

    role_rows = (
        db.session.query(User.role, func.count(User.id))
        .filter(User.organization_id == org.id)
        .group_by(User.role)
        .all()
    )
    role_distribution = [
        {"role": role.value, "count": count}
        for role, count in role_rows
    ]

    login_cutoff = datetime.utcnow() - timedelta(days=30)
    login_rows = (
        db.session.query(func.strftime("%Y-%m-%d", User.last_login_at).label("login_date"), func.count(User.id))
        .filter(
            User.organization_id == org.id,
            User.last_login_at.isnot(None),
            User.last_login_at >= login_cutoff,
        )
        .group_by("login_date")
        .order_by("login_date")
        .all()
    )
    login_activity = [
        {
            "label": _format_date_label(date_value),
            "value": count,
        }
        for date_value, count in login_rows
    ]

    dashboard_data = {
        "stats": {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "admin_users": admin_users,
            "org_age_days": org_age_days,
            "last_login_user": last_login_user.full_name if last_login_user else None,
            "last_login_at": last_login_user.last_login_at.isoformat() if last_login_user else None,
            "last_login_display": last_login_display,
        },
        "charts": {
            "user_growth": user_growth,
            "role_distribution": role_distribution,
            "login_activity": login_activity,
        },
        "org": {
            "name": org.name,
            "slug": org.slug,
            "brand_color": org.brand_color or "#2563eb",
        },
        "current_user": {
            "name": user.full_name,
            "role": user.role.value,
        },
    }

    return render_template("dashboard.html", dashboard_data=dashboard_data)


def _format_month_label(month_value: str) -> str:
    """Convert YYYY-MM to a friendly label like `Jan 2024`."""
    try:
        month_dt = datetime.strptime(month_value, "%Y-%m")
        return month_dt.strftime("%b %Y")
    except (TypeError, ValueError):
        return month_value


def _format_date_label(date_value: str) -> str:
    """Convert YYYY-MM-DD to a friendly label for charts."""
    try:
        date_dt = datetime.strptime(date_value, "%Y-%m-%d")
        return date_dt.strftime("%b %d")
    except (TypeError, ValueError):
        return date_value


def _active_admin_count(org_id: int, exclude_user_id: int | None = None) -> int:
    query = User.query.filter_by(organization_id=org_id, role=UserRole.ADMIN, is_active=True)
    if exclude_user_id:
        query = query.filter(User.id != exclude_user_id)
    return query.count()


@main_bp.route("/onboarding")
@login_required
@org_required
def onboarding():
    return render_template("onboarding.html")


@main_bp.route("/team", methods=["GET"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def team_management():
    org = g.current_org
    assert org is not None
    users = User.scoped_to_org(org.id).order_by(User.created_at.desc()).all()
    return render_template("team.html", users=users, bulk_result=None, UserRole=UserRole)


def _validate_role(raw_role: str) -> Tuple[bool, UserRole | None, str | None]:
    role_normalized = (raw_role or "").strip().lower()
    if role_normalized in {"admin", "administrator"}:
        return True, UserRole.ADMIN, None
    if role_normalized in {"user", "standard", "standard user"}:
        return True, UserRole.STANDARD, None
    return False, None, "Role must be Admin or User"


@main_bp.route("/team/invite", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def invite_user():
    org = g.current_org
    assert org is not None

    full_name = (request.form.get("full_name") or "").strip()
    email = normalize_email(request.form.get("email") or "")
    raw_role = request.form.get("role") or ""
    password = request.form.get("password", "").strip()

    errors: List[str] = []
    if not full_name:
        errors.append("Full name is required.")
    if not email:
        errors.append("Email is required.")
    is_valid_role, role_enum, role_error = _validate_role(raw_role)
    if not is_valid_role or not role_enum:
        errors.append(role_error or "Invalid role selected.")
    if password and len(password) < 12:
        errors.append("Temporary password must be at least 12 characters.")

    existing = User.query.filter_by(organization_id=org.id, email=email).first()
    if existing:
        errors.append("A user with this email already exists in your organization.")

    if errors:
        for message in errors:
            flash(message, "danger")
        return redirect(url_for("main.team_management"))

    temporary_password = password if password else generate_secure_password()

    try:
        user = User(
            organization_id=org.id,
            full_name=full_name,
            email=email,
            role=role_enum,
            is_active=True,
        )
        user.set_password(temporary_password)
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Could not create user due to a database constraint. Please adjust and retry.", "danger")
        return redirect(url_for("main.team_management"))

    flash(
        f"User {full_name} created. Temporary password: {temporary_password}. Share securely and ask them to rotate on first login.",
        "success",
    )
    return redirect(url_for("main.team_management"))


def _validate_csv_headers(fieldnames: List[str]) -> bool:
    expected = ["full_name", "email", "role"]
    if not fieldnames:
        return False
    normalized = [name.strip().lower() for name in fieldnames]
    return normalized == expected


def _parse_csv(file_bytes: bytes) -> Tuple[List[Dict[str, str]], List[str]]:
    errors: List[str] = []
    rows: List[Dict[str, str]] = []
    try:
        text_stream = io.StringIO(file_bytes.decode("utf-8-sig"))
    except UnicodeDecodeError:
        return [], ["CSV must be UTF-8 encoded."]

    reader = csv.DictReader(text_stream)
    if not _validate_csv_headers(reader.fieldnames or []):
        return [], ["CSV headers must be: full_name,email,role"]

    for idx, row in enumerate(reader, start=2):  # data starts on line 2
        rows.append({"row": idx, **{k: (row.get(k, "") or "").strip() for k in reader.fieldnames or []}})
    return rows, errors


@main_bp.route("/team/bulk", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def bulk_upload_users():
    org = g.current_org
    assert org is not None

    file = request.files.get("csv_file")
    if not file or not file.filename:
        flash("Please select a CSV file to upload.", "danger")
        return redirect(url_for("main.team_management"))

    if not file.filename.lower().endswith(".csv"):
        flash("Only .csv files are accepted for bulk upload.", "danger")
        return redirect(url_for("main.team_management"))

    file_bytes = file.read()
    if not file_bytes:
        flash("Uploaded file is empty.", "danger")
        return redirect(url_for("main.team_management"))
    if len(file_bytes) > 1_000_000:
        flash("CSV file is too large. Limit to 1MB.", "danger")
        return redirect(url_for("main.team_management"))

    rows, parse_errors = _parse_csv(file_bytes)
    if parse_errors:
        for message in parse_errors:
            flash(message, "danger")
        return redirect(url_for("main.team_management"))

    created: List[Dict[str, str]] = []
    errors: List[str] = []
    seen_emails: set[str] = set()

    for row in rows:
        row_number = row["row"]
        full_name = row.get("full_name", "").strip()
        email = normalize_email(row.get("email", ""))
        raw_role = row.get("role", "")

        if not full_name or not email or not raw_role:
            errors.append(f"Row {row_number}: Missing required values.")
            continue

        valid_role, role_enum, role_error = _validate_role(raw_role)
        if not valid_role or not role_enum:
            errors.append(f"Row {row_number}: {role_error or 'Invalid role'}.")
            continue

        if email in seen_emails:
            errors.append(f"Row {row_number}: Duplicate email within upload.")
            continue

        if User.query.filter_by(organization_id=org.id, email=email).first():
            errors.append(f"Row {row_number}: Email already exists in this organization.")
            continue

        temporary_password = generate_secure_password()
        user = User(
            organization_id=org.id,
            full_name=full_name,
            email=email,
            role=role_enum,
            is_active=True,
        )
        user.set_password(temporary_password)
        db.session.add(user)
        created.append({
            "full_name": full_name,
            "email": email,
            "role": "Admin" if role_enum == UserRole.ADMIN else "User",
            "password": temporary_password,
        })
        seen_emails.add(email)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Bulk upload failed due to a database constraint. No users were created.", "danger")
        return redirect(url_for("main.team_management"))

    bulk_result = {
        "created_count": len(created),
        "error_count": len(errors),
        "errors": errors,
        "created": created,
    }

    if bulk_result["created_count"]:
        flash(f"{bulk_result['created_count']} users created successfully.", "success")
    if errors:
        flash(f"{len(errors)} rows skipped due to validation errors.", "warning")

    users = User.scoped_to_org(org.id).order_by(User.created_at.desc()).all()
    return render_template("team.html", users=users, bulk_result=bulk_result, UserRole=UserRole)


@main_bp.route("/team/<int:user_id>/update", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def update_user(user_id: int):
    org = g.current_org
    assert org is not None

    user = User.query.filter_by(id=user_id, organization_id=org.id).first_or_404()

    full_name = (request.form.get("full_name") or "").strip()
    raw_role = request.form.get("role") or user.role.value
    status_value = request.form.get("status", "active")

    errors: List[str] = []
    if not full_name:
        errors.append("Full name is required.")

    is_valid_role, role_enum, role_error = _validate_role(raw_role)
    if not is_valid_role or not role_enum:
        errors.append(role_error or "Invalid role.")

    is_active = status_value == "active"

    if user.role == UserRole.ADMIN and (role_enum != UserRole.ADMIN or not is_active):
        if _active_admin_count(org.id, exclude_user_id=user.id) == 0:
            errors.append("You must keep at least one active admin in the organization.")

    if errors:
        for message in errors:
            flash(message, "danger")
        return redirect(url_for("main.team_management"))

    user.full_name = full_name
    user.role = role_enum if role_enum else user.role
    user.is_active = is_active

    db.session.commit()
    flash("User updated successfully.", "success")
    return redirect(url_for("main.team_management"))


@main_bp.route("/organization/profile", methods=["GET", "POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def organization_profile():
    org = g.current_org
    assert org is not None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        contact_email = request.form.get("contact_email", "").strip().lower()
        tagline = request.form.get("tagline", "").strip() or None
        description = request.form.get("description", "").strip() or None
        brand_color_input = request.form.get("brand_color", "").strip()
        logo_url_input = request.form.get("logo_url", "").strip()
        logo_file = request.files.get("logo_file")

        errors = []
        if not name:
            errors.append("Organization name is required.")
        if not contact_email:
            errors.append("Organization email is required.")

        if brand_color_input:
            from ..routes.auth import _sanitize_brand_color  # lazy import to avoid cycles

            if not _sanitize_brand_color(brand_color_input):
                errors.append("Brand color must be a valid 6-digit hex color (e.g., #2563eb).")

        existing_conflict = (
            Organization.query.filter(Organization.id != org.id)
            .filter((Organization.name == name) | (Organization.contact_email == contact_email))
            .first()
        )
        if existing_conflict:
            errors.append("Another organization already uses this name or email.")

        logo_value = org.logo_url
        if logo_file and logo_file.filename:
            stored_name, upload_error = save_logo_file(
                logo_file,
                org.slug,
                current_app.config.get("UPLOAD_FOLDER"),
                current_app.config.get("ALLOWED_LOGO_EXTENSIONS", []),
            )
            if upload_error:
                errors.append(upload_error)
            else:
                logo_value = stored_name
        elif logo_url_input:
            if not logo_url_input.startswith("http://") and not logo_url_input.startswith("https://"):
                errors.append("Logo URL must start with http or https.")
            else:
                logo_value = logo_url_input

        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("organization_profile.html", org=org)

        org.name = name
        org.contact_email = contact_email
        org.tagline = tagline
        org.description = description
        org.brand_color = brand_color_input or org.brand_color or "#2563eb"
        org.logo_url = logo_value

        db.session.commit()
        flash("Organization profile updated successfully.", "success")
        return redirect(url_for("main.organization_profile"))

    return render_template("organization_profile.html", org=org)


@main_bp.route("/assets/logos/<slug>/<filename>")
@login_required
@org_required
def logo_file(slug: str, filename: str):
    org = g.current_org
    if not org or org.slug != slug:
        abort(403)
    upload_folder = Path(current_app.config.get("UPLOAD_FOLDER")) / slug
    file_path = upload_folder / filename
    if not file_path.is_file():
        abort(404)
    return send_from_directory(upload_folder, filename)
