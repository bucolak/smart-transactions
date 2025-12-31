"""Public-facing routes and authenticated dashboard plus onboarding flows."""
from __future__ import annotations

import csv
import io
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, send_from_directory, url_for
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import (
    AIInteractionLog,
    AIStatus,
    Invoice,
    InvoiceStatus,
    Organization,
    Project,
    ProjectStatus,
    Task,
    TaskPriority,
    TaskStatus,
    User,
    UserRole,
)
from ..services.ai_service import ai_service
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

    payload = _dashboard_payload(org, user)
    return render_template(
        "dashboard.html",
        dashboard_data=payload["dashboard_data"],
        ai_dashboard_insight=None,
        ai_dashboard_error=False,
    )


@main_bp.route("/dashboard/ai-insight", methods=["POST"])
@login_required
@org_required
def dashboard_ai_insight():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    payload = _dashboard_payload(org, user)
    ai_context = payload.get("ai_context", {})
    totals = ai_context.get("totals", {})
    prompt = (
        "You are an enterprise SaaS advisor. Use the provided tenant metrics to craft a concise "
        "three-bullet AI insight covering productivity, risk, and suggested admin follow-up."
        f" Organization: {org.name} (slug {org.slug}). "
        f"Users: {totals.get('users', 0)} total, {totals.get('active_users', 0)} active, {totals.get('admins', 0)} admins. "
        f"Projects: {totals.get('projects', 0)}, open tasks: {totals.get('open_tasks', 0)}. "
        f"Overdue invoices: {totals.get('overdue_invoices', 0)}."
    )

    result = ai_service.generate_content(
        operation_name="Dashboard AI insight",
        organization_id=org.id,
        user_id=user.id,
        contents=prompt,
        context={"location": "dashboard", "totals": totals},
    )

    return render_template(
        "dashboard.html",
        dashboard_data=payload["dashboard_data"],
        ai_dashboard_insight=result.get("text"),
        ai_dashboard_error=result.get("error", False),
    )


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


def _parse_date(raw_value: str | None) -> Optional[date]:
    """Safely parse a date string in YYYY-MM-DD format."""
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value.strip(), "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def _active_admin_count(org_id: int, exclude_user_id: int | None = None) -> int:
    query = User.query.filter_by(organization_id=org_id, role=UserRole.ADMIN, is_active=True)
    if exclude_user_id:
        query = query.filter(User.id != exclude_user_id)
    return query.count()


def _dashboard_payload(org: Organization, user: User) -> Dict[str, Any]:
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

    project_count = Project.scoped_to_org(org.id).count()
    open_tasks = Task.scoped_to_org(org.id).filter(Task.status != TaskStatus.COMPLETED).count()
    overdue_invoices = Invoice.scoped_to_org(org.id).filter(Invoice.status == InvoiceStatus.OVERDUE).count()

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

    ai_context = {
        "totals": {
            "users": total_users,
            "active_users": active_users,
            "admins": admin_users,
            "projects": project_count,
            "open_tasks": open_tasks,
            "overdue_invoices": overdue_invoices,
        },
        "org": {"name": org.name, "slug": org.slug},
        "activity_window_days": 30,
    }

    return {"dashboard_data": dashboard_data, "ai_context": ai_context}


def _projects_payload(org: Organization, user: User) -> Dict[str, Any]:
    projects = (
        Project.scoped_to_org(org.id)
        .order_by(Project.created_at.desc())
        .all()
    )
    tasks_query = Task.scoped_to_org(org.id).order_by(Task.due_date.is_(None), Task.due_date, Task.created_at.desc())
    all_tasks = tasks_query.all()
    tasks = (
        all_tasks
        if user.role == UserRole.ADMIN
        else [t for t in all_tasks if t.assignee_id == user.id or t.created_by_id == user.id]
    )

    task_summary = {
        status.value: len([t for t in all_tasks if t.status == status])
        for status in TaskStatus
    }
    priority_summary = {
        priority.value: len([t for t in all_tasks if t.priority == priority])
        for priority in TaskPriority
    }
    overdue_tasks = [t for t in all_tasks if t.due_date and t.due_date < date.today() and t.status != TaskStatus.COMPLETED]
    project_progress = []
    for project in projects:
        total = len(project.tasks)
        completed = len([t for t in project.tasks if t.status == TaskStatus.COMPLETED])
        project_progress.append({
            "id": project.id,
            "name": project.name,
            "completed": completed,
            "total": total,
        })

    return {
        "projects": projects,
        "tasks": tasks,
        "task_summary": task_summary,
        "priority_summary": priority_summary,
        "overdue_tasks": overdue_tasks,
        "project_progress": project_progress,
        "is_admin": user.role == UserRole.ADMIN,
        "teammates": User.scoped_to_org(org.id).order_by(User.full_name.asc()).all(),
    }


def _finance_payload(org: Organization, user: User) -> Dict[str, Any]:
    invoices = (
        Invoice.scoped_to_org(org.id)
        .order_by(Invoice.due_date.is_(None), Invoice.due_date, Invoice.created_at.desc())
        .all()
    )

    status_totals = {status.value: 0 for status in InvoiceStatus}
    for invoice in invoices:
        status_totals[invoice.status.value] += float(invoice.amount or 0)

    monthly_rows = (
        db.session.query(func.strftime("%Y-%m", Invoice.issue_date).label("month"), func.sum(Invoice.amount))
        .filter(Invoice.organization_id == org.id)
        .group_by("month")
        .order_by("month")
        .all()
    )
    monthly_totals = [
        {"label": _format_month_label(month or ""), "value": float(total or 0)}
        for month, total in monthly_rows
    ]

    return {
        "invoices": invoices,
        "status_totals": status_totals,
        "monthly_totals": monthly_totals,
        "can_edit": user.role == UserRole.ADMIN,
    }


def _ai_operations_payload(org: Organization) -> Dict[str, Any]:
    logs = AIInteractionLog.scoped_to_org(org.id).order_by(AIInteractionLog.created_at.desc()).all()

    usage_rows = (
        db.session.query(func.strftime("%Y-%m-%d", AIInteractionLog.created_at).label("day"), func.count(AIInteractionLog.id))
        .filter(AIInteractionLog.organization_id == org.id)
        .group_by("day")
        .order_by("day")
        .all()
    )
    usage_trend = [{"label": _format_date_label(day or ""), "value": count} for day, count in usage_rows]

    top_ops = (
        db.session.query(AIInteractionLog.operation_name, func.count(AIInteractionLog.id))
        .filter(AIInteractionLog.organization_id == org.id)
        .group_by(AIInteractionLog.operation_name)
        .order_by(func.count(AIInteractionLog.id).desc())
        .limit(5)
        .all()
    )
    op_breakdown = [{"operation": name, "count": count} for name, count in top_ops]

    teammates = User.scoped_to_org(org.id).order_by(User.full_name.asc()).all()

    return {
        "logs": logs,
        "usage_trend": usage_trend,
        "op_breakdown": op_breakdown,
        "teammates": teammates,
    }


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


def _project_for_org(project_id: int, org_id: int) -> Project:
    return Project.query.filter_by(id=project_id, organization_id=org_id).first_or_404()


def _task_for_org(task_id: int, org_id: int) -> Task:
    return Task.query.filter_by(id=task_id, organization_id=org_id).first_or_404()


def _resolve_project_status(raw_status: str | None) -> ProjectStatus:
    try:
        return ProjectStatus((raw_status or "").strip())
    except ValueError:
        return ProjectStatus.ACTIVE


def _resolve_task_status(raw_status: str | None) -> TaskStatus:
    try:
        return TaskStatus((raw_status or "").strip())
    except ValueError:
        return TaskStatus.TODO


def _resolve_task_priority(raw_priority: str | None) -> TaskPriority:
    try:
        return TaskPriority((raw_priority or "").strip())
    except ValueError:
        return TaskPriority.MEDIUM


@main_bp.route("/projects", methods=["GET"])
@login_required
@org_required
def projects():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    payload = _projects_payload(org, user)
    return render_template(
        "projects.html",
        **payload,
        TaskStatus=TaskStatus,
        TaskPriority=TaskPriority,
        ProjectStatus=ProjectStatus,
        ai_task_insight=None,
        ai_task_summary=None,
        ai_task_ideas=None,
        ai_error=None,
    )


@main_bp.route("/projects/ai", methods=["POST"])
@login_required
@org_required
def project_ai_actions():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    payload = _projects_payload(org, user)
    mode = (request.form.get("mode") or "insight").strip().lower()
    project_id_value = request.form.get("project_id")
    selected_project = None
    try:
        if project_id_value:
            selected_project = next((p for p in payload["projects"] if p.id == int(project_id_value)), None)
    except ValueError:
        selected_project = None
    if not selected_project and payload.get("projects"):
        selected_project = payload["projects"][0]

    visible_tasks = payload.get("tasks", [])
    project_tasks = [t for t in visible_tasks if selected_project and t.project_id == selected_project.id]
    task_lines = [
        f"- {t.title} | status={t.status.value} | priority={t.priority.value} | due={t.due_date}"
        for t in project_tasks
    ]

    if mode == "ideas":
        description_input = (request.form.get("idea_description") or "").strip()
        idea_basis = description_input or (selected_project.description or selected_project.name if selected_project else "")
        prompt = (
            "You are a senior delivery lead. Create 5-7 actionable tasks for the project."
            " Include short titles and crisp descriptions. Keep them tenant-safe and practical."
            f" Project: {selected_project.name if selected_project else 'General'}."
            f" Brief: {idea_basis}."
        )
        result_key = "ai_task_ideas"
        operation = "Project task creation helper"
    elif mode == "summary":
        prompt = (
            "You are a program manager. Summarize project progress and bottlenecks in 4 bullets:"
            " momentum, risks, dependencies, and next 48-hour actions."
            f" Project: {selected_project.name if selected_project else 'Portfolio'}."
            f" Description: {selected_project.description if selected_project else 'N/A'}."
            f" Tasks:\n{chr(10).join(task_lines) if task_lines else 'No tasks yet'}"
        )
        result_key = "ai_task_summary"
        operation = "Project task summarization"
    else:
        prompt = (
            "You are a project AI co-pilot. Provide task prioritization and risk alerts."
            " Return 3 sections: Prioritized Next Actions, Risk Alerts (with overdue/blocked),"
            " and Quick Wins. Be concise and specific."
            f" Project: {selected_project.name if selected_project else 'Workspace'}."
            f" Description: {selected_project.description if selected_project else 'N/A'}."
            f" Tasks:\n{chr(10).join(task_lines) if task_lines else 'No tasks yet'}"
        )
        result_key = "ai_task_insight"
        operation = "Project task insight"

    result = ai_service.generate_content(
        operation_name=operation,
        organization_id=org.id,
        user_id=user.id,
        contents=prompt,
        context={
            "mode": mode,
            "project": selected_project.name if selected_project else None,
            "task_count": len(project_tasks),
        },
    )

    payload[result_key] = result.get("text")
    payload["ai_error"] = result.get("error")

    return render_template(
        "projects.html",
        **payload,
        TaskStatus=TaskStatus,
        TaskPriority=TaskPriority,
        ProjectStatus=ProjectStatus,
    )


@main_bp.route("/projects/create", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def create_project():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    due_date = _parse_date(request.form.get("due_date"))
    status = _resolve_project_status(request.form.get("status"))

    if not name:
        flash("Project name is required.", "danger")
        return redirect(url_for("main.projects"))

    project = Project(
        organization_id=org.id,
        name=name,
        description=description,
        status=status,
        due_date=due_date,
        created_by_id=user.id,
    )
    db.session.add(project)
    db.session.commit()
    flash("Project created successfully.", "success")
    return redirect(url_for("main.projects"))


@main_bp.route("/projects/<int:project_id>/update", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def update_project(project_id: int):
    org = g.current_org
    assert org is not None
    selected_project_id = project_id
    form_project_id = request.form.get("project_id")
    if form_project_id:
        try:
            selected_project_id = int(form_project_id)
        except ValueError:
            selected_project_id = project_id

    project = _project_for_org(selected_project_id, org.id)

    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    due_date = _parse_date(request.form.get("due_date"))
    status = _resolve_project_status(request.form.get("status"))

    if not name:
        flash("Project name is required.", "danger")
        return redirect(url_for("main.projects"))

    project.name = name
    project.description = description
    project.due_date = due_date
    project.status = status
    db.session.commit()
    flash("Project updated.", "success")
    return redirect(url_for("main.projects"))


@main_bp.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def delete_project(project_id: int):
    org = g.current_org
    assert org is not None
    project = _project_for_org(project_id, org.id)
    db.session.delete(project)
    db.session.commit()
    flash("Project and its tasks deleted.", "warning")
    return redirect(url_for("main.projects"))


@main_bp.route("/projects/<int:project_id>/tasks/create", methods=["POST"])
@login_required
@org_required
def create_task(project_id: int):
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    project = _project_for_org(project_id, org.id)

    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip() or None
    status = _resolve_task_status(request.form.get("status"))
    priority = _resolve_task_priority(request.form.get("priority"))
    due_date = _parse_date(request.form.get("due_date"))
    assignee_id = request.form.get("assignee_id")
    assignee = None
    if assignee_id:
        try:
            assignee = User.query.filter_by(id=int(assignee_id), organization_id=org.id).first()
        except ValueError:
            assignee = None

    if not title:
        flash("Task title is required.", "danger")
        return redirect(url_for("main.projects"))

    if user.role != UserRole.ADMIN:
        assignee = assignee or user
        if assignee.id != user.id:  # type: ignore[union-attr]
            assignee = user

    task = Task(
        organization_id=org.id,
        project_id=project.id,
        title=title,
        description=description,
        status=status,
        priority=priority,
        due_date=due_date,
        assignee_id=assignee.id if assignee else None,
        created_by_id=user.id,
    )
    if status == TaskStatus.COMPLETED:
        task.completed_at = datetime.utcnow()

    db.session.add(task)
    db.session.commit()
    flash("Task created.", "success")
    return redirect(url_for("main.projects"))


@main_bp.route("/tasks/<int:task_id>/update", methods=["POST"])
@login_required
@org_required
def update_task(task_id: int):
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None
    task = _task_for_org(task_id, org.id)

    is_admin = user.role == UserRole.ADMIN
    if not is_admin and task.assignee_id not in {user.id, None} and task.created_by_id != user.id:
        abort(403)

    title = (request.form.get("title") or task.title).strip()
    description = (request.form.get("description") or task.description or "").strip() or None
    status = _resolve_task_status(request.form.get("status"))
    priority = _resolve_task_priority(request.form.get("priority"))
    raw_due = request.form.get("due_date")
    due_date = _parse_date(raw_due)

    assignee = task.assignee
    if is_admin:
        assignee_id = request.form.get("assignee_id")
        if assignee_id:
            try:
                assignee = User.query.filter_by(id=int(assignee_id), organization_id=org.id).first()
            except ValueError:
                assignee = None

    if not title:
        flash("Task title is required.", "danger")
        return redirect(url_for("main.projects"))

    task.title = title
    task.description = description
    task.status = status
    task.priority = priority
    task.due_date = due_date
    task.assignee_id = assignee.id if assignee else None
    if status == TaskStatus.COMPLETED:
        task.completed_at = datetime.utcnow()
    else:
        task.completed_at = None

    db.session.commit()
    flash("Task updated.", "success")
    return redirect(url_for("main.projects"))


@main_bp.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
@org_required
def delete_task(task_id: int):
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None
    task = _task_for_org(task_id, org.id)

    is_admin = user.role == UserRole.ADMIN
    if not is_admin and task.created_by_id != user.id:
        abort(403)

    db.session.delete(task)
    db.session.commit()
    flash("Task deleted.", "warning")
    return redirect(url_for("main.projects"))


@main_bp.route("/finance", methods=["GET"])
@login_required
@org_required
def finance():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    payload = _finance_payload(org, user)
    return render_template(
        "finance.html",
        **payload,
        InvoiceStatus=InvoiceStatus,
        ai_finance_insight=None,
        ai_finance_error=None,
    )


@main_bp.route("/finance/ai", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def finance_ai_insight():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    payload = _finance_payload(org, user)
    invoices = payload.get("invoices", [])
    overdue = [inv for inv in invoices if inv.status == InvoiceStatus.OVERDUE]
    pending = [inv for inv in invoices if inv.status == InvoiceStatus.PENDING]

    prompt = (
        "You are a finance analyst. Provide a succinct billing health summary with:"
        " (1) overall cash position, (2) overdue risk, (3) predictive-style guidance based on observed patterns,"
        " and (4) two recommended actions. Avoid generic fluff."
        f" Organization: {org.name}."
        f" Totals: pending ${payload['status_totals'].get('pending', 0):.2f}, paid ${payload['status_totals'].get('paid', 0):.2f}, overdue ${payload['status_totals'].get('overdue', 0):.2f}."
        f" Overdue count: {len(overdue)}. Pending count: {len(pending)}."
    )

    result = ai_service.generate_content(
        operation_name="Finance AI insight",
        organization_id=org.id,
        user_id=user.id,
        contents=prompt,
        context={
            "overdue": [inv.id for inv in overdue],
            "pending": [inv.id for inv in pending],
            "status_totals": payload.get("status_totals"),
        },
    )

    payload["ai_finance_insight"] = result.get("text")
    payload["ai_finance_error"] = result.get("error")

    return render_template(
        "finance.html",
        **payload,
        InvoiceStatus=InvoiceStatus,
    )


@main_bp.route("/finance/create", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def create_invoice():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    title = (request.form.get("title") or "").strip()
    amount_raw = (request.form.get("amount") or "0").replace(",", "")
    description = (request.form.get("description") or "").strip() or None
    currency = (request.form.get("currency") or "USD").upper()[:8]
    status = request.form.get("status") or InvoiceStatus.PENDING.value
    issue_date = _parse_date(request.form.get("issue_date"))
    due_date = _parse_date(request.form.get("due_date"))

    if not title:
        flash("Title is required for invoices.", "danger")
        return redirect(url_for("main.finance"))

    try:
        amount_value = round(float(amount_raw), 2)
    except ValueError:
        flash("Amount must be numeric.", "danger")
        return redirect(url_for("main.finance"))

    try:
        status_enum = InvoiceStatus(status)
    except ValueError:
        status_enum = InvoiceStatus.PENDING

    invoice = Invoice(
        organization_id=org.id,
        title=title,
        amount=amount_value,
        currency=currency,
        description=description,
        status=status_enum,
        issue_date=issue_date,
        due_date=due_date,
        created_by_id=user.id,
    )
    if status_enum == InvoiceStatus.PAID:
        invoice.mark_paid()

    db.session.add(invoice)
    db.session.commit()
    flash("Invoice created.", "success")
    return redirect(url_for("main.finance"))


@main_bp.route("/finance/<int:invoice_id>/update", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def update_invoice(invoice_id: int):
    org = g.current_org
    assert org is not None
    invoice = Invoice.query.filter_by(id=invoice_id, organization_id=org.id).first_or_404()

    title = (request.form.get("title") or invoice.title).strip()
    description = (request.form.get("description") or invoice.description or "").strip() or None
    currency = (request.form.get("currency") or invoice.currency).upper()[:8]
    status_value = request.form.get("status") or invoice.status.value
    raw_issue = request.form.get("issue_date")
    raw_due = request.form.get("due_date")
    issue_date = _parse_date(raw_issue)
    due_date = _parse_date(raw_due)

    try:
        status_enum = InvoiceStatus(status_value)
    except ValueError:
        status_enum = invoice.status

    try:
        amount_raw = (request.form.get("amount") or invoice.amount or 0)
        amount_value = round(float(amount_raw), 2)
    except ValueError:
        flash("Amount must be numeric.", "danger")
        return redirect(url_for("main.finance"))

    invoice.title = title
    invoice.description = description
    invoice.currency = currency
    invoice.status = status_enum
    invoice.amount = amount_value
    invoice.issue_date = issue_date
    invoice.due_date = due_date
    if status_enum == InvoiceStatus.PAID:
        invoice.mark_paid()
    elif status_enum != InvoiceStatus.PAID:
        invoice.paid_at = None

    db.session.commit()
    flash("Invoice updated.", "success")
    return redirect(url_for("main.finance"))


@main_bp.route("/finance/<int:invoice_id>/delete", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def delete_invoice(invoice_id: int):
    org = g.current_org
    assert org is not None
    invoice = Invoice.query.filter_by(id=invoice_id, organization_id=org.id).first_or_404()
    db.session.delete(invoice)
    db.session.commit()
    flash("Invoice deleted.", "warning")
    return redirect(url_for("main.finance"))


@main_bp.route("/ai/operations", methods=["GET"])
@login_required
@org_required
def ai_operations():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    status_param = request.args.get("status")
    user_param = request.args.get("user_id")
    start_param = _parse_date(request.args.get("start"))
    end_param = _parse_date(request.args.get("end"))

    query = AIInteractionLog.scoped_to_org(org.id)
    if status_param:
        try:
            status_enum = AIStatus(status_param)
            query = query.filter(AIInteractionLog.status == status_enum)
        except ValueError:
            pass
    if user_param:
        try:
            query = query.filter(AIInteractionLog.triggered_by_id == int(user_param))
        except ValueError:
            pass
    if start_param:
        query = query.filter(AIInteractionLog.created_at >= datetime.combine(start_param, datetime.min.time()))
    if end_param:
        query = query.filter(AIInteractionLog.created_at <= datetime.combine(end_param, datetime.max.time()))

    scoped_logs = query.order_by(AIInteractionLog.created_at.desc()).all()
    payload = _ai_operations_payload(org)
    payload["logs"] = scoped_logs

    return render_template(
        "ai_operations.html",
        **payload,
        AIStatus=AIStatus,
        can_admin=user.role == UserRole.ADMIN,
        assistant_reply=None,
        assistant_question=None,
        assistant_error=None,
    )


@main_bp.route("/ai/operations/assistant", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def ai_operations_assistant():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    payload = _ai_operations_payload(org)
    question = (request.form.get("question") or "").strip()
    if not question:
        flash("Please ask a question for the AI assistant.", "warning")
        return render_template(
            "ai_operations.html",
            **payload,
            AIStatus=AIStatus,
            can_admin=True,
            assistant_reply=None,
            assistant_question=None,
            assistant_error=None,
        )

    latest_logs = payload.get("logs", [])[:5]
    context_lines = [
        f"{log.operation_name} ({log.status.value}) at {log.created_at.strftime('%Y-%m-%d %H:%M')}" for log in latest_logs
    ]

    prompt = (
        "You are the AI Operations Command Console for a tenant."
        " Answer the admin's question using the context and propose 2 admin actions."
        f" Organization: {org.name}."
        f" Recent AI activity: {chr(10).join(context_lines) if context_lines else 'No recent AI calls.'}"
        f" Question: {question}"
    )

    result = ai_service.generate_content(
        operation_name="AI operations assistant",
        organization_id=org.id,
        user_id=user.id,
        contents=prompt,
        context={"question": question, "recent_log_ids": [log.id for log in latest_logs]},
    )

    return render_template(
        "ai_operations.html",
        **payload,
        AIStatus=AIStatus,
        can_admin=True,
        assistant_reply=result.get("text"),
        assistant_question=question,
        assistant_error=result.get("error"),
    )


@main_bp.route("/ai/operations/trigger", methods=["POST"])
@login_required
@org_required
def trigger_ai_health():
    org = g.current_org
    user = g.current_user
    assert org is not None and user is not None

    log_entry = AIInteractionLog(
        organization_id=org.id,
        operation_name="Gemini tenant health",
        context=f"Health probe for org {org.slug}",
        status=AIStatus.PENDING,
        triggered_by_id=user.id,
    )
    db.session.add(log_entry)
    db.session.flush()

    start_time = datetime.utcnow()
    try:
        from google import genai  # type: ignore

        client = genai.Client()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=f"Provide a concise AI operations health summary for the organization named {org.name}.",
        )
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        summary = getattr(response, "text", str(response))

        log_entry.mark_result(AIStatus.SUCCESS, summary=summary[:4000], duration_ms=duration_ms)
        flash("AI health check completed.", "success")
    except Exception as exc:  # pragma: no cover - defensive
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        log_entry.mark_result(
            AIStatus.FAILED,
            summary=f"AI call failed: {exc}",
            duration_ms=duration_ms,
        )
        flash("AI health check failed. See details in the log.", "danger")

    db.session.commit()
    return redirect(url_for("main.ai_operations"))


@main_bp.route("/ai/operations/<int:log_id>/update", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def update_ai_log(log_id: int):
    org = g.current_org
    assert org is not None
    log_entry = AIInteractionLog.query.filter_by(id=log_id, organization_id=org.id).first_or_404()

    status_value = request.form.get("status") or log_entry.status.value
    summary = (request.form.get("result_summary") or log_entry.result_summary or "").strip() or None
    try:
        status_enum = AIStatus(status_value)
    except ValueError:
        status_enum = log_entry.status

    log_entry.status = status_enum
    log_entry.result_summary = summary
    db.session.commit()
    flash("AI log updated.", "success")
    return redirect(url_for("main.ai_operations"))


@main_bp.route("/ai/operations/<int:log_id>/delete", methods=["POST"])
@login_required
@org_required
@role_required(UserRole.ADMIN)
def delete_ai_log(log_id: int):
    org = g.current_org
    assert org is not None
    log_entry = AIInteractionLog.query.filter_by(id=log_id, organization_id=org.id).first_or_404()
    db.session.delete(log_entry)
    db.session.commit()
    flash("AI log deleted.", "warning")
    return redirect(url_for("main.ai_operations"))
