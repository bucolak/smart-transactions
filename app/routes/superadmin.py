"""Platform-owner control surface with global governance capabilities."""
from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Dict, List

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import case, func
from sqlalchemy.orm import joinedload

from ..extensions import db
from ..models import (
    AIInteractionLog,
    AIStatus,
    EmailToken,
    EmailTokenPurpose,
    Invoice,
    InvoiceStatus,
    Organization,
    OrganizationSubscription,
    PaymentProvider,
    PaymentStatus,
    PaymentTransaction,
    Project,
    Task,
    TaskStatus,
    SubscriptionStatus,
    User,
    UserRole,
)
from ..services.ai_service import load_ai_blocklist, persist_ai_blocklist
from ..services.otp_service import issue_password_reset_token, send_password_reset_email
from ..services.subscription_service import ensure_subscription, sync_member_usage
from ..utils.auth import superadmin_required

superadmin_bp = Blueprint("superadmin", __name__, url_prefix="/superadmin")


@superadmin_bp.route("/dashboard")
@superadmin_required
def dashboard():
    total_orgs = Organization.query.count()
    active_orgs = Organization.query.filter_by(is_active=True).count()
    suspended_orgs = max(total_orgs - active_orgs, 0)
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    ai_usage = AIInteractionLog.query.count()
    ai_failed = AIInteractionLog.query.filter_by(status=AIStatus.FAILED).count()
    invoices_total = db.session.query(func.sum(Invoice.amount)).scalar() or 0

    subscription_rows = (
        db.session.query(OrganizationSubscription.status, func.count(OrganizationSubscription.id))
        .group_by(OrganizationSubscription.status)
        .all()
    )
    subscription_dist = {status.value: count for status, count in subscription_rows}

    transactions = (
        PaymentTransaction.query.order_by(PaymentTransaction.created_at.desc()).limit(10).all()
    )

    growth_rows = (
        db.session.query(func.strftime("%Y-%m", Organization.created_at).label("month"), func.count(Organization.id))
        .group_by("month")
        .order_by("month")
        .all()
    )
    org_growth = [{"label": month, "value": count} for month, count in growth_rows]

    return render_template(
        "superadmin/dashboard.html",
        metrics={
            "total_orgs": total_orgs,
            "active_orgs": active_orgs,
            "suspended_orgs": suspended_orgs,
            "total_users": total_users,
            "active_users": active_users,
            "ai_usage": ai_usage,
            "ai_failed": ai_failed,
            "invoices_total": float(invoices_total),
        },
        subscription_dist=subscription_dist,
        transactions=transactions,
        org_growth=org_growth,
    )


@superadmin_bp.route("/analytics")
@superadmin_required
def analytics():
    payload = _global_analytics_payload()
    return render_template("superadmin/analytics.html", analytics=payload, superadmin=True)


@superadmin_bp.route("/organizations", methods=["GET", "POST"])
@superadmin_required
def organizations():
    if request.method == "POST":
        return _handle_org_action()

    orgs = Organization.query.order_by(Organization.created_at.desc()).all()
    subs = {
        sub.organization_id: sub
        for sub in OrganizationSubscription.query.options(joinedload(OrganizationSubscription.plan)).all()
    }
    return render_template("superadmin/organizations.html", organizations=orgs, subscriptions=subs)


def _handle_org_action():
    org_id = request.form.get("org_id")
    action = request.form.get("action")
    if not org_id or not action:
        flash("Missing organization action details.", "danger")
        return redirect(url_for("superadmin.organizations"))

    organization = Organization.query.filter_by(id=int(org_id)).first()
    if not organization:
        flash("Organization not found.", "danger")
        return redirect(url_for("superadmin.organizations"))

    subscription = ensure_subscription(organization)
    if action == "activate":
        organization.is_active = True
        flash(f"Activated {organization.name}.", "success")
    elif action == "suspend":
        organization.is_active = False
        flash(f"Suspended {organization.name}.", "warning")
    elif action == "set_status":
        new_status = request.form.get("status")
        try:
            subscription.status = SubscriptionStatus(new_status)
            flash("Subscription status updated.", "success")
        except Exception:
            flash("Invalid subscription status.", "danger")
    elif action == "member_limit":
        limit = max(int(request.form.get("member_limit", 0) or 0), 0)
        subscription.purchased_member_limit = limit
        flash("Member limit adjusted.", "success")
    elif action == "extend_trial":
        days = max(int(request.form.get("days", 0) or 0), 0)
        subscription.trial_ends_at = (subscription.trial_ends_at or datetime.utcnow()) + timedelta(days=days)
        flash("Trial window extended.", "success")
    elif action == "reset_usage":
        sync_member_usage(organization, commit=False)
        flash("Usage resynced.", "info")
    else:
        flash("Unsupported action.", "danger")

    db.session.commit()
    return redirect(url_for("superadmin.organizations"))


@superadmin_bp.route("/users", methods=["GET", "POST"])
@superadmin_required
def users():
    if request.method == "POST":
        return _handle_user_action()

    all_users = (
        User.query.options(joinedload(User.organization))
        .order_by(User.created_at.desc())
        .all()
    )
    return render_template("superadmin/users.html", users=all_users)


def _handle_user_action():
    user_id = request.form.get("user_id")
    action = request.form.get("action")
    if not user_id or not action:
        flash("Missing user action details.", "danger")
        return redirect(url_for("superadmin.users"))

    user = User.query.options(joinedload(User.organization)).filter_by(id=int(user_id)).first()
    if not user or not user.organization:
        flash("User not found.", "danger")
        return redirect(url_for("superadmin.users"))

    org = user.organization
    if action == "disable":
        user.is_active = False
        flash(f"Disabled {user.email}.", "warning")
    elif action == "enable":
        user.is_active = True
        flash(f"Enabled {user.email}.", "success")
    elif action == "promote":
        user.role = UserRole.ADMIN
        flash("User promoted to admin.", "success")
    elif action == "demote":
        user.role = UserRole.STANDARD
        flash("User downgraded to standard.", "info")
    elif action == "force_reset":
        token, secret = issue_password_reset_token(user=user, organization=org, request_ip=request.remote_addr)
        send_password_reset_email(token=token, secret=secret, organization=org, user=user)
        flash("Password reset email sent.", "info")
    else:
        flash("Unsupported action.", "danger")

    db.session.commit()
    return redirect(url_for("superadmin.users"))


@superadmin_bp.route("/billing", methods=["GET", "POST"])
@superadmin_required
def billing():
    if request.method == "POST":
        return _handle_billing_action()

    subscriptions = OrganizationSubscription.query.options(joinedload(OrganizationSubscription.organization)).all()
    transactions = PaymentTransaction.query.order_by(PaymentTransaction.created_at.desc()).limit(50).all()
    return render_template(
        "superadmin/billing.html",
        subscriptions=subscriptions,
        transactions=transactions,
    )


def _handle_billing_action():
    sub_id = request.form.get("subscription_id")
    action = request.form.get("action")
    if not sub_id or not action:
        flash("Missing billing action details.", "danger")
        return redirect(url_for("superadmin.billing"))

    subscription = OrganizationSubscription.query.options(joinedload(OrganizationSubscription.organization)).filter_by(id=int(sub_id)).first()
    if not subscription:
        flash("Subscription not found.", "danger")
        return redirect(url_for("superadmin.billing"))

    if action == "force_activate":
        limit = max(int(request.form.get("member_limit", 0) or 0), 0)
        subscription.status = SubscriptionStatus.ACTIVE
        subscription.purchased_member_limit = limit
        subscription.last_payment_at = datetime.utcnow()
        flash("Subscription activated.", "success")
    elif action == "suspend":
        subscription.status = SubscriptionStatus.SUSPENDED
        flash("Subscription suspended.", "warning")
    elif action == "expire":
        subscription.status = SubscriptionStatus.EXPIRED
        flash("Subscription expired.", "info")
    else:
        flash("Unsupported action.", "danger")

    db.session.commit()
    return redirect(url_for("superadmin.billing"))


@superadmin_bp.route("/ai", methods=["GET", "POST"])
@superadmin_required
def ai_monitor():
    if request.method == "POST":
        return _handle_ai_action()

    blocked = load_ai_blocklist()
    logs = AIInteractionLog.query.options(joinedload(AIInteractionLog.triggered_by)).order_by(AIInteractionLog.created_at.desc()).limit(200).all()
    org_usage = (
        db.session.query(AIInteractionLog.organization_id, func.count(AIInteractionLog.id))
        .group_by(AIInteractionLog.organization_id)
        .order_by(func.count(AIInteractionLog.id).desc())
        .all()
    )
    return render_template(
        "superadmin/ai.html",
        logs=logs,
        blocked=blocked,
        org_usage=org_usage,
    )


def _handle_ai_action():
    org_id = request.form.get("org_id")
    action = request.form.get("action")
    if not org_id or not action:
        flash("Missing AI control details.", "danger")
        return redirect(url_for("superadmin.ai_monitor"))

    org_id_int = int(org_id)
    blocked = load_ai_blocklist()
    if action == "block":
        blocked.add(org_id_int)
        persist_ai_blocklist(blocked)
        flash("AI disabled for organization.", "warning")
    elif action == "unblock":
        blocked.discard(org_id_int)
        persist_ai_blocklist(blocked)
        flash("AI enabled for organization.", "success")
    elif action == "purge_logs":
        AIInteractionLog.query.filter_by(organization_id=org_id_int).delete()
        db.session.commit()
        flash("AI logs purged for organization.", "info")
    else:
        flash("Unsupported action.", "danger")

    return redirect(url_for("superadmin.ai_monitor"))


def _safe_percent(numerator: float, denominator: float) -> float:
    return round((numerator / denominator) * 100, 2) if denominator else 0.0


def _format_month_label(raw: str) -> str:
    return raw or ""


def _ensure_daily_series(rows: List[Dict[str, Any]], *, days: int, keys: List[str]) -> List[Dict[str, Any]]:
    """Guarantee a daily time series with zeroed values when the DB has no rows."""
    if rows:
        return rows
    today = date.today()
    labels = [(today - timedelta(days=delta)).strftime("%Y-%m-%d") for delta in range(days - 1, -1, -1)]
    return [{"label": label, **{k: 0 for k in keys}} for label in labels]


def _ensure_monthly_series(rows: List[Dict[str, Any]], *, months: int, keys: List[str]) -> List[Dict[str, Any]]:
    """Guarantee a monthly series (YYYY-MM) so charts never render empty."""
    if rows:
        return rows
    start_month = date.today().replace(day=1)
    labels: List[str] = []
    for i in range(months - 1, -1, -1):
        month_start = (start_month - timedelta(days=i * 30)).strftime("%Y-%m")
        labels.append(month_start)
    return [{"label": label, **{k: 0 for k in keys}} for label in labels]


def _global_analytics_payload() -> Dict[str, Any]:
    now = datetime.utcnow()
    today = date.today()
    past_30 = now - timedelta(days=30)
    past_90 = now - timedelta(days=90)

    total_orgs = Organization.query.count()
    active_orgs = Organization.query.filter_by(is_active=True).count()
    suspended_orgs = max(total_orgs - active_orgs, 0)

    subs_rows = (
        db.session.query(OrganizationSubscription.status, func.count(OrganizationSubscription.id))
        .group_by(OrganizationSubscription.status)
        .all()
    )
    subscription_levels = [
        {"label": status.value.replace("_", " ").title(), "value": count} for status, count in subs_rows
    ] or [
        {"label": "Trial", "value": 0},
        {"label": "Active", "value": active_orgs},
        {"label": "Suspended", "value": suspended_orgs},
    ]

    status_mix = [
        {"label": "Active", "value": active_orgs},
        {"label": "Suspended", "value": suspended_orgs},
        {"label": "Inactive", "value": max(total_orgs - active_orgs - suspended_orgs, 0)},
    ]

    org_regions = [{"label": "Unspecified", "value": total_orgs or 0}]

    trial_paid_rows = (
        db.session.query(
            func.strftime("%Y-%m", OrganizationSubscription.created_at).label("month"),
            func.sum(case((OrganizationSubscription.status == SubscriptionStatus.TRIAL, 1), else_=0)),
            func.sum(case((OrganizationSubscription.status == SubscriptionStatus.ACTIVE, 1), else_=0)),
            func.sum(case((OrganizationSubscription.status == SubscriptionStatus.SUSPENDED, 1), else_=0)),
        )
        .group_by("month")
        .order_by("month")
        .all()
    )
    trial_paid = [
        {"label": _format_month_label(month or ""), "trial": int(trial or 0), "paid": int(paid or 0), "suspended": int(suspended or 0)}
        for month, trial, paid, suspended in trial_paid_rows
    ]
    trial_paid = _ensure_monthly_series(trial_paid, months=6, keys=["trial", "paid", "suspended"])

    org_growth_rows = (
        db.session.query(func.strftime("%Y-%m", Organization.created_at).label("month"), func.count(Organization.id))
        .group_by("month")
        .order_by("month")
        .all()
    )
    org_growth = [
        {"label": _format_month_label(month or ""), "value": count}
        for month, count in org_growth_rows
    ]
    org_growth = _ensure_monthly_series(org_growth, months=6, keys=["value"])

    users_growth_rows = (
        db.session.query(func.strftime("%Y-%m", User.created_at).label("month"), func.count(User.id))
        .group_by("month")
        .order_by("month")
        .all()
    )
    users_growth = [
        {"label": _format_month_label(month or ""), "value": count}
        for month, count in users_growth_rows
    ]
    users_growth = _ensure_monthly_series(users_growth, months=6, keys=["value"])

    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    admin_users = User.query.filter_by(role=UserRole.ADMIN).count()
    verified_users = User.query.filter_by(is_verified=True).count()

    role_rows = db.session.query(User.role, func.count(User.id)).group_by(User.role).all()
    role_mix = [{"label": role.value.title(), "value": count} for role, count in role_rows]

    login_rows = (
        db.session.query(func.strftime("%Y-%m-%d", User.last_login_at).label("day"), func.count(User.id))
        .filter(User.last_login_at.isnot(None), User.last_login_at >= past_30)
        .group_by("day")
        .order_by("day")
        .all()
    )
    login_trend = [{"label": day or "", "value": count, "unique": count} for day, count in login_rows]
    login_trend = _ensure_daily_series(login_trend, days=14, keys=["value", "unique"])

    org_user_rows = (
        db.session.query(Organization.name, func.count(User.id))
        .join(User, User.organization_id == Organization.id)
        .group_by(Organization.name)
        .order_by(func.count(User.id).desc())
        .limit(10)
        .all()
    )
    org_user_distribution = [{"label": name, "value": count} for name, count in org_user_rows]
    if not org_user_distribution:
        org_user_distribution = [{"label": "No organizations", "value": 0}]

    engagement_heatmap: List[Dict[str, Any]] = []
    for i in range(6, -1, -1):
        day_start = now - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        day_label = day_start.strftime("%a")
        day_count = (
            db.session.query(func.count(User.id))
            .filter(User.last_login_at >= day_start, User.last_login_at < day_end)
            .scalar()
            or 0
        )
        engagement_heatmap.append({"label": day_label, "value": int(day_count)})

    project_count = Project.query.count()
    task_count = Task.query.count()
    completed_tasks = Task.query.filter(Task.status == TaskStatus.COMPLETED).count()
    overdue_tasks = (
        Task.query.filter(Task.due_date.isnot(None), Task.due_date < today, Task.status != TaskStatus.COMPLETED).count()
    )

    completion_rows = (
        db.session.query(func.strftime("%Y-%m-%d", Task.completed_at).label("day"), func.count(Task.id))
        .filter(Task.completed_at.isnot(None), Task.completed_at >= past_90)
        .group_by("day")
        .order_by("day")
        .all()
    )
    completion_trend = [{"label": day or "", "completed": count, "overdue": 0} for day, count in completion_rows]
    completion_trend = _ensure_daily_series(completion_trend, days=14, keys=["completed", "overdue"])

    creation_rows = (
        db.session.query(func.strftime("%Y-%m-%d", Task.created_at).label("day"), func.count(Task.id))
        .filter(Task.created_at >= past_30)
        .group_by("day")
        .order_by("day")
        .all()
    )
    creation_completion = [
        {"label": day or "", "created": count, "completed": next((c["completed"] for c in completion_trend if c["label"] == day), 0)}
        for day, count in creation_rows
    ]
    creation_completion = _ensure_daily_series(creation_completion, days=14, keys=["created", "completed"])

    project_load_rows = (
        db.session.query(Project.name, func.count(Task.id))
        .join(Task, Task.project_id == Project.id)
        .group_by(Project.name)
        .order_by(func.count(Task.id).desc())
        .limit(10)
        .all()
    )
    project_load = [{"label": name, "value": count} for name, count in project_load_rows]
    if not project_load:
        project_load = [{"label": "No projects", "value": 0}]

    productivity_rows = (
        db.session.query(Task.project_id, func.count(Task.id), func.avg(func.julianday(Task.completed_at) - func.julianday(Task.created_at)))
        .filter(Task.completed_at.isnot(None))
        .group_by(Task.project_id)
        .limit(30)
        .all()
    )
    productivity = [
        {"x": count, "y": float(avg_days or 0), "r": max(6, min(18, count)), "project": project_id}
        for project_id, count, avg_days in productivity_rows
    ]
    if not productivity:
        productivity = [{"x": 0, "y": 0, "r": 8, "project": "N/A"}]

    revenue_sum = (
        db.session.query(func.coalesce(func.sum(PaymentTransaction.amount), 0))
        .filter(PaymentTransaction.status == PaymentStatus.SUCCEEDED)
        .scalar()
    ) or 0

    monthly_revenue_rows = (
        db.session.query(func.strftime("%Y-%m", PaymentTransaction.created_at).label("month"), func.sum(PaymentTransaction.amount))
        .filter(PaymentTransaction.status == PaymentStatus.SUCCEEDED)
        .group_by("month")
        .order_by("month")
        .all()
    )
    monthly_revenue = [
        {"label": _format_month_label(month or ""), "value": float(amount or 0)}
        for month, amount in monthly_revenue_rows
    ]
    monthly_revenue = _ensure_monthly_series(monthly_revenue, months=6, keys=["value"])

    provider_split_rows = (
        db.session.query(
            func.sum(case((PaymentTransaction.provider == PaymentProvider.STRIPE, 1), else_=0)),
            func.sum(case((PaymentTransaction.provider == PaymentProvider.RAZORPAY, 1), else_=0)),
        )
        .filter(PaymentTransaction.status == PaymentStatus.SUCCEEDED)
        .all()
    )
    stripe_count, razor_count = provider_split_rows[0] if provider_split_rows else (0, 0)
    provider_split = [
        {"label": "Providers", "stripe": int(stripe_count or 0), "razorpay": int(razor_count or 0)}
    ]

    payment_status_rows = (
        db.session.query(PaymentTransaction.status, func.count(PaymentTransaction.id))
        .group_by(PaymentTransaction.status)
        .all()
    )
    payment_status_lookup = {status.value.title(): count for status, count in payment_status_rows}
    payment_status = [
        {"label": status.value.title(), "value": payment_status_lookup.get(status.value.title(), 0)}
        for status in PaymentStatus
    ]

    upgrade_rows = (
        db.session.query(func.strftime("%Y-%m", OrganizationSubscription.last_payment_at).label("month"), func.count(OrganizationSubscription.id))
        .filter(OrganizationSubscription.last_payment_at.isnot(None))
        .group_by("month")
        .order_by("month")
        .all()
    )
    upgrades = [{"label": _format_month_label(month or ""), "value": count} for month, count in upgrade_rows]
    upgrades = _ensure_monthly_series(upgrades, months=6, keys=["value"])

    paid_org_growth = [
        {"label": row[0] or "", "value": row[1]}
        for row in upgrade_rows
    ]
    paid_org_growth = _ensure_monthly_series(paid_org_growth, months=6, keys=["value"])

    ai_total = AIInteractionLog.query.count()
    ai_failed = AIInteractionLog.query.filter_by(status=AIStatus.FAILED).count()
    ai_success = AIInteractionLog.query.filter_by(status=AIStatus.SUCCESS).count()
    ai_trend_rows = (
        db.session.query(
            func.strftime("%Y-%m-%d", AIInteractionLog.created_at).label("day"),
            func.count(AIInteractionLog.id),
            func.sum(case((AIInteractionLog.status == AIStatus.FAILED, 1), else_=0)),
        )
        .filter(AIInteractionLog.created_at >= past_30)
        .group_by("day")
        .order_by("day")
        .all()
    )
    ai_trend = [
        {"label": day or "", "total": total, "failures": int(fails or 0)}
        for day, total, fails in ai_trend_rows
    ]
    ai_trend = _ensure_daily_series(ai_trend, days=14, keys=["total", "failures"])

    ai_outcomes_rows = (
        db.session.query(AIInteractionLog.status, func.count(AIInteractionLog.id))
        .group_by(AIInteractionLog.status)
        .all()
    )
    ai_outcomes = [{"label": status.value.title(), "value": count} for status, count in ai_outcomes_rows]
    if not ai_outcomes:
        ai_outcomes = [
            {"label": AIStatus.SUCCESS.value.title(), "value": 0},
            {"label": AIStatus.FAILED.value.title(), "value": 0},
            {"label": AIStatus.PENDING.value.title(), "value": 0},
        ]

    ai_features_rows = (
        db.session.query(AIInteractionLog.operation_name, func.count(AIInteractionLog.id))
        .group_by(AIInteractionLog.operation_name)
        .order_by(func.count(AIInteractionLog.id).desc())
        .limit(8)
        .all()
    )
    ai_features = [{"label": op, "value": count} for op, count in ai_features_rows]
    if not ai_features:
        ai_features = [{"label": "No activity", "value": 0}]

    ai_org_rows = (
        db.session.query(Organization.name, func.count(AIInteractionLog.id))
        .join(Organization, Organization.id == AIInteractionLog.organization_id)
        .group_by(Organization.name)
        .order_by(func.count(AIInteractionLog.id).desc())
        .limit(10)
        .all()
    )
    ai_orgs = [{"label": name, "value": count} for name, count in ai_org_rows]
    if not ai_orgs:
        ai_orgs = [{"label": "No org usage", "value": 0}]

    ai_user_rows = (
        db.session.query(User.full_name, func.count(AIInteractionLog.id))
        .join(User, User.id == AIInteractionLog.triggered_by_id)
        .group_by(User.full_name)
        .order_by(func.count(AIInteractionLog.id).desc())
        .limit(10)
        .all()
    )
    ai_users = [{"label": name, "value": count} for name, count in ai_user_rows]
    if not ai_users:
        ai_users = [{"label": "No user usage", "value": 0}]

    security_failed_rows = (
        db.session.query(func.strftime("%Y-%m-%d", User.last_login_at).label("day"), func.count(User.id))
        .filter(User.last_login_at.is_(None))
        .group_by("day")
        .order_by("day")
        .all()
    )
    security_failed = [{"label": day or "", "value": count} for day, count in security_failed_rows]
    security_failed = _ensure_daily_series(security_failed, days=14, keys=["value"])

    otp_rows = (
        db.session.query(EmailToken.purpose, func.count(EmailToken.id))
        .filter(EmailToken.created_at >= past_30)
        .group_by(EmailToken.purpose)
        .all()
    )
    otp_mix = [
        {"label": purpose.value.replace("_", " ").title(), "value": count} for purpose, count in otp_rows
    ]
    if not otp_mix:
        otp_mix = [
            {"label": purpose.value.replace("_", " ").title(), "value": 0}
            for purpose in EmailTokenPurpose
        ]

    lock_rows = (
        db.session.query(func.strftime("%Y-%m-%d", User.updated_at).label("day"), func.count(User.id))
        .filter(User.is_active.is_(False))
        .group_by("day")
        .order_by("day")
        .all()
    )
    lock_timeline = [{"label": day or "", "value": count} for day, count in lock_rows]
    lock_timeline = _ensure_daily_series(lock_timeline, days=14, keys=["value"])

    suspicious_rows = (
        db.session.query(func.strftime("%Y-%m-%d", PaymentTransaction.created_at).label("day"), func.count(PaymentTransaction.id))
        .filter(PaymentTransaction.status == PaymentStatus.FAILED)
        .group_by("day")
        .order_by("day")
        .all()
    )
    suspicious = [{"label": day or "", "value": count} for day, count in suspicious_rows]
    suspicious = _ensure_daily_series(suspicious, days=14, keys=["value"])

    stability_timeline = [
        {
            "label": (now - timedelta(days=delta)).strftime("%Y-%m-%d"),
            "uptime": 99.9,
            "latency": 120,
        }
        for delta in range(6, -1, -1)
    ]

    ops_heatmap = [{"label": row["label"], "value": int(row.get("latency", 0))} for row in stability_timeline]

    payload: Dict[str, Any] = {
        "meta": {
            "superadmin_verified": True,
            "last_refreshed": now.isoformat(),
            "brand_color": "#60a5fa",
        },
        "organizations": {
            "total": total_orgs,
            "active": active_orgs,
            "suspended": suspended_orgs,
            "subscription_levels": subscription_levels,
            "status_mix": status_mix,
            "trial_paid": trial_paid,
            "regions": org_regions,
        },
        "platform": {
            "trajectory": {
                "labels": [row["label"] for row in org_growth],
                "orgs": [row["value"] for row in org_growth],
                "users": [row["value"] for row in users_growth],
                "revenue": [row["value"] for row in monthly_revenue],
            }
        },
        "users": {
            "total": total_users,
            "active": active_users,
            "admins": admin_users,
            "verified": verified_users,
            "login_trend": login_trend,
            "growth": [
                {"label": row["label"], "active": row.get("value", 0), "inactive": 0}
                for row in users_growth
            ],
            "roles": role_mix,
            "org_distribution": org_user_distribution,
            "engagement_heatmap": engagement_heatmap,
        },
        "projects": {
            "count": project_count,
            "tasks": task_count,
            "overdue": overdue_tasks,
            "completion_trend": completion_trend,
            "creation_completion": creation_completion,
            "productivity": productivity,
            "load": project_load,
        },
        "finance": {
            "currency": "USD",
            "total_revenue": float(revenue_sum),
            "mrr": monthly_revenue[-1]["value"] if monthly_revenue else 0,
            "stripe_share": _safe_percent(float(stripe_count or 0), float((stripe_count or 0) + (razor_count or 0))),
            "active_subscriptions": OrganizationSubscription.query.filter(OrganizationSubscription.status == SubscriptionStatus.ACTIVE).count(),
            "upgrades_total": sum(v["value"] for v in upgrades),
            "monthly": monthly_revenue,
            "provider_split": provider_split,
            "payment_status": payment_status,
            "upgrade_frequency": upgrades,
            "paid_org_growth": paid_org_growth,
        },
        "ai": {
            "total": ai_total,
            "errors": ai_failed,
            "success_rate": _safe_percent(ai_success, ai_total),
            "trend": ai_trend,
            "outcomes": ai_outcomes,
            "features": ai_features,
            "top_orgs": ai_orgs,
            "top_users": ai_users,
            "forecast": ai_trend,
        },
        "security": {
            "events": len(security_failed),
            "failed_logins": len(security_failed),
            "failed_logins_trend": security_failed,
            "otp": otp_mix,
            "suspicious": suspicious,
            "locks": lock_timeline,
        },
        "stability": {
            "uptime": 99.9,
            "incidents": 0,
            "timeline": stability_timeline,
            "ops_heatmap": ops_heatmap,
        },
    }
    return payload
