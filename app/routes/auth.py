"""Authentication and onboarding routes for the multi-tenant SaaS."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta
from typing import Optional

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import or_  # type: ignore
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import EmailToken, EmailTokenPurpose, Organization, User, UserRole
from ..services.otp_service import (
    check_token_signature,
    issue_login_otp,
    issue_password_reset_token,
    issue_registration_otp,
    send_superadmin_login_email,
    send_login_email,
    send_password_reset_email,
    send_registration_email,
    validate_token_code,
)
from ..services.email_service import render_email, send_email
from ..services.subscription_service import ensure_subscription, sync_member_usage
from ..utils.auth import (
    SESSION_PENDING_LOGIN_TOKEN,
    SESSION_PENDING_LOGIN_USER,
    SESSION_SUPERADMIN_CHALLENGE,
    clear_session,
    clear_superadmin_challenge,
    normalize_email,
    start_session,
    start_superadmin_session,
)
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


def _purge_tokens(user_id: int, purpose: EmailTokenPurpose) -> None:
    EmailToken.query.filter_by(user_id=user_id, purpose=purpose).delete()
    db.session.commit()


def _normalize_otp_input(raw: str | None) -> str:
    if not raw:
        return ""
    return re.sub(r"\s+", "", raw).strip()


def _superadmin_config() -> Optional[dict]:
    email = normalize_email(current_app.config.get("SUPERADMIN_EMAIL", ""))
    password = current_app.config.get("SUPERADMIN_PASSWORD", "")
    name = current_app.config.get("SUPERADMIN_NAME", "Platform Root Owner")
    if not email or not password:
        return None
    return {"email": email, "password": password, "name": name}


def _generate_superadmin_code() -> str:
    return str(secrets.randbelow(900000) + 100000)


def _store_superadmin_challenge(*, code: str, email: str, name: str) -> None:
    salt = secrets.token_hex(16)
    ttl_minutes = max(int(current_app.config.get("SUPERADMIN_OTP_TTL_MINUTES", 10)), 1)
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    session[SESSION_SUPERADMIN_CHALLENGE] = {
        "salt": salt,
        "hash": hashlib.sha256(f"{code}{salt}".encode()).hexdigest(),
        "expires_at": expires_at.isoformat(),
        "attempts": 0,
        "max_attempts": int(current_app.config.get("SUPERADMIN_OTP_MAX_ATTEMPTS", 5)),
        "email": email,
        "name": name,
        "issued_at": datetime.utcnow().isoformat(),
    }


def _validate_superadmin_challenge(candidate: str) -> tuple[bool, str | None]:
    challenge = session.get(SESSION_SUPERADMIN_CHALLENGE) or {}
    if not challenge:
        return False, "Session expired. Start again."
    try:
        expires_at = datetime.fromisoformat(challenge.get("expires_at", ""))
    except ValueError:
        return False, "Session expired."
    if datetime.utcnow() >= expires_at:
        return False, "Code expired. Request a new one."
    attempts = int(challenge.get("attempts", 0))
    max_attempts = int(challenge.get("max_attempts", 5))
    if attempts >= max_attempts:
        return False, "Too many attempts. Request a new code."

    salt = challenge.get("salt", "")
    candidate_hash = hashlib.sha256(f"{candidate}{salt}".encode()).hexdigest()
    if not hmac.compare_digest(candidate_hash, challenge.get("hash", "")):
        challenge["attempts"] = attempts + 1
        session[SESSION_SUPERADMIN_CHALLENGE] = challenge
        return False, "Invalid code."

    clear_superadmin_challenge()
    return True, None


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html", form={})

    clear_session()
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

    admin_user = None
    organization = None
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
            is_active=False,
            is_verified=False,
        )
        admin_user.set_password(password)

        db.session.add(organization)
        db.session.add(admin_user)
        db.session.commit()
        ensure_subscription(organization)
        sync_member_usage(organization, commit=False)
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

    if not admin_user or not organization:
        flash("Registration failed. Please try again.", "danger")
        return redirect(url_for("auth.register"))

    _purge_tokens(admin_user.id, EmailTokenPurpose.REGISTRATION_VERIFY)
    token, code = issue_registration_otp(
        user=admin_user,
        organization=organization,
        request_ip=request.remote_addr,
    )
    send_ok, send_err = send_registration_email(token=token, code=code, organization=organization, user=admin_user)
    if not send_ok and send_err:
        flash(f"Account created but email delivery failed: {send_err}", "warning")
    else:
        flash("We sent a verification code to your email. Enter it to activate your account.", "info")

    return redirect(url_for("auth.verify_registration", token=token.public_id))


@auth_bp.route("/register/verify/<token>", methods=["GET", "POST"])
def verify_registration(token: str):
    challenge = EmailToken.query.filter_by(public_id=token, purpose=EmailTokenPurpose.REGISTRATION_VERIFY).first()
    if not challenge or not challenge.user or not challenge.user.organization:
        flash("This verification link is invalid or has expired.", "danger")
        return redirect(url_for("auth.register"))

    user = challenge.user
    organization = user.organization
    if user.is_verified:
        flash("Account already verified. Please sign in.", "info")
        return redirect(url_for("auth.login", org=organization.slug))

    if request.method == "POST":
        code = _normalize_otp_input(request.form.get("otp"))
        if not code:
            flash("Enter the code we emailed to you.", "danger")
        else:
            success, message = validate_token_code(token=challenge, candidate=code)
            if success:
                user.mark_verified()
                db.session.commit()
                ensure_subscription(organization)
                sync_member_usage(organization, commit=False)
                db.session.commit()
                clear_session()
                start_session(user)
                try:
                    welcome_html = render_email(
                        "emails/subscription_notice.html",
                        title="Workspace activated",
                        badge="Organization",
                        heading=f"{organization.name} is live",
                        subheading="Email verification complete",
                        pill="Welcome",
                        message="Your workspace is fully activated. Use the dashboard to invite your team and enforce MFA by default.",
                        facts={"Organization": organization.slug, "Admin": user.full_name},
                        org=organization,
                    )
                    send_email(
                        to=organization.contact_email,
                        subject=f"{organization.name} workspace activated",
                        html_body=welcome_html,
                    )
                except Exception:
                    current_app.logger.warning("Activation email failed", exc_info=True)
                flash("Email verified. You're all set!", "success")
                return redirect(url_for("main.onboarding"))
            flash(message or "Invalid code.", "danger")

    return render_template(
        "auth/verify_registration.html",
        token=challenge,
        org=organization,
        email=user.email,
        expires_at=challenge.expires_at,
    )


@auth_bp.route("/register/resend/<token>")
def resend_registration(token: str):
    challenge = EmailToken.query.filter_by(public_id=token, purpose=EmailTokenPurpose.REGISTRATION_VERIFY).first()
    if not challenge or not challenge.user or not challenge.user.organization:
        flash("Unable to resend. Please register again.", "danger")
        return redirect(url_for("auth.register"))

    user = challenge.user
    organization = user.organization
    if user.is_verified:
        flash("Account is already verified. Please sign in.", "info")
        return redirect(url_for("auth.login", org=organization.slug))

    _purge_tokens(user.id, EmailTokenPurpose.REGISTRATION_VERIFY)
    new_token, code = issue_registration_otp(
        user=user,
        organization=organization,
        request_ip=request.remote_addr,
    )
    send_registration_email(token=new_token, code=code, organization=organization, user=user)
    flash("A fresh verification code was sent to your email.", "info")
    return redirect(url_for("auth.verify_registration", token=new_token.public_id))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        clear_session()
        return render_template("auth/login.html", org_hint=request.args.get("org", ""))

    org_identifier = request.form.get("organization", "").strip()
    email = normalize_email(request.form.get("email", ""))
    password = request.form.get("password", "")

    superadmin_cfg = _superadmin_config()
    if superadmin_cfg and hmac.compare_digest(email, superadmin_cfg["email"]):
        if not hmac.compare_digest(password, superadmin_cfg["password"]):
            flash("Invalid credentials. Please verify your details and try again.", "danger")
            return render_template("auth/login.html", org_hint=org_identifier, email=email)

        clear_session()
        code = _generate_superadmin_code()
        _store_superadmin_challenge(code=code, email=superadmin_cfg["email"], name=superadmin_cfg["name"])
        send_superadmin_login_email(
            email=superadmin_cfg["email"],
            name=superadmin_cfg["name"],
            code=code,
            ip_address=request.remote_addr,
        )
        flash("Platform owner verification code sent. Check your email to continue.", "info")
        return redirect(url_for("auth.superadmin_otp", next=request.args.get("next")))

    if not org_identifier or not email or not password:
        flash("All fields are required to sign in.", "danger")
        return render_template("auth/login.html", org_hint=org_identifier, email=email)

    organization = _find_org(org_identifier)
    if not organization:
        flash("Invalid credentials. Please verify your organization and try again.", "danger")
        return render_template("auth/login.html", org_hint=org_identifier, email=email)

    user = User.query.filter_by(organization_id=organization.id, email=email).first()
    if not user or not user.check_password(password):
        flash("Invalid credentials. Please verify your details and try again.", "danger")
        return render_template("auth/login.html", org_hint=org_identifier, email=email)

    if not user.is_active:
        flash("This account is disabled. Contact your administrator.", "danger")
        return render_template("auth/login.html", org_hint=org_identifier, email=email)

    if not user.is_verified:
        _purge_tokens(user.id, EmailTokenPurpose.REGISTRATION_VERIFY)
        token, code = issue_registration_otp(
            user=user,
            organization=organization,
            request_ip=request.remote_addr,
        )
        send_registration_email(token=token, code=code, organization=organization, user=user)
        flash("We need to verify your email before signing you in. Enter the code we just sent.", "warning")
        return redirect(url_for("auth.verify_registration", token=token.public_id))

    _purge_tokens(user.id, EmailTokenPurpose.LOGIN_MFA)
    token, code = issue_login_otp(
        user=user,
        organization=organization,
        request_ip=request.remote_addr,
    )
    send_login_email(
        token=token,
        code=code,
        organization=organization,
        user=user,
        ip_address=request.remote_addr,
    )
    session[SESSION_PENDING_LOGIN_USER] = user.id
    session[SESSION_PENDING_LOGIN_TOKEN] = token.public_id
    flash("We emailed you a one-time code. Enter it to finish signing in.", "info")
    return redirect(url_for("auth.login_otp", next=request.args.get("next")))


@auth_bp.route("/login/otp", methods=["GET", "POST"])
def login_otp():
    challenge_id = session.get(SESSION_PENDING_LOGIN_TOKEN) or request.args.get("token")
    user_id = session.get(SESSION_PENDING_LOGIN_USER)
    if not challenge_id or not user_id:
        flash("Start by entering your email and password.", "warning")
        return redirect(url_for("auth.login"))

    challenge = EmailToken.query.filter_by(public_id=challenge_id, purpose=EmailTokenPurpose.LOGIN_MFA).first()
    if not challenge or not challenge.user or challenge.user.id != user_id:
        flash("Your login attempt expired. Please sign in again.", "warning")
        clear_session()
        return redirect(url_for("auth.login"))

    user = challenge.user
    organization = user.organization
    if not organization or not user.is_active:
        flash("Account is inactive.", "danger")
        clear_session()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = _normalize_otp_input(request.form.get("otp"))
        success, message = validate_token_code(token=challenge, candidate=code)
        if success:
            user.mark_login()
            db.session.commit()
            clear_session()
            start_session(user)
            flash(f"Welcome back, {user.full_name.split(' ')[0]}!", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("main.dashboard"))
        flash(message or "Invalid code.", "danger")

    session[SESSION_PENDING_LOGIN_TOKEN] = challenge.public_id
    session[SESSION_PENDING_LOGIN_USER] = user.id
    return render_template(
        "auth/login_otp.html",
        token=challenge,
        org=organization,
        email=user.email,
        expires_at=challenge.expires_at,
    )


@auth_bp.route("/superadmin/otp", methods=["GET", "POST"])
def superadmin_otp():
    cfg = _superadmin_config()
    challenge = session.get(SESSION_SUPERADMIN_CHALLENGE)
    if not cfg or not challenge or normalize_email(challenge.get("email", "")) != cfg["email"]:
        flash("Start by signing in as platform owner.", "warning")
        clear_session()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = _normalize_otp_input(request.form.get("otp"))
        success, message = _validate_superadmin_challenge(code)
        if success:
            start_superadmin_session(name=cfg["name"], email=cfg["email"])
            flash("Super admin authenticated.", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("superadmin.dashboard"))
        flash(message or "Invalid code.", "danger")

    remaining = 0
    try:
        remaining = max(int(challenge.get("max_attempts", 0)) - int(challenge.get("attempts", 0)), 0)
    except Exception:
        remaining = 0
    return render_template(
        "auth/superadmin_otp.html",
        email=cfg["email"],
        name=cfg["name"],
        expires_at=challenge.get("expires_at"),
        attempts_left=remaining,
    )


@auth_bp.route("/superadmin/otp/resend")
def resend_superadmin_otp():
    cfg = _superadmin_config()
    if not cfg:
        flash("Super admin credentials are not configured.", "danger")
        return redirect(url_for("auth.login"))

    code = _generate_superadmin_code()
    _store_superadmin_challenge(code=code, email=cfg["email"], name=cfg["name"])
    send_superadmin_login_email(
        email=cfg["email"],
        name=cfg["name"],
        code=code,
        ip_address=request.remote_addr,
    )
    flash("A fresh platform owner code was sent.", "info")
    return redirect(url_for("auth.superadmin_otp"))


@auth_bp.route("/login/otp/resend")
def resend_login_otp():
    challenge_id = session.get(SESSION_PENDING_LOGIN_TOKEN)
    user_id = session.get(SESSION_PENDING_LOGIN_USER)
    if not challenge_id or not user_id:
        flash("Start by signing in with email and password.", "warning")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(id=user_id).first()
    if not user or not user.organization:
        flash("Session expired. Please sign in again.", "warning")
        clear_session()
        return redirect(url_for("auth.login"))

    organization = user.organization
    _purge_tokens(user.id, EmailTokenPurpose.LOGIN_MFA)
    token, code = issue_login_otp(
        user=user,
        organization=organization,
        request_ip=request.remote_addr,
    )
    send_login_email(
        token=token,
        code=code,
        organization=organization,
        user=user,
        ip_address=request.remote_addr,
    )
    session[SESSION_PENDING_LOGIN_TOKEN] = token.public_id
    flash("A new sign-in code was sent.", "info")
    return redirect(url_for("auth.login_otp"))


@auth_bp.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        clear_session()
        return render_template("auth/forgot_password.html")

    org_identifier = request.form.get("organization", "").strip()
    email = normalize_email(request.form.get("email", ""))
    if not org_identifier or not email:
        flash("Organization and email are required.", "danger")
        return render_template("auth/forgot_password.html", org_hint=org_identifier, email=email)

    organization = _find_org(org_identifier)
    user = None
    if organization:
        user = User.query.filter_by(organization_id=organization.id, email=email, is_active=True).first()

    if not user:
        flash("If that account exists, a reset email is on the way.", "info")
        return redirect(url_for("auth.login"))

    _purge_tokens(user.id, EmailTokenPurpose.PASSWORD_RESET)
    token, secret = issue_password_reset_token(
        user=user,
        organization=organization,
        request_ip=request.remote_addr,
    )
    send_password_reset_email(token=token, secret=secret, organization=organization, user=user)
    flash("If that account exists, a reset email is on the way.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/reset", methods=["GET", "POST"])
def reset_password():
    public_id = request.args.get("token") or request.form.get("token")
    secret = request.args.get("code") or request.form.get("code")
    if not public_id or not secret:
        flash("Reset link is invalid.", "danger")
        return redirect(url_for("auth.login"))

    token = (
        EmailToken.query.filter(
            EmailToken.public_id == public_id,
            EmailToken.purpose.in_([EmailTokenPurpose.PASSWORD_RESET, EmailTokenPurpose.ORG_INVITE]),
        )
        .first()
    )
    if not token or not token.user or not token.user.organization:
        flash("Reset link is invalid or expired.", "danger")
        return redirect(url_for("auth.login"))

    if token.is_consumed or token.is_expired or token.attempts >= token.max_attempts:
        flash("Reset link is invalid or expired.", "danger")
        return redirect(url_for("auth.login"))

    if not check_token_signature(token=token, candidate=secret):
        flash("Reset link is invalid.", "danger")
        return redirect(url_for("auth.login"))

    user = token.user
    organization = user.organization

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if len(password) < 12:
            errors.append("Password must be at least 12 characters.")
        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password):
            errors.append("Use upper, lower, and number characters for strength.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template(
                "auth/reset_password.html",
                token=public_id,
                code=secret,
                org=organization,
                email=user.email,
            )

        success, message = validate_token_code(token=token, candidate=secret)
        if not success:
            flash(message or "Reset link is invalid.", "danger")
            return redirect(url_for("auth.login"))

        user.set_password(password)
        user.is_active = True
        if not user.is_verified:
            user.mark_verified()
        db.session.commit()
        sync_member_usage(organization, commit=True)
        clear_session()
        start_session(user)
        flash("Password updated. You are signed in.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template(
        "auth/reset_password.html",
        token=public_id,
        code=secret,
        org=organization,
        email=user.email,
    )


@auth_bp.route("/logout")
def logout():
    clear_session()
    flash("You have been signed out securely.", "info")
    return redirect(url_for("auth.login"))
