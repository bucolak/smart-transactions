"""Token issuance and verification for registration, MFA, and password reset."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Tuple

from flask import current_app

from ..extensions import db
from ..models import EmailToken, EmailTokenPurpose, Organization, User
from .email_service import render_email, send_email


def _hash_secret(secret: str, salt: str) -> str:
    return hashlib.sha256(f"{secret}{salt}".encode("utf-8")).hexdigest()


def _issue_token(
    *,
    user: User,
    organization: Organization,
    purpose: EmailTokenPurpose,
    ttl_minutes: int,
    secret: str,
    request_ip: str | None = None,
    max_attempts: int | None = None,
) -> EmailToken:
    salt = secrets.token_hex(16)
    token = EmailToken(
        organization_id=organization.id,
        user_id=user.id,
        purpose=purpose,
        token_hash=_hash_secret(secret, salt),
        salt=salt,
        destination_email=user.email,
        expires_at=datetime.utcnow() + timedelta(minutes=max(ttl_minutes, 1)),
        max_attempts=max_attempts or current_app.config.get("EMAIL_OTP_MAX_ATTEMPTS", 5),
        request_ip=request_ip,
        last_sent_at=datetime.utcnow(),
    )
    db.session.add(token)
    db.session.commit()
    return token


def _generate_numeric_code(length: int = 6) -> str:
    length = max(4, min(length, 10))
    upper = 10 ** length
    lower = 10 ** (length - 1)
    return str(secrets.randbelow(upper - lower) + lower)


def issue_registration_otp(*, user: User, organization: Organization, request_ip: str | None = None) -> Tuple[EmailToken, str]:
    code = _generate_numeric_code(6)
    token = _issue_token(
        user=user,
        organization=organization,
        purpose=EmailTokenPurpose.REGISTRATION_VERIFY,
        ttl_minutes=current_app.config.get("EMAIL_OTP_TTL_MINUTES", 10),
        secret=code,
        request_ip=request_ip,
    )
    return token, code


def issue_login_otp(*, user: User, organization: Organization, request_ip: str | None = None) -> Tuple[EmailToken, str]:
    code = _generate_numeric_code(6)
    token = _issue_token(
        user=user,
        organization=organization,
        purpose=EmailTokenPurpose.LOGIN_MFA,
        ttl_minutes=current_app.config.get("EMAIL_OTP_TTL_MINUTES", 10),
        secret=code,
        request_ip=request_ip,
    )
    return token, code


def issue_password_reset_token(*, user: User, organization: Organization, request_ip: str | None = None) -> Tuple[EmailToken, str]:
    secret = secrets.token_urlsafe(32)
    token = _issue_token(
        user=user,
        organization=organization,
        purpose=EmailTokenPurpose.PASSWORD_RESET,
        ttl_minutes=current_app.config.get("EMAIL_RESET_TTL_MINUTES", 30),
        secret=secret,
        request_ip=request_ip,
        max_attempts=1,
    )
    token.meta = secret[:8]  # minimal marker for auditing without exposing full secret
    db.session.commit()
    return token, secret


def issue_invite_token(*, user: User, organization: Organization, request_ip: str | None = None) -> Tuple[EmailToken, str]:
    """Create an invite token so new members can set their password securely."""
    secret = secrets.token_urlsafe(32)
    token = _issue_token(
        user=user,
        organization=organization,
        purpose=EmailTokenPurpose.ORG_INVITE,
        ttl_minutes=current_app.config.get("EMAIL_INVITE_TTL_MINUTES", 72 * 60),
        secret=secret,
        request_ip=request_ip,
        max_attempts=1,
    )
    db.session.commit()
    return token, secret


def validate_token_code(*, token: EmailToken, candidate: str) -> Tuple[bool, str | None]:
    if token.is_consumed:
        return False, "Token already used. Request a new one."
    if token.is_expired:
        return False, "Token expired. Request a fresh code."
    if token.attempts >= token.max_attempts:
        return False, "Maximum attempts reached. Request a new code."

    candidate_hash = _hash_secret(candidate.strip(), token.salt)
    if candidate_hash != token.token_hash:
        token.increment_attempts()
        db.session.commit()
        return False, "Invalid code."

    token.consume()
    db.session.commit()
    return True, None


def check_token_signature(*, token: EmailToken, candidate: str) -> bool:
    """Non-mutating signature check used for GET preflight on reset links."""
    if not candidate:
        return False
    return _hash_secret(candidate.strip(), token.salt) == token.token_hash


def send_registration_email(*, token: EmailToken, code: str, organization: Organization, user: User) -> Tuple[bool, str | None]:
    html = render_email(
        "emails/registration_otp.html",
        otp=code,
        org=organization,
        user=user,
        expires_at=token.expires_at,
    )
    subject = f"Verify your {organization.name} account"
    return send_email(to=user.email, subject=subject, html_body=html)


def send_login_email(*, token: EmailToken, code: str, organization: Organization, user: User, ip_address: str | None) -> Tuple[bool, str | None]:
    html = render_email(
        "emails/login_otp.html",
        otp=code,
        org=organization,
        user=user,
        ip_address=ip_address,
        expires_at=token.expires_at,
    )
    subject = f"Your {organization.name} sign-in code"
    return send_email(to=user.email, subject=subject, html_body=html)


def send_password_reset_email(*, token: EmailToken, secret: str, organization: Organization, user: User) -> Tuple[bool, str | None]:
    reset_url = current_app.config.get("PREFERRED_URL_SCHEME", "https")
    base = current_app.config.get("SERVER_NAME")
    if not base:
        # Fallback to request context external URL
        from flask import url_for

        reset_link = url_for("auth.reset_password", token=token.public_id, code=secret, _external=True)
    else:  # pragma: no cover - optional path
        reset_link = f"{reset_url}://{base}/auth/reset?token={token.public_id}&code={secret}"

    html = render_email(
        "emails/password_reset.html",
        reset_url=reset_link,
        org=organization,
        user=user,
        expires_at=token.expires_at,
    )
    subject = f"Reset your {organization.name} password"
    return send_email(to=user.email, subject=subject, html_body=html)


def send_invite_email(*, token: EmailToken, secret: str, organization: Organization, user: User) -> Tuple[bool, str | None]:
    """Send a branded invite with a secure set-password link."""
    from flask import url_for

    reset_link = url_for("auth.reset_password", token=token.public_id, code=secret, _external=True)
    html = render_email(
        "emails/invite_user.html",
        reset_url=reset_link,
        org=organization,
        user=user,
        expires_at=token.expires_at,
    )
    subject = f"You're invited to {organization.name}"
    return send_email(to=user.email, subject=subject, html_body=html)


def send_superadmin_login_email(*, email: str, name: str, code: str, ip_address: str | None) -> Tuple[bool, str | None]:
    """Send a platform-owner OTP that is not tied to any tenant user."""
    html = render_email(
        "emails/superadmin_login_otp.html",
        otp=code,
        name=name,
        ip_address=ip_address,
    )
    subject = "Platform owner sign-in code"
    return send_email(to=email, subject=subject, html_body=html)
