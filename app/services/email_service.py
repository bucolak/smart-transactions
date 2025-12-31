"""Transactional email delivery utilities using SMTP only."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from typing import Iterable, Tuple

from flask import current_app, render_template


def _build_sender() -> str:
    sender_email = current_app.config.get("MAIL_DEFAULT_SENDER", "no-reply@smart-transactions.app")
    sender_name = current_app.config.get("MAIL_DEFAULT_NAME", "Smart Transactions Security")
    return formataddr((sender_name, sender_email))


def send_email(*, to: str | Iterable[str], subject: str, html_body: str) -> Tuple[bool, str | None]:
    """Send an HTML email via SMTP.

    If SMTP is not configured, log and return an explicit error so callers can surface it.
    """
    recipients = list(to) if isinstance(to, (list, tuple, set)) else [to]
    if not recipients:
        current_app.logger.warning("Email send aborted: no recipients provided for subject '%s'", subject)
        return False, "No recipients provided"

    smtp_host = (current_app.config.get("SMTP_HOST") or "").strip()
    if not smtp_host:
        current_app.logger.error("SMTP delivery skipped: SMTP_HOST is not configured.")
        return False, "SMTP is not configured. Set SMTP_HOST (and credentials if required)."

    ok, err = _send_via_smtp(recipients, subject, html_body)
    if not ok:
        current_app.logger.error("SMTP delivery failed: %s", err)
    return ok, err


def _send_via_smtp(recipients: list[str], subject: str, html_body: str) -> Tuple[bool, str | None]:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _build_sender()
    msg["To"] = ", ".join(recipients)
    msg.set_content("This message requires an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")

    host = current_app.config.get("SMTP_HOST")
    port = int(current_app.config.get("SMTP_PORT", 587))
    username = current_app.config.get("SMTP_USERNAME")
    password = current_app.config.get("SMTP_PASSWORD")
    use_tls = bool(current_app.config.get("SMTP_USE_TLS", True))
    use_ssl = bool(current_app.config.get("SMTP_USE_SSL", False))

    try:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context) as server:
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port) as server:
                if use_tls:
                    server.starttls(context=ssl.create_default_context())
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
    except Exception as exc:  # pragma: no cover - network dependent
        return False, f"SMTP send failed: {exc}"

    return True, None


def render_email(template: str, **context) -> str:
    """Render an HTML email template with the provided context."""
    return render_template(template, **context)
