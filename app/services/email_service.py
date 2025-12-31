"""Transactional email delivery utilities with SMTP and SendGrid support."""
from __future__ import annotations

import http.client
import json
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
    """Send an HTML email via SendGrid if configured, otherwise via SMTP."""
    recipients = list(to) if isinstance(to, (list, tuple, set)) else [to]
    if not recipients:
        return False, "No recipients provided"

    api_key = current_app.config.get("SENDGRID_API_KEY", "")
    if api_key:
        ok, err = _send_via_sendgrid(api_key, recipients, subject, html_body)
        if ok:
            return True, None
        # fall through to SMTP on SendGrid failure

    smtp_host = current_app.config.get("SMTP_HOST", "")
    if smtp_host:
        return _send_via_smtp(recipients, subject, html_body)

    return False, "No email provider configured. Set SENDGRID_API_KEY or SMTP_HOST."


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


def _send_via_sendgrid(api_key: str, recipients: list[str], subject: str, html_body: str) -> Tuple[bool, str | None]:
    payload = {
        "personalizations": [{"to": [{"email": rcpt} for rcpt in recipients]}],
        "from": {"email": current_app.config.get("MAIL_DEFAULT_SENDER", "no-reply@smart-transactions.app")},
        "subject": subject,
        "content": [{"type": "text/html", "value": html_body}],
    }

    try:
        conn = http.client.HTTPSConnection("api.sendgrid.com")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        conn.request("POST", "/v3/mail/send", body=json.dumps(payload), headers=headers)
        response = conn.getresponse()
        status = response.status
        if 200 <= status < 300:
            return True, None
        body = response.read().decode()
        return False, f"SendGrid error {status}: {body}"
    except Exception as exc:  # pragma: no cover - network dependent
        return False, f"SendGrid send failed: {exc}"


def render_email(template: str, **context) -> str:
    """Render an HTML email template with the provided context."""
    return render_template(template, **context)
