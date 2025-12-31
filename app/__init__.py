"""Flask application factory for the Smart Transactions SaaS platform."""
import os
import traceback
from flask import Flask, g, render_template, request
from sqlalchemy.engine.url import make_url
from werkzeug.exceptions import HTTPException

from .config import DevelopmentConfig, ProductionConfig
from .extensions import db
from .routes.main import main_bp
from .routes.auth import auth_bp
from .routes.superadmin import superadmin_bp
from .utils.auth import current_superadmin, current_user


def create_app(config_object=None):
    """Application factory to create configured Flask app instances."""
    app = Flask(__name__, instance_relative_config=True)

    # Ensure instance folder exists for SQLite and future secrets
    os.makedirs(app.instance_path, exist_ok=True)

    _configure_app(app, config_object)
    _register_extensions(app)
    _register_blueprints(app)
    _register_shellcontext(app)
    _register_template_globals(app)
    _register_security_headers(app)
    _register_request_hooks(app)
    _register_error_handlers(app)
    _setup_db(app)

    return app


def _configure_app(app, config_object=None):
    env = os.environ.get("FLASK_ENV") or os.environ.get("APP_ENV") or "development"
    if config_object:
        app.config.from_object(config_object)
    elif env.lower() == "production":
        app.config.from_object(ProductionConfig)
    else:
        app.config.from_object(DevelopmentConfig)
    os.makedirs(app.config.get("UPLOAD_FOLDER", app.instance_path), exist_ok=True)


def _register_extensions(app):
    db.init_app(app)


def _register_blueprints(app):
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(superadmin_bp)


def _register_shellcontext(app):
    @app.shell_context_processor
    def make_shell_context():
        from .models import (  # noqa: WPS433
            AIInteractionLog,
            AIStatus,
            Invoice,
            InvoiceStatus,
            OrganizationSubscription,
            Organization,
            PaymentProvider,
            PaymentStatus,
            PaymentTransaction,
            Project,
            ProjectStatus,
            Task,
            TaskPriority,
            TaskStatus,
            SubscriptionPlan,
            SubscriptionStatus,
            User,
            UserRole,
                EmailToken,
                EmailTokenPurpose,
                SupportRequest,
                SupportStatus,
        )

        return {
            "db": db,
            "Organization": Organization,
            "User": User,
            "UserRole": UserRole,
            "Project": Project,
            "ProjectStatus": ProjectStatus,
            "Task": Task,
            "TaskStatus": TaskStatus,
            "TaskPriority": TaskPriority,
            "Invoice": Invoice,
            "InvoiceStatus": InvoiceStatus,
            "AIInteractionLog": AIInteractionLog,
            "AIStatus": AIStatus,
            "SubscriptionPlan": SubscriptionPlan,
            "OrganizationSubscription": OrganizationSubscription,
            "SubscriptionStatus": SubscriptionStatus,
            "PaymentProvider": PaymentProvider,
            "PaymentStatus": PaymentStatus,
            "PaymentTransaction": PaymentTransaction,
                "EmailToken": EmailToken,
                "EmailTokenPurpose": EmailTokenPurpose,
            "SupportRequest": SupportRequest,
            "SupportStatus": SupportStatus,
        }


def _setup_db(app):
    with app.app_context():
        # Import models to ensure metadata is loaded before table creation
        from . import models  # noqa: WPS433

        # Auto-create SQLite database file and parent directory when missing
        database_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        try:
            url = make_url(database_uri)
        except Exception:
            url = None

        if url and url.drivername.startswith("sqlite") and url.database:
            db_dir = os.path.dirname(url.database)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            if not os.path.exists(url.database):
                app.logger.info("Initializing SQLite database at %s", url.database)

        db.create_all()


def _register_template_globals(app):
    from datetime import datetime
    from flask import url_for
    from .models import UserRole

    def _current_brand_color():
        org = getattr(g, "current_org", None)
        return (org.brand_color if org and org.brand_color else "#2563eb")

    def _org_logo_url(url_for_func):
        org = getattr(g, "current_org", None)
        if not org or not org.logo_url:
            return None
        if str(org.logo_url).lower().startswith("http"):
            return org.logo_url
        return url_for_func("main.logo_file", slug=org.slug, filename=org.logo_url)

    @app.context_processor
    def inject_now():
        return {
            "now": datetime.utcnow,
            "current_user": getattr(g, "current_user", None),
            "current_org": getattr(g, "current_org", None),
            "superadmin": getattr(g, "superadmin", None),
            "brand_color": _current_brand_color,
            "org_logo_url": lambda: _org_logo_url(url_for),
            "is_admin": lambda: bool(getattr(g, "current_user", None) and getattr(g, "current_user").role == UserRole.ADMIN),
        }


def _register_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        if app.config.get("ENV") == "production":
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response


def _register_request_hooks(app):
    @app.before_request
    def bind_current_user():
        g.superadmin = current_superadmin()  # type: ignore[attr-defined]
        user = current_user()
        org = getattr(g, "current_org", None)
        if org:
            from .services.subscription_service import ensure_subscription, sync_member_usage  # noqa: WPS433

            subscription = ensure_subscription(org)
            g.current_subscription = subscription  # type: ignore[attr-defined]
            if user:
                sync_member_usage(org, commit=False)


def _register_error_handlers(app):
    def _render_error(error):
        is_http = isinstance(error, HTTPException)
        status_code = getattr(error, "code", None) or 500
        title = getattr(error, "name", None) or "Application error"
        description = getattr(error, "description", None) or "An unexpected error occurred."
        support_email = app.config.get("SUPPORT_INBOX") or app.config.get("SUPERADMIN_EMAIL") or app.config.get("MAIL_DEFAULT_SENDER")
        show_trace = bool(app.config.get("DEBUG") or (app.config.get("ENV") or "").lower() == "development")
        stack_trace = traceback.format_exc() if show_trace and not is_http else None

        if not is_http:
            app.logger.exception("Unhandled exception", exc_info=error)

        payload = {
            "status_code": status_code,
            "error_title": title,
            "error_description": description,
            "detail_message": str(error),
            "stack_trace": stack_trace,
            "path": request.path,
            "method": request.method,
            "support_email": support_email,
            "request_id": request.headers.get("X-Request-ID") or request.environ.get("REQUEST_ID"),
        }

        return render_template("error.html", **payload), status_code

    tracked_codes = (400, 401, 403, 404, 405, 408, 413, 429, 500, 502, 503, 504)
    for code in tracked_codes:
        app.register_error_handler(code, _render_error)
    app.register_error_handler(Exception, _render_error)
