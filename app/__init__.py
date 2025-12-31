"""Flask application factory for the Smart Transactions SaaS platform."""
import os
from flask import Flask, g

from .config import DevelopmentConfig, ProductionConfig
from .extensions import db
from .routes.main import main_bp
from .routes.auth import auth_bp
from .utils.auth import current_user


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


def _register_shellcontext(app):
    @app.shell_context_processor
    def make_shell_context():
        from .models import Organization, User, UserRole  # noqa: WPS433

        return {"db": db, "Organization": Organization, "User": User, "UserRole": UserRole}


def _setup_db(app):
    with app.app_context():
        # Import models to ensure metadata is loaded before table creation
        from . import models  # noqa: WPS433
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
        current_user()
