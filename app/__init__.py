"""Flask application factory for the Smart Transactions SaaS platform."""
import os
from flask import Flask

from .config import DevelopmentConfig, ProductionConfig
from .extensions import db
from .routes.main import main_bp


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


def _register_extensions(app):
    db.init_app(app)


def _register_blueprints(app):
    app.register_blueprint(main_bp)


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

    @app.context_processor
    def inject_now():
        return {"now": datetime.utcnow}
