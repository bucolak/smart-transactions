"""Application configuration module.

Provides environment-specific settings with sane, secure defaults.
"""
import os
from pathlib import Path
from datetime import timedelta


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
INSTANCE_DIR = PROJECT_ROOT / "instance"
DEFAULT_DB_PATH = INSTANCE_DIR / "database.sqlite"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or f"sqlite:///{DEFAULT_DB_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    APP_NAME = "Smart Transactions"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=45)
    SESSION_REFRESH_EACH_REQUEST = True
    USE_X_SENDFILE = False
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "https")
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB upload ceiling for logos
    ALLOWED_LOGO_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", INSTANCE_DIR / "uploads")


class DevelopmentConfig(Config):
    DEBUG = True
    ENV = "development"


class ProductionConfig(Config):
    DEBUG = False
    ENV = "production"
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
