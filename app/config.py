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
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)
    SESSION_REFRESH_EACH_REQUEST = True
    USE_X_SENDFILE = False
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "https")
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB upload ceiling for logos
    ALLOWED_LOGO_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", INSTANCE_DIR / "uploads")
    SUBSCRIPTION_TRIAL_DAYS = int(os.environ.get("SUBSCRIPTION_TRIAL_DAYS", "14"))
    SUBSCRIPTION_TRIAL_LIMIT = int(os.environ.get("SUBSCRIPTION_TRIAL_LIMIT", "5"))
    SUBSCRIPTION_BASE_FEE = float(os.environ.get("SUBSCRIPTION_BASE_FEE", "50"))
    SUBSCRIPTION_PER_MEMBER_FEE = float(os.environ.get("SUBSCRIPTION_PER_MEMBER_FEE", "5"))
    SUBSCRIPTION_DEFAULT_CURRENCY = os.environ.get("SUBSCRIPTION_DEFAULT_CURRENCY", "USD").upper()
    STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
    RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
    RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "no-reply@smart-transactions.app")
    MAIL_DEFAULT_NAME = os.environ.get("MAIL_DEFAULT_NAME", "Smart Transactions Security")
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
    SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").lower() == "true"
    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
    SUPPORT_INBOX = os.environ.get("SUPPORT_INBOX", "") or os.environ.get("SUPERADMIN_EMAIL", "")
    SUPPORT_CATEGORIES = (
        "Billing & Payments",
        "Subscription & Plan Issues",
        "Technical Issue / Bug Report",
        "Feature Request",
        "Account / Login Problems",
        "Security Concern",
        "Organization / Admin Support",
        "AI & Automation Issues",
        "General Inquiry",
        "Other",
    )
    EMAIL_OTP_TTL_MINUTES = int(os.environ.get("EMAIL_OTP_TTL_MINUTES", "10"))
    EMAIL_RESET_TTL_MINUTES = int(os.environ.get("EMAIL_RESET_TTL_MINUTES", "30"))
    EMAIL_OTP_MAX_ATTEMPTS = int(os.environ.get("EMAIL_OTP_MAX_ATTEMPTS", "5"))
    EMAIL_INVITE_TTL_MINUTES = int(os.environ.get("EMAIL_INVITE_TTL_MINUTES", str(72 * 60)))
    SUPERADMIN_EMAIL = os.environ.get("SUPERADMIN_EMAIL", "")
    SUPERADMIN_PASSWORD = os.environ.get("SUPERADMIN_PASSWORD", "")
    SUPERADMIN_NAME = os.environ.get("SUPERADMIN_NAME", "Platform Root Owner")
    SUPERADMIN_OTP_TTL_MINUTES = int(os.environ.get("SUPERADMIN_OTP_TTL_MINUTES", "10"))
    SUPERADMIN_OTP_MAX_ATTEMPTS = int(os.environ.get("SUPERADMIN_OTP_MAX_ATTEMPTS", "5"))


class DevelopmentConfig(Config):
    DEBUG = True
    ENV = "development"


class ProductionConfig(Config):
    DEBUG = False
    ENV = "production"
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
