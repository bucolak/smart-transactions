Smart Transactions
===================

Overview
--------
- Multi-tenant Flask SaaS that unifies subscription licensing, finance operations, project/task execution, AI observability, and support.
- Tenant isolation is enforced in routes, services, models, and templates; superadmin “god mode” is a separate OTP-gated path.
- Defaults to SQLite in the `instance/` directory; works with Stripe and Razorpay for payments and SendGrid/SMTP for email delivery.
- AI features call Gemini (model `gemini-2.5-flash`) via a thin service that logs every request/result per organization.

Key Features
------------
- Authentication & MFA: Password + email OTP for org users; superadmin OTP for platform owners; password reset flows.
- Tenant management: Org onboarding with branding (logo upload or URL, brand color, tagline), onboarding page, org profile editor.
- RBAC: `admin` vs `standard` roles, plus superadmin bypass; server-side decorators guard tenant, role, and session context.
- Projects & Tasks: CRUD with status/priority, due dates, assignees, bulk task insights, and AI-powered summaries/ideas.
- Finance & Billing: Invoices, payment status, totals, revenue summaries; subscription purchase flows with Stripe Checkout or Razorpay order + signature verification.
- Subscription Gating: Trial limits, per-seat allowance, seat counting, plan pricing (base + per-member), upgrade checkout, webhook handling.
- Team Management: Invite single users or bulk CSV import with secure email links; edit role/status; seat usage indicators.
- AI Operations: Health checks, assistant console, AI log editing/deletion, charts for usage/ops, demo seeding, modal drill-downs.
- Analytics: Tenant analytics (users, logins, roles, projects/tasks, finance, AI) and superadmin global analytics with Chart.js dashboards.
- Support: Public support form with categories, tenant context capture, and confirmation page; admin email notifications.
- Content & SEO: Marketing pages (home, about, terms, privacy), structured data (JSON-LD), security headers, canonical/meta tags.

Architecture
------------
- Framework: Flask application factory in `app/__init__.py`; blueprints for `main`, `auth`, and `superadmin` routes.
- Persistence: SQLAlchemy models with `TenantMixin` and `TimestampMixin`; SQLite default with foreign keys enforced in `extensions.py`.
- Models: organizations, users, projects, tasks, invoices, subscriptions, payment transactions, AI logs, email tokens, support requests.
- Services: `ai_service` (Gemini calls + logging), `email_service` (SendGrid/SMTP), `otp_service` (issuance/validation + email), `subscription_service` (seat sync, checkout, webhook handling).
- Utils: Authentication decorators (`login_required`, `org_required`, `role_required`, `superadmin_required`), session/org helpers, password generator, file upload helper.
- Frontend: Jinja2 templates with Bootstrap 5, Bootstrap Icons, Chart.js, custom CSS/JS; role-aware nav and scoped actions.
- Static: `static/css/main.css`, `static/js/main.js`, icons/images for branding and marketing sections.

Setup
-----
1. Python environment
	- Python 3.11+ recommended.
	- Create and activate a virtual environment.
2. Install dependencies
	- `pip install -r requirements.txt` (file assumed to be present with Flask/SQLAlchemy/etc.).
3. Environment
	- Copy `.env.example` if present or set the variables listed below (minimum: `SECRET_KEY`).
4. Database
	- Default SQLite file at `instance/database.sqlite` (auto-created). For a fresh start, delete the file to re-seed tables.
5. Run
	- `flask run` (with `FLASK_APP=run.py`) or `python run.py` for the built-in server.
6. Access
	- App runs at `http://localhost:5000`. Health probe: `/health`.

Usage
-----
- Register: Create an organization + admin via `/register`; verify email OTP to activate.
- Login: `/login` with org identifier + email + password → email OTP to complete.
- Dashboard: `/dashboard` for tenant summary and AI insight trigger.
- Projects: `/projects` for project/task CRUD, AI task ideas/insights, and charts.
- Finance: `/finance` for invoices/payments, revenue charts, AI insights; Stripe/Razorpay checkout on `/subscription`.
- Team: `/team` for invites, bulk CSV upload, edit role/status (admin only).
- AI Ops: `/ai-operations` for AI logs, assistant, health checks, charts.
- Analytics: `/analytics` (tenant) and `/superadmin/analytics` (platform) for Chart.js boards.
- Support: `/support` to file tickets; confirmation at `/support/submitted/<id>`.
- Superadmin: `/superadmin/login` → OTP → dashboards for orgs, users, billing, AI control.

Configuration (env vars)
------------------------
- Core: `SECRET_KEY`, `DATABASE_URL` (else SQLite at `instance/database.sqlite`), `PREFERRED_URL_SCHEME`.
- Cookies/Sessions: `SESSION_COOKIE_SECURE` (prod), `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, `PERMANENT_SESSION_LIFETIME` (minutes).
- Uploads: `UPLOAD_FOLDER` (default `instance/uploads`), `MAX_CONTENT_LENGTH` (2MB), `ALLOWED_LOGO_EXTENSIONS`.
- Subscription & Billing: `SUBSCRIPTION_TRIAL_DAYS`, `SUBSCRIPTION_TRIAL_LIMIT`, `SUBSCRIPTION_BASE_FEE`, `SUBSCRIPTION_PER_MEMBER_FEE`, `SUBSCRIPTION_DEFAULT_CURRENCY`.
- Stripe: `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET`.
- Razorpay: `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`.
- Email: `MAIL_DEFAULT_SENDER`, `MAIL_DEFAULT_NAME`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_USE_TLS`, `SMTP_USE_SSL`, `SENDGRID_API_KEY`.
- Support: `SUPPORT_INBOX` (defaults to `SUPERADMIN_EMAIL`), `SUPPORT_CATEGORIES` (preset list in config).
- OTP/Links: `EMAIL_OTP_TTL_MINUTES`, `EMAIL_RESET_TTL_MINUTES`, `EMAIL_OTP_MAX_ATTEMPTS`, `EMAIL_INVITE_TTL_MINUTES`.
- Superadmin: `SUPERADMIN_EMAIL`, `SUPERADMIN_PASSWORD`, `SUPERADMIN_NAME`, `SUPERADMIN_OTP_TTL_MINUTES`, `SUPERADMIN_OTP_MAX_ATTEMPTS`.

Security Posture
----------------
- Tenant isolation enforced via org-bound queries and decorators; superadmin routes are separate and OTP-gated.
- Cookies HTTPOnly by default; Secure enabled in production; SameSite=Lax; 45-minute session lifetime with refresh.
- Passwords hashed (PBKDF2); MFA via email OTP for login/registration/reset/invite/superadmin flows with TTL + attempt caps.
- File uploads constrained to 2MB and whitelisted extensions; stored per org in `instance/uploads`.
- Support tickets and AI logs are scoped to organizations; admin-only actions protected server-side.
- Security headers and referrer policy set in app factory; robots set to noindex for authenticated/sensitive areas.

Performance & Operations
------------------------
- Lightweight stack (Flask + SQLite) suitable for local/dev; SQLAlchemy session management and FK enforcement.
- Chart.js dashboards pull aggregated counts/trends; empty-state handling to avoid heavy renders without data.
- Health check endpoint `/health`; AI health trigger seeds demo data when requested by admins.
- Email and payment providers are optional; if keys are empty those features remain dormant.

Limitations
-----------
- SQLite default is not production-grade for write-heavy or multi-node deployments; replace `DATABASE_URL` with Postgres/MySQL in production.
- No background workers/queues; Stripe/Razorpay webhooks and email sending occur inline.
- AI service assumes Gemini API key via environment (not configured in code defaults); calls may fail without it.
- No rate limiting or WAF; front-door security should be added for production.
- Tests are not included in this repository.

Enhancement Ideas
-----------------
- Add Celery/RQ tasks for email, AI calls, and payment webhooks to decouple latency.
- Provide Postgres migrations (Alembic) and seed scripts for staging/production.
- Add rate limiting, CSP, and stricter input validation for public forms.
- Extend AI guardrails (blocklists, PII redaction) and add alerting on AI failure rates.
- Build comprehensive test suite (unit + integration) and CI pipeline.

Business Value
--------------
- Accelerates launch of compliant, seat-based SaaS with payments, analytics, and AI telemetry ready out of the box.
- Reduces implementation risk with RBAC, MFA, tenant isolation, and audit trails already wired.
- Provides investor- and customer-facing credibility via polished UI, legal pages, and operational dashboards.

Contribution
------------
- Open a ticket or branch off `main`.
- Run formatting/linting if configured; add small, focused PRs with context.
- Include screenshots for UI changes where relevant.

License
-------
- No explicit license file is present. Treat the code as “all rights reserved” until the maintainer specifies otherwise.

Conclusion
----------
- Smart Transactions is a complete reference stack for tenant-aware billing, AI observability, and operations. Configure environment secrets, run the Flask app, and expand with the suggested enhancements for production readiness.
