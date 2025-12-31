# Smart Transactions SaaS Starter

Production-minded Flask + SQLAlchemy + Bootstrap foundation for building a modern payments or transactions SaaS.

## Stack
- Flask application factory with modular blueprints
- SQLAlchemy ORM backed by SQLite (instance-scoped)
- Bootstrap 5 + Bootstrap Icons + Manrope typography
- Ready-to-extend services layer (AI entrypoint included)

## Quickstart
1. Install dependencies:
   ```bash
   pip install flask flask_sqlalchemy
   ```
2. Run the application:
   ```bash
   python run.py
   ```
3. Visit http://localhost:5000 to see the landing page.

## Configuration
- Environment detection uses `FLASK_ENV` or `APP_ENV` (production defaults enable secure cookies).
- Override database URI with `DATABASE_URL`; otherwise uses `instance/database.sqlite`.
- Provide a strong `SECRET_KEY` in production.

## Project Layout
```
app/
  __init__.py        # Application factory
  config.py          # Environment-specific settings
  extensions.py      # Shared extensions (SQLAlchemy)
  models/            # ORM models
  routes/            # Blueprints
  services/          # Service layer (AI-ready)
  templates/         # Jinja templates
  static/            # CSS / JS / assets
instance/
  database.sqlite    # SQLite data file
run.py               # Entry point
```

## Future AI Integration
Use the service layer as the single integration point. Approved usage example:
```python
from google import genai
client = genai.Client()
response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="How does AI work?",
)
print(response.text)
```

## Development Notes
- The database is created automatically on startup.
- `/health` endpoint returns a simple JSON status for uptime probes.
- CSS and JS are loaded via the base layout for consistent theming.
