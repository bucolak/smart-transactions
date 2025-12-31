"""Application-wide extensions registry and engine safeguards."""
from sqlite3 import Connection as SQLite3Connection

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine

# SQLAlchemy instance for database interactions
# Initialized in the application factory to keep the global state clean.
db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover - engine hook
    """Ensure SQLite enforces foreign key constraints for tenant safety."""
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()
