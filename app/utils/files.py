"""File utilities for safe tenant-scoped uploads."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Tuple
from uuid import uuid4

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def allowed_file(filename: str, allowed_extensions: Iterable[str]) -> bool:
    """Return True if filename extension is permitted."""
    ext = _extension(filename)
    return bool(ext) and ext in {ext.lower() for ext in allowed_extensions}


def save_logo_file(
    file_storage: FileStorage,
    org_slug: str,
    upload_folder: os.PathLike[str] | str,
    allowed_extensions: Iterable[str],
) -> Tuple[str | None, str | None]:
    """Persist a logo file into a tenant-scoped directory.

    Returns a tuple of (stored_filename, error_message). stored_filename is suitable for
    later retrieval via the logo serving route.
    """
    if not file_storage or file_storage.filename is None:
        return None, "No file provided."

    filename = secure_filename(file_storage.filename)
    if not filename:
        return None, "Unable to read file name."

    ext = _extension(filename)
    if not allowed_file(filename, allowed_extensions):
        return None, "Unsupported file type for logo upload."

    org_dir = Path(upload_folder) / org_slug
    org_dir.mkdir(parents=True, exist_ok=True)

    stored_name = f"logo-{uuid4().hex}.{ext}"
    destination = org_dir / stored_name
    file_storage.save(destination)
    return stored_name, None
