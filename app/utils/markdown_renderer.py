"""Markdown rendering helpers for AI responses."""
from __future__ import annotations

from markdown import markdown


def render_markdown(text: str | None) -> str | None:
    """Convert Markdown text to HTML while handling empty inputs."""
    if not text:
        return None
    return markdown(text, extensions=["extra", "sane_lists"], output_format="html5")
