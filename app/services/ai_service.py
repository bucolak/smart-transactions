"""Future-facing AI service integration point.

This module centralizes any AI provider wiring to keep the rest of the codebase
clean and dependency-light. When you are ready to enable Google GenAI, the
approved usage pattern is:

from google import genai
client = genai.Client()
response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="How does AI work?",
)
print(response.text)
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class AIService:
    """Container for AI client configuration and future helpers."""

    def __init__(self) -> None:
        self._client_config: Dict[str, Any] = {}

    def configure_google(self, **client_kwargs: Any) -> None:
        """Store configuration values for a future Google GenAI client."""
        self._client_config = {**client_kwargs, "provider": "google-genai"}

    @property
    def client_config(self) -> Optional[Dict[str, Any]]:
        return self._client_config or None


ai_service = AIService()
