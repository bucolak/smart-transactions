"""Centralized Gemini service with tenant-aware logging and resilience."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Set

from flask import current_app

from ..extensions import db
from ..models import AIInteractionLog, AIStatus


def _blocklist_path() -> Path:
    return Path(current_app.instance_path) / "ai_blocklist.json"


def load_ai_blocklist() -> Set[int]:
    path = _blocklist_path()
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
        return {int(item) for item in data}
    except Exception:  # pragma: no cover - defensive
        return set()


def persist_ai_blocklist(blocked: Set[int]) -> None:
    path = _blocklist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sorted(blocked)))
    current_app.config["AI_DISABLED_ORG_IDS"] = blocked


class AIService:
    """Single entry point for Gemini calls with audit logging."""

    def __init__(self) -> None:
        self._client = None

    def _client_instance(self):
        """Lazily create a Gemini client using the approved pattern."""
        if self._client is not None:
            return self._client
        api_key = current_app.config.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("Gemini API key is not configured")
        try:
            from google import genai  # type: ignore

            self._client = genai.Client(api_key=api_key)
            return self._client
        except Exception as exc:  # pragma: no cover - defensive
            current_app.logger.error("Failed to initialize Gemini client: %s", exc)
            raise

    def generate_content(
        self,
        *,
        operation_name: str,
        organization_id: int,
        user_id: Optional[int],
        contents: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a Gemini prompt and persist an AIInteractionLog entry.

        Returns a dictionary with the generated text, the log id, and an error flag when applicable.
        """

        log_entry = AIInteractionLog(
            organization_id=organization_id,
            operation_name=operation_name,
            context=self._serialize_context(context),
            status=AIStatus.PENDING,
            triggered_by_id=user_id,
        )
        db.session.add(log_entry)
        db.session.flush()

        if self._is_org_blocked(organization_id):
            log_entry.mark_result(AIStatus.FAILED, summary="AI access disabled by platform owner", duration_ms=0)
            db.session.commit()
            return {
                "text": "AI features are disabled for this organization by the platform owner.",
                "log_id": log_entry.id,
                "error": True,
            }

        start_time = datetime.utcnow()
        try:
            client = self._client_instance()
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=contents,
            )
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            text = getattr(response, "text", "") or str(response)
            log_entry.mark_result(AIStatus.SUCCESS, summary=text[:4000], duration_ms=duration_ms)
            db.session.commit()
            return {"text": text, "log_id": log_entry.id, "error": False}
        except Exception as exc:  # pragma: no cover - defensive
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            safe_message = "AI is currently unavailable. Please retry shortly."
            log_entry.mark_result(
                AIStatus.FAILED,
                summary=f"{safe_message} Details: {exc}",
                duration_ms=duration_ms,
            )
            db.session.commit()
            return {"text": safe_message, "log_id": log_entry.id, "error": True}

    def _is_org_blocked(self, organization_id: int) -> bool:
        blocked: Set[int] = current_app.config.get("AI_DISABLED_ORG_IDS") or set()
        if not blocked:
            blocked = load_ai_blocklist()
            current_app.config["AI_DISABLED_ORG_IDS"] = blocked
        return organization_id in blocked

    def _serialize_context(self, context: Optional[Dict[str, Any]]) -> str | None:
        """Safely serialize AI context payloads for logging."""
        if not context:
            return None
        try:
            return json.dumps(context, default=str)[:4000]
        except Exception:  # pragma: no cover - defensive
            return str(context)[:4000]


ai_service = AIService()
