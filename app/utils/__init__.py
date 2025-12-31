"""Utility helpers for the application."""
from os import getenv


def env_bool(key: str, default: bool = False) -> bool:
    val = getenv(key)
    if val is None:
        return default
    return val.lower() in {"1", "true", "t", "yes", "y"}
