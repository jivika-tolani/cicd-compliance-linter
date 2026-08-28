"""A deliberately clean fixture file — the scanner should report zero findings on this file."""

import os


def get_api_key() -> str:
    """Correct pattern: read the secret from the environment, never hardcode it."""
    return os.environ["API_KEY"]


def fetch_data(base_url: str = "https://api.example.com/v1/resource") -> dict:
    """Uses HTTPS and takes the endpoint as a parameter rather than hardcoding it."""
    return {"url": base_url}


def health_check(host: str = "http://localhost:8000/health") -> str:
    """localhost is explicitly excluded from the insecure-HTTP rule."""
    return host
