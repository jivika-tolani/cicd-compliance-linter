"""
A fully clean file — the tool should report zero problems here.
Used to confirm the linter doesn't flag things that are actually fine.
"""

import os


def get_database_url():
    # Correct pattern: read from environment, never hardcode.
    return os.environ.get("DATABASE_URL")


def get_health_check_endpoint():
    # localhost is explicitly safe to use in code.
    return "http://localhost:8080/health"
