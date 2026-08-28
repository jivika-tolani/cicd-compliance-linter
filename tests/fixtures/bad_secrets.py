"""
Intentionally BAD fixture file for tests/test_scanner.py.

Every value below is a fabricated, non-functional placeholder used only
to verify that the linter's regex rules fire correctly. None of these
are real, active credentials.
"""

# Rule 1 (SEC001): fabricated AWS-style access key ID
AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"

# Rule 2 (SEC002): generic secret assignment patterns
api_key = "sk_test_fabricated1234567890abcdef"
SECRET = "fabricatedSecretValueNotReal000111"
password = "fabricatedPasswordValue2026!!"

# Rule 2 (SEC002): bearer token in a header string
AUTH_HEADER = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fabricated"

# Rule 4 (NET001): insecure HTTP endpoint (not localhost)
LEGACY_ENDPOINT = "http://internal-api.example.com/v1/data"
