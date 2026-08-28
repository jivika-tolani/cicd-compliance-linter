"""
Sample application file — used to test the CI/CD Compliance & Quality Linter.

This file deliberately mixes GOOD and BAD patterns so you can see the tool
both catch problems and correctly leave clean code alone.
"""

import os

# --- BAD: a hardcoded AWS access key (SEC001) ---
AWS_ACCESS_KEY_ID = "AKIAFAKEKEYFORTESTING12"

# --- BAD: a hardcoded API key (SEC002) ---
STRIPE_API_KEY = "sk_test_51FakeKeyForTestingPurposesOnly99"

# --- BAD: a hardcoded password (SEC002) ---
DB_PASSWORD = "SuperSecretPassword2026"

# --- GOOD: the correct way to handle secrets, using environment variables ---
def get_real_api_key():
    return os.environ.get("REAL_API_KEY")


# --- BAD: an insecure HTTP endpoint (NET001) ---
PAYMENT_GATEWAY_URL = "http://payments.example-company.com/api/charge"

# --- GOOD: a secure HTTPS endpoint ---
SECURE_GATEWAY_URL = "https://payments.example-company.com/api/charge"

# --- GOOD: localhost is allowed, since it's just for local development ---
LOCAL_DEV_SERVER = "http://localhost:5000"


def process_payment(amount):
    """A harmless placeholder function — nothing to flag here."""
    print(f"Processing payment of {amount} via {SECURE_GATEWAY_URL}")
    return True
