"""Tests for auth request validation strictness."""


def test_register_request_allows_non_email_formatted_email():
    from routers.auth import RegisterRequest

    # Intentionally not a "real" email; we allow this for local/dev simplicity.
    RegisterRequest(username="testuser", email="a@a", password="12345678")

