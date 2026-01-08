"""Tests for authentication service."""
import pytest
from unittest.mock import AsyncMock, MagicMock
import uuid

from services.auth_service import AuthService


@pytest.fixture
def auth_service():
    return AuthService()


class TestPasswordHashing:
    def test_hash_password(self, auth_service):
        password = "test_password_123"
        hashed = auth_service.hash_password(password)
        assert hashed != password
        assert auth_service.verify_password(password, hashed)

    def test_verify_wrong_password(self, auth_service):
        password = "correct_password"
        hashed = auth_service.hash_password(password)
        assert not auth_service.verify_password("wrong_password", hashed)


class TestJWTTokens:
    def test_create_access_token(self, auth_service):
        user_id = uuid.uuid4()
        token = auth_service.create_access_token(user_id, "testuser")
        assert token is not None
        payload = auth_service.decode_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["username"] == "testuser"
        assert payload["type"] == "access"

    def test_create_refresh_token(self, auth_service):
        user_id = uuid.uuid4()
        token = auth_service.create_refresh_token(user_id)
        payload = auth_service.decode_token(token)
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"

    def test_decode_invalid_token(self, auth_service):
        assert auth_service.decode_token("invalid_token") is None


class TestAPIKeyEncryption:
    def test_encrypt_decrypt_api_key(self, auth_service):
        api_key = "sk-test-1234567890abcdef"
        encrypted = auth_service.encrypt_api_key(api_key)
        assert encrypted != api_key
        decrypted = auth_service.decrypt_api_key(encrypted)
        assert decrypted == api_key

    def test_encrypt_empty_key(self, auth_service):
        assert auth_service.encrypt_api_key("") == ""
        assert auth_service.decrypt_api_key("") == ""
