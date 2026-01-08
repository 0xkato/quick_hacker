"""Tests for /api/auth/register fallback behavior."""

import uuid
from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
async def test_register_falls_back_to_login_when_user_exists(monkeypatch):
    from routers import auth as auth_router
    from services.auth_service import auth_service

    async def _raise_value_error(*_args, **_kwargs):
        raise ValueError("Email already registered")

    async def _authenticate_user(_db, username: str, password: str):
        if username == "test@example.com" and password == "password123":
            return SimpleNamespace(id=uuid.uuid4(), username="tester", is_active=True)
        return None

    monkeypatch.setattr(auth_service, "create_user", _raise_value_error)
    monkeypatch.setattr(auth_service, "authenticate_user", _authenticate_user)

    request = auth_router.RegisterRequest(
        username="tester",
        email="test@example.com",
        password="password123",
    )

    token_response = await auth_router.register(request, db=object())

    assert token_response.token_type == "bearer"
    assert isinstance(token_response.access_token, str) and token_response.access_token
    assert isinstance(token_response.refresh_token, str) and token_response.refresh_token

