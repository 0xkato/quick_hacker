"""Tests for WebSocket auth token verification helpers."""

import uuid


def test_verify_ws_token_accepts_legacy_and_jwt_access():
    from middleware import auth
    from services.auth_service import auth_service

    assert hasattr(auth, "verify_ws_token")

    legacy = auth.create_new_session()
    assert auth.verify_ws_token(legacy) is True

    access_token = auth_service.create_access_token(uuid.uuid4(), "testuser")
    assert auth.verify_ws_token(access_token) is True

    refresh_token = auth_service.create_refresh_token(uuid.uuid4())
    assert auth.verify_ws_token(refresh_token) is False

    assert auth.verify_ws_token("not-a-real-token") is False

