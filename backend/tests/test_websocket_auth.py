"""WebSocket authentication handshake tests."""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from main import app
from services.auth_service import auth_service


async def mock_init_db() -> None:
    return None


@pytest.fixture(scope="module")
def client():
    with patch("main.init_db", new=mock_init_db):
        with TestClient(app) as test_client:
            yield test_client


def _make_access_token() -> str:
    return auth_service.create_access_token(uuid.uuid4(), "test-user")


def test_websocket_auth_ok_with_query_token(client: TestClient):
    token = _make_access_token()
    with client.websocket_connect(f"/ws?token={token}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "auth_ok"

        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong["type"] == "pong"


def test_websocket_auth_ok_with_message_handshake(client: TestClient):
    token = _make_access_token()
    with client.websocket_connect("/ws") as ws:
        auth_required = ws.receive_json()
        assert auth_required["type"] == "auth_required"

        ws.send_json({"type": "auth", "token": token})
        msg = ws.receive_json()
        assert msg["type"] == "auth_ok"

        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong["type"] == "pong"
