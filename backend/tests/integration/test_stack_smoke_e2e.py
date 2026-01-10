from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import pytest
import websockets


pytestmark = pytest.mark.e2e


def test_health_endpoint(http_client: httpx.Client, ensure_backend_ready: None) -> None:
    response = http_client.get("/health")
    assert response.status_code == 200
    assert response.json().get("status") == "ok"


def test_jwt_auth_allows_api_access(
    http_client: httpx.Client,
    auth_headers: dict[str, str],
) -> None:
    unauth = http_client.get("/api/projects/status")
    assert unauth.status_code == 401

    authed = http_client.get("/api/projects/status", headers=auth_headers)
    assert authed.status_code == 200
    assert "in_project" in authed.json()


def test_register_login_me_refresh_flow(http_client: httpx.Client, ensure_backend_ready: None) -> None:
    suffix = uuid.uuid4().hex[:10]
    username = f"tester_{suffix}"
    email = f"{username}@example.com"
    password = "password123!"

    register = http_client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert register.status_code == 200, register.text
    tokens = register.json()
    assert tokens.get("access_token")
    assert tokens.get("refresh_token")

    me = http_client.get("/api/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200
    profile = me.json()
    assert profile.get("username") == username
    assert profile.get("email") == email

    bearer_projects = http_client.get("/api/projects/status", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert bearer_projects.status_code == 200

    refreshed = http_client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200
    new_tokens = refreshed.json()
    assert new_tokens.get("access_token")
    assert new_tokens.get("refresh_token")

    login = http_client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    login_tokens = login.json()
    assert login_tokens.get("access_token")

    # Development-friendly behavior: re-registering with the same creds should behave like login.
    register_again = http_client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert register_again.status_code == 200
    assert register_again.json().get("access_token")


@pytest.mark.asyncio
async def test_websocket_ping_pong_with_jwt_token(stack_config, ensure_backend_ready: None) -> None:
    suffix = uuid.uuid4().hex[:10]
    username = f"ws_{suffix}"
    email = f"{username}@example.com"
    password = "password123!"

    async with httpx.AsyncClient(base_url=stack_config.base_url, timeout=30.0) as client:
        response = await client.post(
            "/api/auth/register",
            json={"username": username, "email": email, "password": password},
        )
        assert response.status_code == 200, response.text
        token = response.json().get("access_token") or ""
        assert token

    ws_url = f"{stack_config.ws_url}?token={token}"
    async with websockets.connect(ws_url) as ws:
        await ws.send(json.dumps({"type": "ping"}))
        raw = await asyncio.wait_for(ws.recv(), timeout=5)
        msg = json.loads(raw)
        assert msg.get("type") == "pong"


def test_project_quick_clone_files_and_calltree(
    http_client: httpx.Client,
    auth_headers: dict[str, str],
    fixture_clone_url: str,
) -> None:
    # Ensure we're not stuck inside a prior project (persistent volumes / local dev).
    http_client.post("/api/projects/exit", headers=auth_headers)

    clone = http_client.post(
        "/api/projects/quick-clone",
        headers=auth_headers,
        json={"url": fixture_clone_url, "force": True, "project_name": f"e2e-{uuid.uuid4().hex[:6]}"},
    )
    assert clone.status_code == 200, clone.text
    project = clone.json()
    project_id = project.get("id")
    assert project_id
    assert project.get("is_cloned") is True

    tree = http_client.get(f"/api/files/{project_id}/tree?max_depth=4", headers=auth_headers)
    assert tree.status_code == 200, tree.text
    tree_json = tree.json()
    assert tree_json.get("type") == "directory"

    main_py = http_client.get(
        f"/api/files/{project_id}/content",
        headers=auth_headers,
        params={"path": "main.py"},
    )
    assert main_py.status_code == 200, main_py.text
    assert "FastAPI" in (main_py.json().get("content") or "")

    routes = http_client.get(f"/api/calltree/{project_id}/routes", headers=auth_headers)
    assert routes.status_code == 200, routes.text
    routes_json = routes.json()
    assert isinstance(routes_json, list)
    assert any(r.get("path") == "/hello" for r in routes_json)

    route_id = next(r["id"] for r in routes_json if r.get("path") == "/hello")
    calltree = http_client.get(
        f"/api/calltree/{project_id}/tree",
        headers=auth_headers,
        params={"route_id": route_id, "max_depth": 6, "max_nodes": 250, "include_external": True},
    )
    assert calltree.status_code == 200, calltree.text
    graph = calltree.json()
    assert isinstance(graph.get("nodes"), list) and len(graph["nodes"]) >= 3
    assert isinstance(graph.get("edges"), list) and len(graph["edges"]) >= 2
    assert any(n.get("type") == "entry_point" for n in graph["nodes"])
    assert any((n.get("label") or "").startswith("hello(") for n in graph["nodes"])
