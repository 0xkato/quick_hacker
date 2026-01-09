from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from tests.fixtures.generate_fastapi_repo import ensure_fastapi_fixture_repo


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip docker-stack e2e tests unless explicitly enabled."""
    if os.environ.get("RUN_E2E") == "1":
        return

    marker = pytest.mark.skip(reason="e2e tests are disabled by default (set RUN_E2E=1)")
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(marker)


@dataclass(frozen=True)
class StackConfig:
    base_url: str
    ws_url: str
    fixture_clone_url: str


@pytest.fixture(scope="session")
def stack_config() -> StackConfig:
    base_url = os.environ.get("E2E_BASE_URL", "http://localhost:8000").rstrip("/")

    ws_url = os.environ.get("E2E_WS_URL")
    if not ws_url:
        ws_url = "ws://" + base_url.removeprefix("http://").removeprefix("https://") + "/ws"
    ws_url = ws_url.rstrip("/")

    # Create the fixture repo on the host so the backend container can access it via the bind mount.
    tests_dir = Path(__file__).resolve().parents[1]
    fixture_repo_path = tests_dir / "fixtures" / "generated_fastapi_repo"
    ensure_fastapi_fixture_repo(fixture_repo_path)

    fixture_clone_url = os.environ.get("E2E_FIXTURE_CLONE_URL", "")

    return StackConfig(
        base_url=base_url,
        ws_url=ws_url,
        fixture_clone_url=fixture_clone_url,
    )


@pytest.fixture(scope="session")
def http_client(stack_config: StackConfig) -> httpx.Client:
    return httpx.Client(base_url=stack_config.base_url, timeout=30.0)


@pytest.fixture(scope="session")
def ensure_backend_ready(http_client: httpx.Client) -> None:
    deadline = time.monotonic() + 90
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = http_client.get("/health")
            if response.status_code == 200 and response.json().get("status") == "ok":
                return
        except Exception as exc:  # pragma: no cover - best-effort polling
            last_error = exc
        time.sleep(1)

    raise AssertionError(f"Backend did not become ready in time. Last error: {last_error!r}")


@pytest.fixture(scope="session")
def legacy_token(http_client: httpx.Client, ensure_backend_ready: None) -> str:
    response = http_client.get("/api/auth/token")
    response.raise_for_status()
    token = response.json().get("token") or ""
    assert token, "Expected a non-empty token from /api/auth/token"
    return token


@pytest.fixture(scope="session")
def legacy_headers(legacy_token: str) -> dict[str, str]:
    return {"X-Session-Token": legacy_token}


@pytest.fixture(scope="session")
def fixture_clone_url(http_client: httpx.Client, stack_config: StackConfig, legacy_headers: dict[str, str]) -> str:
    if stack_config.fixture_clone_url:
        return stack_config.fixture_clone_url

    # Best-effort heuristic: when running in docker compose, repos_dir will be under /app.
    try:
        health = http_client.get("/api/health", headers=legacy_headers)
        if health.status_code == 200:
            repos_dir = str(health.json().get("repos_dir") or "")
            if repos_dir.startswith("/app/"):
                return "/app/tests/fixtures/generated_fastapi_repo"
    except Exception:
        pass

    tests_dir = Path(__file__).resolve().parents[1]
    return str((tests_dir / "fixtures" / "generated_fastapi_repo").resolve())

