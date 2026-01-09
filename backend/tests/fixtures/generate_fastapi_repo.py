from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def ensure_fastapi_fixture_repo(
    repo_path: Path,
    *,
    force_recreate: bool = False,
) -> Path:
    """Create a small FastAPI repo (as a real git repo) for clone/call-tree e2e tests."""
    repo_path = repo_path.resolve()

    if repo_path.exists() and not force_recreate:
        return repo_path

    if repo_path.exists():
        shutil.rmtree(repo_path)

    repo_path.mkdir(parents=True, exist_ok=True)

    (repo_path / "README.md").write_text(
        "# Fixture FastAPI Repo\n\nUsed by quick_hack e2e tests.\n",
        encoding="utf-8",
    )

    (repo_path / "main.py").write_text(
        "\n".join(
            [
                "from fastapi import FastAPI",
                "",
                "from controllers import hello_controller",
                "",
                "app = FastAPI()",
                "",
                "",
                "@app.get('/hello')",
                "def hello():",
                "    return hello_controller()",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (repo_path / "controllers.py").write_text(
        "\n".join(
            [
                "from services import get_greeting",
                "",
                "",
                "def hello_controller():",
                "    greeting = get_greeting()",
                "    return {'message': greeting}",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (repo_path / "services.py").write_text(
        "\n".join(
            [
                "import os",
                "",
                "from data_access import load_user",
                "",
                "",
                "def get_greeting():",
                "    user = load_user()",
                "    suffix = os.getenv('FIXTURE_SUFFIX', 'world')",
                "    return f\"hello {user['name']} {suffix}\"",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (repo_path / "data_access.py").write_text(
        "\n".join(
            [
                "def load_user():",
                "    return {'id': 1, 'name': 'fixture'}",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    _run(["git", "init", "--initial-branch=main"], cwd=repo_path)
    _run(["git", "config", "user.email", "fixture@example.com"], cwd=repo_path)
    _run(["git", "config", "user.name", "Fixture Repo"], cwd=repo_path)
    _run(["git", "add", "."], cwd=repo_path)
    _run(["git", "commit", "-m", "Initial fixture"], cwd=repo_path)

    return repo_path


def _run(args: list[str], *, cwd: Path) -> None:
    subprocess.run(args, cwd=str(cwd), check=True, stdout=subprocess.DEVNULL)

