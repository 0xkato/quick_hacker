# 2026-01-12 — Local “Out-of-Repo” Dependency Audit

## What we checked

Goal: identify whether the app depends on **code/executables outside this repo** on a developer machine (not counting normal `pip`/`npm` libraries vendored into a venv or `node_modules`).

Heuristics used:
- Look for absolute-path imports and `sys.path` manipulation.
- Look for subprocess calls that require host-installed binaries.
- Look for runtime reads/writes outside the repo tree.

## Findings (app source)

### No direct imports of local code outside the repo

No runtime code in `backend/` or `frontend/` adds absolute paths to `sys.path`, imports modules by `/Users/...`, or otherwise depends on “random code on the laptop” outside this repository.

### The backend does invoke external executables (host tools)

These are **not** Python packages; they must exist on the machine (or in the Docker image):

- `rg` (ripgrep)
  - Used via `subprocess.run(["rg", ...])` in `backend/services/evidence_gatherer.py`.
- `git`
  - Used indirectly via GitPython (`backend/services/git_service.py`, `backend/services/project_service.py`).
- `claude` CLI (optional, only for Claude SDK mode)
  - The Docker image installs `@anthropic-ai/claude-code` globally (`backend/Dockerfile`).
  - The SDK path expects `claude setup-token` to be available for auth flows (`backend/services/claude_sdk_orchestrator.py`).

### External services / daemons are required for full functionality

- PostgreSQL (database): configured in `docker-compose.yml` and referenced by `DATABASE_URL`.
- Redis (optional, but enabled in compose): `REDIS_URL`.
- Ollama (optional): `OLLAMA_BASE_URL`.
- Docker daemon/socket (sandbox execution): `/var/run/docker.sock` mount in `docker-compose.yml`.

## Notes about “paths that look out-of-repo”

Some absolute paths can show up inside **runtime artifacts** (e.g., scan reports, cloned repo contents). Those are data generated at runtime, not application source code dependencies.

