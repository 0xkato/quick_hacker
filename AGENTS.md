# Repository Guidelines

## Project Structure & Module Organization
- `backend/`: FastAPI service (`backend/main.py`) exposing REST under `/api/*` and WebSockets under `/ws`.
  - `backend/routers/`: request/response layer (keep endpoints thin).
  - `backend/services/`: business logic, persistence, integrations.
  - `backend/agents/`, `backend/pipelines/`, `backend/prompts/`, `backend/providers/`: agent + LLM orchestration.
  - `backend/data/`, `backend/repos/`: runtime state (SQLite, cloned repos). Avoid committing generated files.
- `frontend/`: Next.js (App Router) UI.
  - `frontend/app/`: routes/layouts, plus `frontend/components/`, `frontend/hooks/`, `frontend/lib/`, `frontend/types/`.

## Build, Test, and Development Commands
- `cp .env.example .env`: local env template (API keys are optional; can also be configured via the Settings UI).
- `docker compose up --build`: run full stack (frontend `http://localhost:3000`, backend `http://localhost:8000`, Ollama `http://localhost:11434`).
- `docker compose down`: stop services (add `-v` to reset volumes/data).
- Frontend:
  - `cd frontend && npm install`
  - `npm run dev` / `npm run build` / `npm run start` / `npm run lint`
- Backend (non-Docker):
  - `cd backend && python -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt && uvicorn main:app --reload --port 8000`
- Quick health check: `curl http://localhost:8000/health`

## Coding Style & Naming Conventions
- TypeScript: `strict` is enabled; prefer typed props and avoid `any`.
- React: components in `PascalCase.tsx`, hooks in `useThing.ts`; keep API helpers in `frontend/lib/`.
- Python: 4-space indentation, type hints where practical, `snake_case` for files/functions; keep heavy logic out of `backend/routers/`.

## Testing Guidelines
No dedicated test suite is currently wired up. For non-trivial changes, include a reproduction script (curl/steps) in the PR and consider adding tests (recommended: `pytest` for `backend/`).

## Commit & Pull Request Guidelines
- Git history isn’t included in this checkout (`.git` missing), so conventions can’t be inferred. Recommended: Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`).
- PRs: describe behavior changes, link issues, include screenshots for UI changes, and call out any `.env`/Docker changes.

## Security & Configuration Tips
- Never commit `.env` files or API keys; keep secrets out of logs.
- Most `/api/*` endpoints require `X-Session-Token`; fetch via `GET /api/auth/token` (localhost-only by default; see `AUTH_BOOTSTRAP_ALLOW_REMOTE`).
- The backend mounts `docker.sock` for sandboxed execution (privileged). Treat this as production-sensitive and harden before deploying.
