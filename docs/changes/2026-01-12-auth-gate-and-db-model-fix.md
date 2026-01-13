# 2026-01-12 — Auth Gate + DB Model Fix

## Summary

Two issues were addressed:

1. **Unauthenticated users could reach the Projects/clone UI** at `http://localhost:3000` even though the backend requires auth for `/api/projects/*`.
2. **Backend startup could crash** on import/mapping because SQLAlchemy reserves the attribute name `metadata` for Declarative models.

## Frontend (Auth Gate)

Goal: users should not be able to see or use project/clone functionality unless authenticated.

Changes:

- `frontend/app/page.tsx`
  - Adds an **auth gate**: if unauthenticated, render a dedicated auth screen instead of the app shell.
  - Loads `/api/projects/status` **only after authentication** (prevents noisy 401s and avoids showing project UI while logged out).
  - Connects WebSockets **only when authenticated** (JWT token available).
  - Logout now **exits the active project first** (calls `/api/projects/exit`) before clearing tokens, to avoid stale “in project” state.
- `frontend/components/Auth/AuthScreen.tsx`
  - New full-page login/register screen used by the auth gate.
- `frontend/playwright.smoke.spec.ts`
  - Updated to self-register a throwaway user if the auth screen is shown, then continue the clone/call-tree flow.

## Backend (SQLAlchemy reserved attribute fix)

Root cause: `Finding` declared a mapped attribute named `metadata`, which SQLAlchemy forbids for Declarative models (`InvalidRequestError: Attribute name 'metadata' is reserved`).

Changes:

- `backend/database/models.py`
  - Renames the mapped attribute to `metadata_` while keeping the database column name as `"metadata"`.
  - No schema migration required (column name stays the same).
- `backend/config.py`
  - Adds `database_url` (reads `DATABASE_URL` from `.env` / environment) so DB config is consistent with the rest of settings.
  - Loads `.env` from repo root when running from `backend/` (and falls back to `backend/.env` if present).
- `backend/database/connection.py`
  - Uses `settings.database_url` instead of a hardcoded default so `.env` `DATABASE_URL` actually takes effect.
  - Wraps connection failures with a clearer error message (e.g., “start Postgres with `docker compose up -d postgres`”).
- `backend/tests/test_database_models.py`
  - Regression test ensures `database.models` is importable and `Finding` maps `"metadata"` → `metadata_`.

## Verification

Frontend:

1. Open `http://localhost:3000` in an incognito window.
2. Expected: you see the login/register screen, **not** the Projects/clone UI.
3. Register and/or login.
4. Expected: the Projects screen is available, and cloning works normally.

Backend:

- `pytest -q backend/tests/test_database_models.py`

## Notes / Follow-ups

- Local dev still requires Postgres running for auth-backed APIs (see `README.md` “Local Development” and `docker-compose.yml`).
