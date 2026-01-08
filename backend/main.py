"""quick_hack - Security Auditing Browser IDE Backend."""

import asyncio
import ipaddress
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from routers import git, files, agents, websocket, projects, flow
from routers import settings as settings_router
from routers import chat as chat_router
from routers.websocket import set_main_loop
from services.settings_service import settings_service
from services.project_service import project_service
from middleware.auth import create_new_session, get_session_token, require_auth, verify_session


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup
    print(f"Starting {settings.app_name}...")
    print(f"Repos directory: {settings.repos_dir.absolute()}")
    print(f"Max concurrent agents: {settings.max_concurrent_agents}")

    # Store main event loop for WebSocket broadcasts from agents
    set_main_loop(asyncio.get_running_loop())
    print("Main event loop registered")

    # Initialize services
    await settings_service.initialize()
    print("Settings service initialized")

    await project_service.initialize()
    print("Project service initialized")

    yield

    # Shutdown
    print(f"Shutting down {settings.app_name}...")


app = FastAPI(
    title="quick_hack",
    description="Security Auditing Browser IDE - AI-powered vulnerability detection",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware - explicit methods/headers for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Session-Token"],
)

# Include routers
app.include_router(
    projects.router,
    prefix="/api",
    tags=["Projects"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    git.router,
    prefix="/api/git",
    tags=["Git"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    files.router,
    prefix="/api/files",
    tags=["Files"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    agents.router,
    prefix="/api/agents",
    tags=["Agents"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    settings_router.router,
    prefix="/api",
    tags=["Settings"],
)
app.include_router(
    chat_router.router,
    prefix="/api",
    tags=["Chat"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    flow.router,
    prefix="/api",
    tags=["Flow"],
    dependencies=[Depends(require_auth)],
)
app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "app": settings.app_name,
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
async def health_simple():
    """Simple health check for Docker."""
    return {"status": "ok"}


@app.get("/api/health")
async def health(_: str = Depends(require_auth)):
    """Detailed health check."""
    app_settings = await settings_service.get_settings()
    providers_status = {
        name: "configured" if p.api_key or name == "ollama" else "not configured"
        for name, p in app_settings.providers.items()
    }

    return {
        "status": "healthy",
        "repos_dir": str(settings.repos_dir.absolute()),
        "sandbox_enabled": settings.sandbox_enabled,
        "max_agents": settings.max_concurrent_agents,
        "providers": providers_status,
    }


# === Authentication Endpoints ===

def _require_local_bootstrap(request: Request):
    """Deny remote access to bootstrap auth endpoints by default."""
    if not settings.auth_bootstrap_allow_remote:
        # Avoid proxy bypass: treat forwarded headers as non-local.
        if request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip"):
            raise HTTPException(status_code=403, detail="Auth bootstrap is localhost-only by default")

        client_host = request.client.host if request.client else ""
        try:
            if not ipaddress.ip_address(client_host).is_loopback:
                raise HTTPException(status_code=403, detail="Auth bootstrap is localhost-only by default")
        except ValueError:
            raise HTTPException(status_code=403, detail="Auth bootstrap is localhost-only by default")


@app.get("/api/auth/token")
async def get_auth_token(request: Request):
    """
    Get the master session token for authentication.

    This token is generated on server startup and remains valid for the session.
    Use it in the X-Session-Token header for authenticated endpoints (WebSocket uses ?token=).

    Note: This endpoint is intentionally unauthenticated to allow initial token retrieval.
    By default it is restricted to localhost requests; set AUTH_BOOTSTRAP_ALLOW_REMOTE=true to override
    (not recommended without real authentication/TLS).
    """
    _require_local_bootstrap(request)
    token = get_session_token()
    return {
        "token": token,
        "usage": "Add 'X-Session-Token: <token>' header to requests",
        "note": "Keep this token secure - it grants access to sensitive settings and findings",
    }


@app.post("/api/auth/session")
async def create_session(request: Request):
    """Create a new session token (alternative to master token)."""
    _require_local_bootstrap(request)
    token = create_new_session()
    return {
        "token": token,
        "expires_in": "24 hours",
    }


@app.get("/api/auth/verify")
async def verify_token(request: Request, token: str):
    """Verify if a token is valid."""
    _require_local_bootstrap(request)
    is_valid = verify_session(token)
    return {"valid": is_valid}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )
