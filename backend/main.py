"""quick_hack - Security Auditing Browser IDE Backend."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from routers import git, files, agents, websocket, projects, flow, auth, call_tree, cache, feature_flags
from routers import settings as settings_router
from routers import chat as chat_router
from routers import graph as graph_router
from routers import session as session_router
from routers import protocol_routes
from routers import findings
from routers import reports
from routers import simple_report
from routers import behavior_tree as behavior_tree_router
from routers import campaigns as campaigns_router
from routers import lanes as lanes_router
from routers import runs as runs_router
from routers import artifacts as artifacts_router
from routers import issues as issues_router
from routers.websocket import set_main_loop
from database import init_db
from database.connection import engine
from database.schema_checker import initialize_triage_availability
from services.settings_service import settings_service
from services.project_service import project_service
from middleware.auth import require_auth
from middleware.request_id import RequestIDMiddleware


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

    # Initialize database
    await init_db()
    print("Database initialized")

    # Check triage system schema availability
    await initialize_triage_availability(engine)
    print("Triage schema compatibility checked")

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

# Request ID middleware - generates/propagates X-Request-ID for log correlation
app.add_middleware(RequestIDMiddleware)

# CORS middleware - explicit methods/headers for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
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
app.include_router(
    call_tree.router,
    prefix="/api",
    tags=["CallTree"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    graph_router.router,
    prefix="/api",
    tags=["Graph"],
    dependencies=[Depends(require_auth)],
)
app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])
app.include_router(auth.router)
app.include_router(
    session_router.router,
    prefix="/api",
    dependencies=[Depends(require_auth)],
)
app.include_router(
    cache.router,
    prefix="/api",
    tags=["Cache"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    feature_flags.router,
    prefix="/api",
    tags=["FeatureFlags"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    protocol_routes.router,
    dependencies=[Depends(require_auth)],
)
app.include_router(
    findings.router,
    dependencies=[Depends(require_auth)],
)
app.include_router(
    reports.router,
    dependencies=[Depends(require_auth)],
)
app.include_router(
    simple_report.router,
    dependencies=[Depends(require_auth)],
)
app.include_router(
    behavior_tree_router.router,
    prefix="/api",
    tags=["BehaviorTree"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    campaigns_router.router,
    prefix="/api/campaigns",
    tags=["Campaigns"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    lanes_router.router,
    prefix="/api/lanes",
    tags=["Lanes"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    runs_router.router,
    prefix="/api/runs",
    tags=["Runs"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    artifacts_router.router,
    prefix="/api/artifacts",
    tags=["Artifacts"],
    dependencies=[Depends(require_auth)],
)
app.include_router(
    issues_router.router,
    prefix="/api/issues",
    tags=["Issues"],
    dependencies=[Depends(require_auth)],
)


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
    )
