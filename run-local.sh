#!/bin/bash
set -e

cd "$(dirname "$0")"
ROOT_DIR="$(pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log files
BACKEND_LOG="$ROOT_DIR/.logs/backend.log"
FRONTEND_LOG="$ROOT_DIR/.logs/frontend.log"
mkdir -p "$ROOT_DIR/.logs"

echo -e "${GREEN}=== Quick Hack Local Development ===${NC}"

# Parse arguments
BACKEND_ONLY=false
FRONTEND_ONLY=false
NO_DB=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --backend-only)
            BACKEND_ONLY=true
            shift
            ;;
        --frontend-only)
            FRONTEND_ONLY=true
            shift
            ;;
        --no-db)
            NO_DB=true
            shift
            ;;
        --help)
            echo "Usage: ./run-local.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --backend-only   Start only the backend server"
            echo "  --frontend-only  Start only the frontend server"
            echo "  --no-db          Skip database startup (assumes already running)"
            echo "  --help           Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Create data directories
echo -e "${BLUE}[Setup] Creating data directories...${NC}"
mkdir -p "$ROOT_DIR/repos" "$ROOT_DIR/data/agent_states"

# Start databases with Docker
if [ "$NO_DB" = false ] && [ "$FRONTEND_ONLY" = false ]; then
    echo -e "${BLUE}[1/4] Starting databases (Redis + PostgreSQL)...${NC}"
    docker compose up -d --pull never redis postgres

    # Wait for databases to be ready
    echo "Waiting for databases to be ready..."
    sleep 3

    # Health check for PostgreSQL
    echo -n "Checking PostgreSQL... "
    for i in {1..10}; do
        if docker compose exec -T postgres pg_isready -U quickhack >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
            break
        fi
        if [ $i -eq 10 ]; then
            echo -e "${RED}✗ Failed to connect${NC}"
            exit 1
        fi
        sleep 1
    done

    # Health check for Redis
    echo -n "Checking Redis... "
    if docker compose exec -T redis redis-cli ping >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Failed to connect${NC}"
        exit 1
    fi
fi

# Backend setup
if [ "$FRONTEND_ONLY" = false ]; then
    echo -e "${BLUE}[2/4] Setting up backend...${NC}"
    cd "$ROOT_DIR/backend"

    if [ ! -d "venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv venv
    fi

    source venv/bin/activate
    echo "Installing Python dependencies..."
    pip install -q -r requirements.txt

    # Run database migrations if needed
    if [ -f "alembic.ini" ]; then
        echo "Running database migrations..."
        alembic upgrade head 2>/dev/null || echo "No migrations to run"
    fi
fi

# Frontend setup
if [ "$BACKEND_ONLY" = false ]; then
    echo -e "${BLUE}[3/4] Setting up frontend...${NC}"
    cd "$ROOT_DIR/frontend"
    if [ ! -d "node_modules" ]; then
        echo "Installing npm dependencies..."
        npm install
    fi
fi

# Export environment variables
export REDIS_URL=redis://localhost:6380
export DATABASE_URL=postgresql+asyncpg://quickhack:quickhack_dev@localhost:5432/quickhack
export REPOS_DIR="$ROOT_DIR/repos"
export DATA_DIR="$ROOT_DIR/data"
export DEBUG=true

# Start services
echo -e "${BLUE}[4/4] Starting services...${NC}"
cd "$ROOT_DIR"

BACKEND_PID=""
FRONTEND_PID=""
FUZZ_WORKER_PID=""
PACKAGE_WORKER_PID=""
REPLAY_WORKER_PID=""

# Start backend
if [ "$FRONTEND_ONLY" = false ]; then
    echo "Starting backend on http://localhost:8000..."
    cd "$ROOT_DIR/backend"
    source venv/bin/activate

    # Clear old log
    > "$BACKEND_LOG"

    # Start backend with output to log file
    uvicorn main:app --reload --port 8000 > "$BACKEND_LOG" 2>&1 &
    BACKEND_PID=$!

    # Wait a moment and check if it started
    sleep 2
    if ! ps -p $BACKEND_PID > /dev/null; then
        echo -e "${RED}✗ Backend failed to start. Check $BACKEND_LOG${NC}"
        tail -n 20 "$BACKEND_LOG"
        exit 1
    fi
    echo -e "${GREEN}✓ Backend started (PID: $BACKEND_PID)${NC}"

    # Start Dramatiq workers
    echo "Starting Dramatiq workers..."

    # Start fuzz worker
    python -m dramatiq execution.workers.fuzz_worker_actor > "$ROOT_DIR/.logs/worker-fuzz.log" 2>&1 &
    FUZZ_WORKER_PID=$!
    echo -e "${GREEN}✓ Fuzz worker started (PID: $FUZZ_WORKER_PID)${NC}"

    # Start package worker
    python -m dramatiq execution.workers.package_worker > "$ROOT_DIR/.logs/worker-package.log" 2>&1 &
    PACKAGE_WORKER_PID=$!
    echo -e "${GREEN}✓ Package worker started (PID: $PACKAGE_WORKER_PID)${NC}"

    # Start replay worker
    python -m dramatiq execution.workers.replay_worker > "$ROOT_DIR/.logs/worker-replay.log" 2>&1 &
    REPLAY_WORKER_PID=$!
    echo -e "${GREEN}✓ Replay worker started (PID: $REPLAY_WORKER_PID)${NC}"
fi

# Start frontend
if [ "$BACKEND_ONLY" = false ]; then
    echo "Starting frontend on http://localhost:3000..."
    cd "$ROOT_DIR/frontend"

    # Clear old log
    > "$FRONTEND_LOG"

    # Start frontend with output to log file
    npm run dev > "$FRONTEND_LOG" 2>&1 &
    FRONTEND_PID=$!

    # Wait a moment and check if it started
    sleep 3
    if ! ps -p $FRONTEND_PID > /dev/null; then
        echo -e "${RED}✗ Frontend failed to start. Check $FRONTEND_LOG${NC}"
        tail -n 20 "$FRONTEND_LOG"
        exit 1
    fi
    echo -e "${GREEN}✓ Frontend started (PID: $FRONTEND_PID)${NC}"
fi

# Function to show logs with color coding
show_logs() {
    if [ "$FRONTEND_ONLY" = false ] && [ -n "$BACKEND_PID" ]; then
        tail -f "$BACKEND_LOG" | sed "s/^/[${BLUE}BACKEND${NC}] /" &
        BACKEND_TAIL_PID=$!
    fi

    if [ "$BACKEND_ONLY" = false ] && [ -n "$FRONTEND_PID" ]; then
        tail -f "$FRONTEND_LOG" | sed "s/^/[${GREEN}FRONTEND${NC}] /" &
        FRONTEND_TAIL_PID=$!
    fi

    if [ -n "$FUZZ_WORKER_PID" ]; then
        tail -f "$ROOT_DIR/.logs/worker-fuzz.log" | sed "s/^/[${YELLOW}FUZZ${NC}] /" &
        FUZZ_TAIL_PID=$!
    fi
    if [ -n "$PACKAGE_WORKER_PID" ]; then
        tail -f "$ROOT_DIR/.logs/worker-package.log" | sed "s/^/[${YELLOW}PKG${NC}] /" &
        PACKAGE_TAIL_PID=$!
    fi
    if [ -n "$REPLAY_WORKER_PID" ]; then
        tail -f "$ROOT_DIR/.logs/worker-replay.log" | sed "s/^/[${YELLOW}REPLAY${NC}] /" &
        REPLAY_TAIL_PID=$!
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"

    # Kill tail processes
    [ -n "$BACKEND_TAIL_PID" ] && kill $BACKEND_TAIL_PID 2>/dev/null || true
    [ -n "$FRONTEND_TAIL_PID" ] && kill $FRONTEND_TAIL_PID 2>/dev/null || true
    [ -n "$FUZZ_TAIL_PID" ] && kill $FUZZ_TAIL_PID 2>/dev/null || true
    [ -n "$PACKAGE_TAIL_PID" ] && kill $PACKAGE_TAIL_PID 2>/dev/null || true
    [ -n "$REPLAY_TAIL_PID" ] && kill $REPLAY_TAIL_PID 2>/dev/null || true

    # Kill worker processes
    if [ -n "$FUZZ_WORKER_PID" ]; then
        echo "Stopping fuzz worker..."
        kill $FUZZ_WORKER_PID 2>/dev/null || true
        wait $FUZZ_WORKER_PID 2>/dev/null || true
    fi
    if [ -n "$PACKAGE_WORKER_PID" ]; then
        echo "Stopping package worker..."
        kill $PACKAGE_WORKER_PID 2>/dev/null || true
        wait $PACKAGE_WORKER_PID 2>/dev/null || true
    fi
    if [ -n "$REPLAY_WORKER_PID" ]; then
        echo "Stopping replay worker..."
        kill $REPLAY_WORKER_PID 2>/dev/null || true
        wait $REPLAY_WORKER_PID 2>/dev/null || true
    fi

    # Kill service processes
    if [ -n "$BACKEND_PID" ]; then
        echo "Stopping backend..."
        kill $BACKEND_PID 2>/dev/null || true
        wait $BACKEND_PID 2>/dev/null || true
    fi

    if [ -n "$FRONTEND_PID" ]; then
        echo "Stopping frontend..."
        kill $FRONTEND_PID 2>/dev/null || true
        wait $FRONTEND_PID 2>/dev/null || true
    fi

    echo -e "${GREEN}Services stopped.${NC}"
    echo "Databases still running. Run 'docker compose down' to stop them."
    echo "Logs saved in .logs/ directory"
}

trap cleanup EXIT INT TERM

echo ""
echo -e "${GREEN}=== Services Running ===${NC}"
if [ "$FRONTEND_ONLY" = false ]; then
    echo -e "${BLUE}Backend:${NC}  http://localhost:8000"
    echo -e "          Docs: http://localhost:8000/docs"
    echo -e "          Log:  $BACKEND_LOG"
fi
if [ "$BACKEND_ONLY" = false ]; then
    echo -e "${GREEN}Frontend:${NC} http://localhost:3000"
    echo -e "          Log:  $FRONTEND_LOG"
fi
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all services${NC}"
echo ""
echo "Showing logs (Ctrl+C to stop):"
echo "---"

# Show logs in real-time with color coding
show_logs

# Wait for processes
if [ -n "$BACKEND_PID" ]; then
    wait $BACKEND_PID
fi
if [ -n "$FRONTEND_PID" ]; then
    wait $FRONTEND_PID
fi
