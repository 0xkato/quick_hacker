#!/bin/bash
set -e

cd "$(dirname "$0")"
ROOT_DIR="$(pwd)"

echo "=== Quick Hack Local Development ==="

# Create data directories
mkdir -p "$ROOT_DIR/repos" "$ROOT_DIR/data/agent_states"

# Start databases with Docker
echo "[1/4] Starting databases (Redis + PostgreSQL)..."
docker compose up -d redis postgres

# Wait for databases to be ready
echo "Waiting for databases..."
sleep 3

# Backend setup
echo "[2/4] Setting up backend..."
cd "$ROOT_DIR/backend"

if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt

# Frontend setup
echo "[3/4] Setting up frontend..."
cd "$ROOT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

# Start services
echo "[4/4] Starting services..."
cd "$ROOT_DIR"

# Export environment variables
export REDIS_URL=redis://localhost:6380
export DATABASE_URL=postgresql+asyncpg://quickhack:quickhack_dev@localhost:5432/quickhack
export REPOS_DIR="$ROOT_DIR/repos"
export DATA_DIR="$ROOT_DIR/data"
export DEBUG=true

# Start backend in background
echo "Starting backend on http://localhost:8000..."
cd "$ROOT_DIR/backend"
source venv/bin/activate
uvicorn main:app --reload --port 8000 &
BACKEND_PID=$!

# Start frontend in background
echo "Starting frontend on http://localhost:3000..."
cd "$ROOT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!

# Trap to clean up on exit
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "Services stopped. Databases still running (docker compose down to stop)."
}
trap cleanup EXIT

echo ""
echo "=== Services Running ==="
echo "Frontend: http://localhost:3000"
echo "Backend:  http://localhost:8000"
echo "Press Ctrl+C to stop"
echo ""

# Wait for either process to exit
wait
