# Local Development Guide

## Quick Start

Start everything (backend + frontend + databases):
```bash
./run-local.sh
```

## Usage Options

### Start Everything
```bash
./run-local.sh
```
- Starts PostgreSQL & Redis via Docker
- Starts backend on http://localhost:8000
- Starts frontend on http://localhost:3000
- Shows live logs from both services

### Backend Only
```bash
./run-local.sh --backend-only
```
- Starts only the backend server
- Useful for API development or testing with external tools

### Frontend Only
```bash
./run-local.sh --frontend-only
```
- Starts only the frontend server
- Assumes backend is already running

### Skip Database Startup
```bash
./run-local.sh --no-db
```
- Assumes databases are already running
- Faster startup for subsequent runs

## Features

✅ **Automated Setup**
- Creates virtual environment and installs dependencies
- Starts databases automatically
- Runs database migrations

✅ **Health Checks**
- Verifies databases are ready before starting services
- Checks that services start successfully

✅ **Live Logs**
- Color-coded output: [BACKEND] in blue, [FRONTEND] in green
- Logs saved to `.logs/` directory for debugging

✅ **Clean Shutdown**
- Ctrl+C stops all services gracefully
- Databases keep running (stop with `docker compose down`)

## URLs

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | Main application UI |
| Backend API | http://localhost:8000 | FastAPI backend |
| API Docs | http://localhost:8000/docs | Swagger/OpenAPI docs |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6380 | Cache/pub-sub |

## Log Files

Logs are saved to `.logs/` directory:
- `.logs/backend.log` - Backend server logs
- `.logs/frontend.log` - Frontend server logs

View logs while running:
```bash
# Backend logs
tail -f .logs/backend.log

# Frontend logs
tail -f .logs/frontend.log
```

## Environment Variables

The script automatically sets:
- `REDIS_URL=redis://localhost:6380`
- `DATABASE_URL=postgresql+asyncpg://quickhack:quickhack_dev@localhost:5432/quickhack`
- `REPOS_DIR=./repos`
- `DATA_DIR=./data`
- `DEBUG=true`

## Troubleshooting

### Port Already in Use
```bash
# Find and kill process on port 8000 (backend)
lsof -ti:8000 | xargs kill -9

# Find and kill process on port 3000 (frontend)
lsof -ti:3000 | xargs kill -9
```

### Database Connection Failed
```bash
# Restart databases
docker compose down
docker compose up -d redis postgres

# Wait a few seconds, then restart services
./run-local.sh
```

### Clean Start
```bash
# Stop everything
docker compose down

# Remove old logs
rm -rf .logs/

# Remove old database data (WARNING: deletes all data)
rm -rf data/postgres/

# Start fresh
./run-local.sh
```

### Dependencies Out of Date
```bash
# Update Python dependencies
cd backend
source venv/bin/activate
pip install -r requirements.txt

# Update Node dependencies
cd ../frontend
npm install
```

## Development Workflow

### 1. First Time Setup
```bash
./run-local.sh
```
Wait for services to start, then visit http://localhost:3000

### 2. Daily Development
```bash
# If databases are already running
./run-local.sh --no-db

# Or just restart everything
./run-local.sh
```

### 3. Backend-Only Development
```bash
./run-local.sh --backend-only
```
Test API at http://localhost:8000/docs

### 4. Frontend-Only Development
```bash
# Terminal 1: Start backend
./run-local.sh --backend-only

# Terminal 2: Start frontend
./run-local.sh --frontend-only
```

## Stopping Services

**Stop Backend + Frontend:**
- Press `Ctrl+C` in the terminal running `run-local.sh`

**Stop Databases:**
```bash
docker compose down
```

**Stop Everything:**
```bash
# Ctrl+C to stop services
# Then:
docker compose down
```

## Manual Startup (Alternative)

If you prefer to run services manually:

### Backend
```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm run dev
```

### Databases
```bash
docker compose up -d redis postgres
```
