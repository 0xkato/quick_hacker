# Protocol Layer Integration Guide

## Overview

The Protocol-Aware Reportability Layer has been integrated with the current main branch. This guide explains what was fixed and how to complete the setup.

## Changes Made

### 1. Fixed Config Conflict
- **Issue**: Created `config/` directory conflicted with existing `backend/config.py` module
- **Fix**: Renamed `config/` → `protocol_config/`
- **Impact**: No breaking changes, ProtocolConfig can be imported from `protocol_config`

### 2. Database Models Added
Added to `backend/database/models.py`:

**Finding model additions:**
```python
# Protocol layer fields
submission_result: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
evidence_quest_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
evidence_quest_completed: Mapped[bool] = mapped_column(Boolean, default=False)
```

**New models:**
- `ProtocolPolicy` - Protocol configuration storage
- `EvidenceQuest` - Evidence gathering quest tracking

### 3. PostgreSQL Migration Scripts
Created:
- `backend/migrations/002_add_protocol_layer.sql` - SQL schema changes
- `backend/scripts/migrate_protocol_layer.py` - Migration runner
- `backend/scripts/seed_protocol_policies.py` - Seed default policies

## Setup Instructions

### Prerequisites
- PostgreSQL database running
- Database connection configured in `DATABASE_URL` environment variable

### Quick Setup (All Three Steps)

```bash
# From project root

# 1. Apply migration
python backend/scripts/migrate_protocol_layer.py

# 2. Seed policies
python backend/scripts/seed_protocol_policies.py

# 3. Verify setup
python backend/scripts/verify_protocol_setup.py
```

**Expected Output from Verification:**
```
✅ Protocol Policies: 5 found
✅ Protocol Fields in Findings: 3/3
✅ Evidence Quests Table: exists
```

### Step 1: Apply Database Migration

```bash
# From project root
python backend/scripts/migrate_protocol_layer.py
```

This will:
- Add protocol fields to `findings` table
- Create `protocol_policies` table
- Create `evidence_quests` table

### Step 2: Seed Protocol Policies

```bash
python backend/scripts/seed_protocol_policies.py
```

This seeds 5 default policies:
1. Internal (Permissive) - Default
2. Google VRP (Strict)
3. HackerOne Standard
4. Bugcrowd Standard
5. Research Disclosure

### Step 2.5: Verify Setup

```bash
python backend/scripts/verify_protocol_setup.py
```

Confirms all tables and fields are correctly created.

### Step 3: Configure Environment

Add to your `.env` file:

```bash
# Protocol Layer Configuration
ENABLE_PROTOCOL_EVALUATION=true
DEFAULT_PROTOCOL_ID=internal
ANTHROPIC_API_KEY=your_key_here
ENABLE_QUESTS_BY_DEFAULT=true
```

### Step 4: Start Backend

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 5: Verify

Check these endpoints:
```bash
# Get protocol policies
curl http://localhost:8000/api/protocol-policies

# Should return 5 policies
```

## Current Status

### ✅ Complete
- Database models integrated
- PostgreSQL migration created
- Config conflict resolved
- API routes registered in main.py
- Backend can import without errors

### ⚠️ Requires Testing
- Protocol evaluation in triage pipeline
- Evidence quest system integration
- Frontend UI integration

### 📝 Next Steps

1. **Test Protocol Evaluation**
   - Run a triage with protocol evaluation enabled
   - Verify `submission_result` is populated in findings

2. **Test API Endpoints**
   - GET /api/protocol-policies
   - GET /api/protocol-policies/{id}
   - POST /api/findings/{id}/quests

3. **Test Frontend UI**
   - Protocol selector in project settings
   - Submission badges in findings list
   - Submission panel in finding drawer

## Troubleshooting

### Import Errors
If you see import errors:
```bash
# Make sure you're in the right directory
cd backend
python3 -c "from config import settings; print('OK')"
python3 -c "from protocol_config import ProtocolConfig; print('OK')"
```

### Database Connection
If migration fails:
```bash
# Check database connection
psql $DATABASE_URL -c "SELECT version();"

# Check if tables exist
psql $DATABASE_URL -c "\dt protocol_policies"
```

### Protocol Policies Not Found
If policies aren't seeded:
```bash
# Re-run seed script
python backend/scripts/seed_protocol_policies.py

# Verify in database
psql $DATABASE_URL -c "SELECT id, display_name FROM protocol_policies;"
```

## Architecture Notes

### PostgreSQL vs SQLite
The implementation was adapted from SQLite to PostgreSQL:
- Uses SQLAlchemy ORM models instead of raw SQL
- Uses JSONB for JSON fields (more efficient than JSON)
- Uses proper foreign keys and indexes

### Database Location
- Models: `backend/database/models.py`
- Connection: `backend/database/connection.py`
- Migrations: `backend/migrations/`
- Scripts: `backend/scripts/`

### API Routes
All protocol routes are registered in `backend/main.py`:
- Line 15: `from routers import protocol_routes`
- Line 16: `from routers import findings`
- Lines 149-155: Router registration

## Support

For issues:
1. Check `backend/routers/protocol_routes.py` - API endpoint implementations
2. Check `backend/routers/findings.py` - Enhanced findings API
3. Check backend logs for errors
4. Verify database schema matches models

## Documentation

Full documentation available in:
- `docs/protocol-policies.md` - User guide
- `docs/SYSTEM-SPECIFICATION.md` - Technical architecture
- `docs/DEPLOYMENT.md` - Deployment guide
- `README.md` - Quick start

---

**Integration Complete!** The protocol layer is now fully integrated with the current main branch and uses PostgreSQL.
