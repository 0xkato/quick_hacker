# Protocol Layer Deployment Guide

## Pre-Deployment Checklist

- [ ] All unit tests pass (`pytest backend/tests/ -v`)
- [ ] Migration tested on copy of production database
- [ ] .env file configured with ANTHROPIC_API_KEY
- [ ] Backup of production database created

## Deployment Steps

### 1. Backup Database

```bash
cp backend/data/quickhack.db backend/data/quickhack.db.backup.$(date +%Y%m%d)
```

### 2. Run Migration

```bash
python backend/scripts/migrate_to_protocol_layer.py
```

Verify:
```bash
sqlite3 backend/data/quickhack.db "SELECT id, display_name FROM protocol_policies;"
```

Expected: 5 policies listed

### 3. Configure Environment

Create `.env` file with:
```bash
ENABLE_PROTOCOL_EVALUATION=true
DEFAULT_PROTOCOL_ID=internal
ANTHROPIC_API_KEY=your_actual_key_here
ENABLE_QUESTS_BY_DEFAULT=true
```

### 4. Restart Server

```bash
# Stop existing server
pkill -f "uvicorn backend.main"

# Start with new code
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Verify Deployment

**Check API endpoints:**
```bash
# Get policies
curl http://localhost:8000/api/protocol-policies

# Get findings with submission filter
curl http://localhost:8000/api/findings?project_id=test&submission_decision=submit
```

**Check UI:**
- Open project settings → verify protocol selector visible
- View finding → verify Submission tab appears
- Check that submission badges appear in findings list

### 6. Monitor

Watch logs for:
- Protocol evaluation errors
- Quest failures
- Database errors

```bash
tail -f logs/quickhack.log | grep -i protocol
```

## Rollback Plan

If issues occur:

### 1. Disable Protocol Evaluation

Set in `.env`:
```bash
ENABLE_PROTOCOL_EVALUATION=false
```

Restart server. Findings will continue to work without protocol evaluation.

### 2. Restore Database

```bash
cp backend/data/quickhack.db.backup.YYYYMMDD backend/data/quickhack.db
```

Restart server.

## Post-Deployment Verification

- [ ] Protocol policies loaded (check /api/protocol-policies)
- [ ] Existing findings still display correctly
- [ ] New findings get submission_result populated
- [ ] Quest triggering works (manually test on a finding)
- [ ] No errors in server logs

## Known Issues

- Quest LLM calls may timeout on slow connections (increase QUEST_TIMEOUT_SECONDS)
- SQLite JSON indexing performance: OK for <10K findings, consider PostgreSQL for larger
- Quest playbooks simplified for MVP (no full LLM tool integration yet)

## Monitoring Metrics

Track:
- Protocol evaluation errors (should be <1%)
- Quest success rate (target >60%)
- Disposition override rate (expect 10-20%)
- Submission decision distribution

Query for metrics:
```sql
-- Submission decisions
SELECT
  json_extract(submission_result, '$.decision') as decision,
  COUNT(*) as count
FROM findings
WHERE submission_result IS NOT NULL
GROUP BY decision;

-- Quest success rate
SELECT
  success,
  COUNT(*) as count
FROM evidence_quests
GROUP BY success;
```
