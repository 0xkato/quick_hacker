# Seamless Integration - Triage System

## Overview

The triage system integrates seamlessly with your production environment **without requiring immediate migrations**. The system automatically detects database schema compatibility on startup and gracefully degrades if the schema is not present.

## How It Works

### Automatic Schema Detection

On application startup, the backend checks if triage columns exist in the `findings` table:

1. **Schema Available**: Triage system enabled automatically (if `TRIAGE_ENABLED=true`)
2. **Schema Missing**: Triage system disabled automatically, application works as before

### Zero-Downtime Deployment

You can deploy the new code **without running the migration**:

```bash
# Deploy code immediately - system works as before
docker-compose up -d

# Triage will be automatically disabled until you run the migration
# You'll see this in logs:
# "Triage columns missing from findings table... Triage system will be disabled."
```

### Running the Migration (Optional)

When you're ready to enable triage, run the migration:

```bash
# Run the idempotent migration (safe to run multiple times)
psql $DATABASE_URL < backend/migrations/add_triage_columns.sql
```

Then restart the backend to enable triage:

```bash
docker-compose restart backend
# You'll see: "✓ Triage system database schema is available"
```

## Production Safety Guarantees

### 1. Idempotent Migration

The migration uses PostgreSQL's `IF NOT EXISTS` checks:

```sql
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='batch_id') THEN
        ALTER TABLE findings ADD COLUMN batch_id VARCHAR(32);
    END IF;
    -- ... etc for all columns
END $$;
```

✅ Safe to run multiple times
✅ Won't fail if columns already exist
✅ Won't break existing queries

### 2. Graceful Degradation

If schema is missing:

- ✅ Application starts successfully
- ✅ All non-triage features work normally
- ✅ Findings are processed and stored (without triage metadata)
- ✅ Clear warning in logs with migration instructions
- ✅ Triage endpoints return 503 with helpful error message

### 3. Backward Compatibility

All triage columns are:

- ✅ Nullable (`NULL` allowed)
- ✅ Optional in Pydantic models (`Optional[...]`)
- ✅ Have no constraints that would break existing data
- ✅ Only accessed when triage is enabled

### 4. No Breaking Changes

The integration:

- ✅ Never modifies existing finding fields
- ✅ Never changes existing behavior when disabled
- ✅ Never drops or loses findings
- ✅ Never requires code changes to disable

## Deployment Strategies

### Strategy 1: Immediate Migration (Recommended for New Deployments)

```bash
# 1. Deploy code
git pull
docker-compose build

# 2. Run migration
psql $DATABASE_URL < backend/migrations/add_triage_columns.sql

# 3. Start with triage enabled
TRIAGE_ENABLED=true docker-compose up -d
```

### Strategy 2: Delayed Migration (Recommended for Production)

```bash
# 1. Deploy code first (triage disabled automatically)
git pull
docker-compose build
docker-compose up -d

# Verify everything works as before
# Run some agents, check findings

# 2. Run migration during maintenance window
psql $DATABASE_URL < backend/migrations/add_triage_columns.sql

# 3. Restart to enable triage (no code changes needed)
docker-compose restart backend
```

### Strategy 3: Gradual Rollout

```bash
# 1. Deploy code, run migration
psql $DATABASE_URL < backend/migrations/add_triage_columns.sql

# 2. Start with triage disabled
TRIAGE_ENABLED=false docker-compose up -d

# 3. Enable triage via environment variable when ready
TRIAGE_ENABLED=true docker-compose up -d
```

## Verification Steps

### Check Current Schema Status

```bash
# Connect to database
psql $DATABASE_URL

# Check if triage columns exist
SELECT column_name
FROM information_schema.columns
WHERE table_name = 'findings'
AND column_name IN (
    'batch_id', 'disposition', 'classification_confidence',
    'exploit_confidence', 'proof_checklist', 'reasoning',
    'triage_policy_version', 'triaged_at', 'category'
);

# Check if evidence_blobs table exists
SELECT EXISTS (
    SELECT FROM information_schema.tables
    WHERE table_name = 'evidence_blobs'
);
```

### Check Application Logs

```bash
# Look for startup messages
docker-compose logs backend | grep -i triage

# Expected if schema present:
# "✓ Triage system database schema is available"

# Expected if schema missing:
# "✗ Triage system database schema is NOT available. Triage features will be disabled."
```

### Test Triage Status

```bash
# Check health endpoint (add triage status if needed)
curl http://localhost:8000/health

# Try triage endpoint (returns 503 if disabled)
curl -X POST http://localhost:8000/api/agents/{agent_id}/triage \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Expected if schema missing:
# 503: "Triage system not available. Database schema missing."
```

## Troubleshooting

### Issue: "Triage columns missing from findings table"

**Cause**: Migration hasn't been run yet

**Solution**:
```bash
psql $DATABASE_URL < backend/migrations/add_triage_columns.sql
docker-compose restart backend
```

### Issue: "relation 'evidence_blobs' does not exist"

**Cause**: Migration partially ran or was interrupted

**Solution**:
```bash
# Safe to re-run (idempotent)
psql $DATABASE_URL < backend/migrations/add_triage_columns.sql
```

### Issue: "column 'disposition' already exists"

**Cause**: None - migration should handle this gracefully

**Solution**: If you see this error, the migration is missing `IF NOT EXISTS` checks. Contact support.

### Issue: Triage running but no disposition in findings

**Cause**: Migration ran but application needs restart

**Solution**:
```bash
docker-compose restart backend
```

## Environment Variables

All triage settings work whether schema is present or not:

```bash
# Enable/disable triage (independent of schema availability)
TRIAGE_ENABLED=true  # Default: true

# Triage policy version (for schema compatibility tracking)
TRIAGE_POLICY_VERSION=1.0.0  # Default: 1.0.0

# Budget settings
TRIAGE_BATCH_BUDGET_MS=15000  # Default: 15000 (15 seconds)
TRIAGE_PER_FINDING_BUDGET_MS=300  # Default: 300 (300ms)
TRIAGE_MAX_EVIDENCE_BYTES=10000  # Default: 10000
TRIAGE_MAX_SNIPPET_LINES=200  # Default: 200

# Feature toggles
TRIAGE_ENABLE_REDACTION=true  # Default: true
TRIAGE_SHOW_FILTERED_BY_DEFAULT=false  # Default: false
TRIAGE_ALLOW_MANUAL_OVERRIDE=true  # Default: true
```

## Performance Impact

### Without Migration (Triage Disabled)

- **Startup time**: +~50ms (schema check)
- **Agent scan**: No change
- **Memory**: No change
- **Database**: No change

### With Migration (Triage Enabled)

- **Startup time**: +~100ms (schema check + validation)
- **Agent scan**: +~10-30% CPU time for evidence gathering
- **Memory**: +~5-10% for evidence caching
- **Database**: +9 columns + evidence_blobs table (minimal overhead)

## Rollback Plan

If you need to disable triage after enabling:

```bash
# Option 1: Disable via environment variable (keeps schema)
TRIAGE_ENABLED=false docker-compose up -d

# Option 2: Remove schema (not recommended, loses triage data)
psql $DATABASE_URL -c "
DROP TABLE IF EXISTS evidence_blobs CASCADE;
ALTER TABLE findings
  DROP COLUMN IF EXISTS batch_id,
  DROP COLUMN IF EXISTS disposition,
  DROP COLUMN IF EXISTS classification_confidence,
  DROP COLUMN IF EXISTS exploit_confidence,
  DROP COLUMN IF EXISTS proof_checklist,
  DROP COLUMN IF EXISTS reasoning,
  DROP COLUMN IF EXISTS triage_policy_version,
  DROP COLUMN IF EXISTS triaged_at,
  DROP COLUMN IF EXISTS category;
"
docker-compose restart backend
```

## Summary

✅ **Deploy anytime** - code works without migration
✅ **Run migration when ready** - during maintenance window
✅ **Automatic detection** - no manual configuration needed
✅ **Graceful degradation** - clear warnings, no failures
✅ **Idempotent migration** - safe to run multiple times
✅ **No breaking changes** - existing features unaffected
✅ **Easy rollback** - just disable via environment variable

The triage system is designed for **production safety first**.
