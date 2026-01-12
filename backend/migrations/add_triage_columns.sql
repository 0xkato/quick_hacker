-- Migration: Add triage system columns to findings table and create evidence_blobs table
-- Purpose: Enable deterministic vulnerability triage with proof-based classification
-- Version: 1.0.0
-- Date: 2026-01-12

-- First, check if findings table exists (it should be created as part of this migration if not)
CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    repo_id VARCHAR(64) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER,
    code_snippet TEXT,
    vulnerable_code TEXT,
    vulnerability_type VARCHAR(128) NOT NULL,
    cwe_id VARCHAR(20),
    attack_scenario TEXT,
    proof_of_concept TEXT,
    recommended_fix TEXT,
    confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_trace JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb,
    classification VARCHAR(32),
    config_dependent BOOLEAN DEFAULT FALSE,
    config_flag VARCHAR(128),
    default_secure BOOLEAN,
    contradiction_present BOOLEAN DEFAULT FALSE,
    fix_type VARCHAR(20) DEFAULT 'code',
    classification_reasoning TEXT
);

-- Add triage columns to findings table (using IF NOT EXISTS for idempotency)
DO $$
BEGIN
    -- Add batch_id column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='batch_id') THEN
        ALTER TABLE findings ADD COLUMN batch_id VARCHAR(32);
    END IF;

    -- Add disposition column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='disposition') THEN
        ALTER TABLE findings ADD COLUMN disposition VARCHAR(32);
    END IF;

    -- Add classification_confidence column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='classification_confidence') THEN
        ALTER TABLE findings ADD COLUMN classification_confidence INTEGER CHECK (classification_confidence >= 0 AND classification_confidence <= 100);
    END IF;

    -- Add exploit_confidence column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='exploit_confidence') THEN
        ALTER TABLE findings ADD COLUMN exploit_confidence INTEGER CHECK (exploit_confidence >= 0 AND exploit_confidence <= 100);
    END IF;

    -- Add proof_checklist column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='proof_checklist') THEN
        ALTER TABLE findings ADD COLUMN proof_checklist JSONB;
    END IF;

    -- Add reasoning column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='reasoning') THEN
        ALTER TABLE findings ADD COLUMN reasoning JSONB;
    END IF;

    -- Add triage_policy_version column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='triage_policy_version') THEN
        ALTER TABLE findings ADD COLUMN triage_policy_version VARCHAR(16);
    END IF;

    -- Add triaged_at column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='triaged_at') THEN
        ALTER TABLE findings ADD COLUMN triaged_at TIMESTAMP;
    END IF;

    -- Add category column for normalized vulnerability categories
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='findings' AND column_name='category') THEN
        ALTER TABLE findings ADD COLUMN category VARCHAR(64);
    END IF;
END $$;

-- Create indexes for triage queries (using IF NOT EXISTS for idempotency)
DO $$
BEGIN
    -- Index on batch_id for batch queries
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_findings_batch_id') THEN
        CREATE INDEX idx_findings_batch_id ON findings(batch_id);
    END IF;

    -- Index on disposition for filtering
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_findings_disposition') THEN
        CREATE INDEX idx_findings_disposition ON findings(disposition);
    END IF;

    -- Composite index on agent_id and disposition
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_findings_agent_disposition') THEN
        CREATE INDEX idx_findings_agent_disposition ON findings(agent_id, disposition);
    END IF;

    -- Composite index on agent_id and triaged_at for time-based queries
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_findings_agent_triaged_at') THEN
        CREATE INDEX idx_findings_agent_triaged_at ON findings(agent_id, triaged_at);
    END IF;

    -- Index on agent_id for general agent queries
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_findings_agent_id') THEN
        CREATE INDEX idx_findings_agent_id ON findings(agent_id);
    END IF;
END $$;

-- Create evidence_blobs table
CREATE TABLE IF NOT EXISTS evidence_blobs (
    id VARCHAR(64) PRIMARY KEY,
    finding_id VARCHAR(64) NOT NULL,
    evidence_type VARCHAR(32) NOT NULL,
    file_path VARCHAR(512),
    line_number INTEGER,
    snippet TEXT CHECK (LENGTH(snippet) <= 8192),
    match_type VARCHAR(32),
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT fk_evidence_finding
        FOREIGN KEY (finding_id)
        REFERENCES findings(id)
        ON DELETE CASCADE
);

-- Create index on finding_id for evidence lookups
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_blobs(finding_id);

-- Create index on evidence_type for type-based queries
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_blobs(evidence_type);

-- Comments for documentation
COMMENT ON COLUMN findings.batch_id IS 'Batch identifier for grouping findings triaged together';
COMMENT ON COLUMN findings.disposition IS 'Triage disposition: valid_security_issue, bug, hardening, misconfiguration, by_design, speculative';
COMMENT ON COLUMN findings.classification_confidence IS 'Confidence in classification (0-100)';
COMMENT ON COLUMN findings.exploit_confidence IS 'Confidence in exploitability (0-100), only for valid_security_issue and bug';
COMMENT ON COLUMN findings.proof_checklist IS 'Tri-state proof checklist (A-F items) as JSON';
COMMENT ON COLUMN findings.reasoning IS 'Array of reasoning bullets explaining the disposition';
COMMENT ON COLUMN findings.triage_policy_version IS 'Version of triage policy used for classification';
COMMENT ON COLUMN findings.triaged_at IS 'Timestamp when triage was performed';
COMMENT ON COLUMN findings.category IS 'Normalized vulnerability category (COMMAND_INJECTION, SSRF, etc.)';

COMMENT ON TABLE evidence_blobs IS 'Evidence snippets gathered during triage process';
COMMENT ON COLUMN evidence_blobs.evidence_type IS 'Type of evidence: snippet, source, sink, route, auth, etc.';
COMMENT ON COLUMN evidence_blobs.match_type IS 'Specific match type: source, sink, auth_gate, route_registration, etc.';
COMMENT ON COLUMN evidence_blobs.snippet IS 'Code snippet with context (max 8192 chars)';
