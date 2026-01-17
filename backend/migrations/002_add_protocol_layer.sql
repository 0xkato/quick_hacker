-- Migration: Add Protocol-Aware Reportability Layer
-- Date: 2026-01-17
-- Description: Adds protocol evaluation tables and fields

-- Add protocol fields to findings table
ALTER TABLE findings
ADD COLUMN IF NOT EXISTS submission_result JSONB,
ADD COLUMN IF NOT EXISTS evidence_quest_id VARCHAR(64),
ADD COLUMN IF NOT EXISTS evidence_quest_completed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_findings_evidence_quest_id ON findings(evidence_quest_id);

-- Create protocol_policies table
CREATE TABLE IF NOT EXISTS protocol_policies (
    id VARCHAR(64) PRIMARY KEY,
    display_name VARCHAR(128) NOT NULL,
    config JSONB NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create evidence_quests table
CREATE TABLE IF NOT EXISTS evidence_quests (
    id VARCHAR(64) PRIMARY KEY,
    finding_id VARCHAR(64) NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    category VARCHAR(64) NOT NULL,
    quest_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    missing_items JSONB,
    evidence_found JSONB,
    new_checklist_items JSONB,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    success BOOLEAN,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_quests_finding_id ON evidence_quests(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_quests_status ON evidence_quests(status);
