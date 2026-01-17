-- Migration: Add protocol-aware reportability layer
-- Date: 2026-01-17

-- Add protocol_id to projects
ALTER TABLE projects ADD COLUMN protocol_id TEXT DEFAULT 'internal';

-- Create protocol_policies table
CREATE TABLE IF NOT EXISTS protocol_policies (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    config JSON NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_protocol_policies_default ON protocol_policies(is_default);

-- Add submission fields to findings
ALTER TABLE findings ADD COLUMN submission_result JSON;
ALTER TABLE findings ADD COLUMN evidence_quest_id TEXT;
ALTER TABLE findings ADD COLUMN evidence_quest_completed BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_findings_submission_decision ON findings(
    json_extract(submission_result, '$.decision')
);
CREATE INDEX IF NOT EXISTS idx_findings_quest ON findings(evidence_quest_id);

-- Create evidence_quests table
CREATE TABLE IF NOT EXISTS evidence_quests (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    category TEXT NOT NULL,
    quest_type TEXT NOT NULL,
    status TEXT NOT NULL,
    missing_items JSON,
    evidence_found JSON,
    new_checklist_items JSON,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    success BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_quests_finding ON evidence_quests(finding_id);
CREATE INDEX IF NOT EXISTS idx_quests_status ON evidence_quests(status);
CREATE INDEX IF NOT EXISTS idx_quests_category ON evidence_quests(category);
