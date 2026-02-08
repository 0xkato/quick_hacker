-- Migration: Add scans table for agent/scan record persistence
-- Date: 2026-02-09
-- Purpose: Persist scan metadata across restarts so completed scans
--          remain visible after app restart (alongside their findings)
-- Note: SQLAlchemy Base.metadata.create_all() in init_db() will also
--       auto-create this table. This file is for documentation and
--       explicit PostgreSQL deployments.

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    repo_id TEXT NOT NULL,
    name TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    status TEXT NOT NULL,
    provider_config JSON NOT NULL DEFAULT '{}',
    scan_tier TEXT,
    time_budget_seconds INTEGER,
    custom_prompt TEXT,
    target_files JSON,
    focus_areas JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    files_analyzed INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_repo_id ON scans(repo_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_repo_status ON scans(repo_id, status);
