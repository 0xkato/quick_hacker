-- Migration: Initial schema for QuickHack
-- Date: 2026-01-17
-- Purpose: Basic tables for testing protocol layer migration

-- Create projects table (minimal for testing)
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create findings table (core fields only)
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    repo_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER,
    code_snippet TEXT,
    vulnerable_code TEXT,
    vulnerability_type TEXT NOT NULL,
    cwe_id TEXT,
    attack_scenario TEXT,
    proof_of_concept TEXT,
    recommended_fix TEXT,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_trace JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSON DEFAULT '{}',
    classification TEXT,
    config_dependent BOOLEAN DEFAULT FALSE,
    config_flag TEXT,
    default_secure BOOLEAN,
    contradiction_present BOOLEAN DEFAULT FALSE,
    fix_type TEXT DEFAULT 'code',
    classification_reasoning TEXT,
    batch_id TEXT,
    disposition TEXT,
    classification_confidence INTEGER CHECK (classification_confidence >= 0 AND classification_confidence <= 100),
    exploit_confidence INTEGER CHECK (exploit_confidence >= 0 AND exploit_confidence <= 100),
    proof_checklist JSON,
    reasoning JSON,
    triage_policy_version TEXT,
    triaged_at TIMESTAMP,
    category TEXT
);

-- Create indexes
CREATE INDEX idx_findings_agent_id ON findings(agent_id);
CREATE INDEX idx_findings_batch_id ON findings(batch_id);
CREATE INDEX idx_findings_disposition ON findings(disposition);
CREATE INDEX idx_findings_agent_disposition ON findings(agent_id, disposition);
CREATE INDEX idx_findings_agent_triaged_at ON findings(agent_id, triaged_at);

-- Create evidence_blobs table
CREATE TABLE IF NOT EXISTS evidence_blobs (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER,
    snippet TEXT,
    match_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX idx_evidence_finding_id ON evidence_blobs(finding_id);
CREATE INDEX idx_evidence_type ON evidence_blobs(evidence_type);
