-- 004: Add LLM interaction and tool detail persistence
-- Persists observability data so it survives page refreshes and server restarts.

CREATE TABLE IF NOT EXISTS llm_interactions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    interaction_type TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    summary TEXT NOT NULL,
    full_content TEXT NOT NULL,
    messages JSON,
    tools_available JSON,
    tool_calls JSON,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    duration_ms INTEGER,
    model TEXT,
    provider TEXT,
    request_id TEXT,
    subagent TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_interactions_agent_id ON llm_interactions(agent_id);
CREATE INDEX IF NOT EXISTS idx_llm_interactions_agent_ts ON llm_interactions(agent_id, timestamp);

CREATE TABLE IF NOT EXISTS tool_details (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool_name TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    arguments JSON NOT NULL,
    arguments_summary TEXT NOT NULL,
    result_data TEXT,
    result_summary TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    code_context JSON,
    duration_ms INTEGER NOT NULL,
    llm_reasoning TEXT,
    confidence_score REAL,
    subagent TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_details_agent_id ON tool_details(agent_id);
CREATE INDEX IF NOT EXISTS idx_tool_details_agent_ts ON tool_details(agent_id, timestamp);
