-- 005: Add behavior tree node persistence
-- Persists behavior tree so it survives page refreshes and server restarts.

CREATE TABLE IF NOT EXISTS bt_nodes (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    parent_id TEXT,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    data JSON,
    children_count INTEGER DEFAULT 0,
    depth INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bt_nodes_agent_id ON bt_nodes(agent_id);
CREATE INDEX IF NOT EXISTS idx_bt_nodes_agent_ts ON bt_nodes(agent_id, timestamp);
