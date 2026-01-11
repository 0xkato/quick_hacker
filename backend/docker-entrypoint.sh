#!/bin/bash
set -e

# Fix permissions on mounted volumes (runs as root initially)
chown -R appuser:appuser /app/repos /app/data 2>/dev/null || true

# Create subdirectories with proper ownership
mkdir -p /app/data/agent_states /app/repos
chown -R appuser:appuser /app/data /app/repos

# Drop to non-root user and execute the command
exec gosu appuser "$@"
