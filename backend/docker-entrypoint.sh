#!/bin/bash
set -e

# Fix permissions on mounted volumes (runs as root initially)
chown -R appuser:appuser /app/repos /app/data /home/appuser/.claude 2>/dev/null || true

# Create subdirectories with proper ownership
mkdir -p /app/data/agent_states /app/repos
chown -R appuser:appuser /app/data /app/repos

# Ensure Claude Code auth directory exists and is writable by appuser
mkdir -p /home/appuser/.claude
chown -R appuser:appuser /home/appuser/.claude

# Drop to non-root user and execute the command
exec gosu appuser "$@"
