FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    nodejs \
    npm \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for Claude SDK compatibility
# (SDK refuses --dangerously-skip-permissions when running as root)
RUN groupadd -r appuser && useradd -r -g appuser -m appuser

WORKDIR /app

# Install Python dependencies as root first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Claude CLI globally (needed by claude-agent-sdk)
RUN npm install -g @anthropic-ai/claude-code || true

# Copy application code
COPY . .

# Create required directories and set ownership
RUN mkdir -p repos data data/agent_states /home/appuser/.claude \
    && chown -R appuser:appuser /app /home/appuser

# Copy and setup entrypoint
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set Python path
ENV PYTHONPATH=/app
ENV HOME=/home/appuser

EXPOSE 8000

# Use entrypoint to fix volume permissions then drop to appuser
ENTRYPOINT ["docker-entrypoint.sh"]

# Run with hot reload for development
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
