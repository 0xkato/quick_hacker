"""Phase 1: Exploration - Context gathering prompt.

Paired with: file_tools, framework_parsers
Output: TechStackContext, EntryPoints, CodeStructure
"""

from typing import Optional, List
from dataclasses import dataclass


@dataclass
class ExplorationPrompt:
    """Exploration phase prompt components."""

    mission: str = """
<exploration_mission>
PHASE 1: EXPLORATION - Map the codebase

YOUR GOAL:
Map the codebase structure, identify technology stack, and locate entry points.
You are NOT finding vulnerabilities - that comes in later phases.
Your job is to gather context efficiently and thoroughly.

WHAT TO COLLECT:

1. TECHNOLOGY STACK
   - Languages (with versions if visible)
   - Frameworks (Django, Flask, Express, Spring, etc.)
   - Key dependencies (from package.json, requirements.txt, pom.xml)

2. CODE STRUCTURE
   - Directory organization
   - Main modules/packages
   - Configuration files location

3. ENTRY POINTS (collect ~20 lines of code context each)
   - API routes (@app.get, router.post, etc.)
   - Form handlers
   - CLI argument parsers
   - File upload handlers
   - WebSocket handlers
   - GraphQL resolvers

4. TRUST BOUNDARIES
   - Auth/authz checkpoints
   - Public vs authenticated routes
   - Admin vs user routes
</exploration_mission>
"""

    tools: str = """
<exploration_tools>
USE THESE TOOLS:

file_tools:
- list_files(path, extensions) - Map directory structure
- read_file(path) - Read file content (use for configs, entry points)
- search_files(pattern) - Find patterns across codebase

framework_parsers:
- detect_framework() - Auto-detect frameworks
- parse_routes() - Extract route definitions

BE EFFICIENT:
- Start broad (directory structure) then narrow
- Read configs first (they reveal architecture)
- Don't read entire files - use line ranges
- Parallelize independent reads
</exploration_tools>
"""

    output: str = """
<exploration_output>
WHEN COMPLETE, OUTPUT:

```json
{
  "tech_stack": {
    "languages": ["python"],
    "frameworks": ["flask"],
    "key_dependencies": ["sqlalchemy", "redis"]
  },
  "structure": {
    "entry_module": "app.py",
    "routers_dir": "routes/",
    "services_dir": "services/",
    "config_files": ["config.py", ".env.example"]
  },
  "entry_points": [
    {
      "name": "login",
      "file": "routes/auth.py",
      "line": 42,
      "method": "POST",
      "route": "/api/login",
      "auth_required": false,
      "code_snippet": "..."
    }
  ],
  "trust_boundaries": [
    {"type": "auth_middleware", "file": "middleware/auth.py", "protects": ["routes/admin/*"]}
  ]
}
```

Signal completion with: "EXPLORATION_COMPLETE"
</exploration_output>
"""

    not_your_job: str = """
<not_your_job>
DO NOT in this phase:
- Report vulnerabilities
- Trace data flows
- Analyze security patterns
- Generate findings

These come in LATER PHASES. Focus on mapping only.
</not_your_job>
"""

    def get_full_prompt(self) -> str:
        return "\n\n".join([
            self.mission.strip(),
            self.tools.strip(),
            self.output.strip(),
            self.not_your_job.strip(),
        ])


def build_exploration_prompt(
    repo_name: str,
    repo_root: Optional[str] = None,
    known_languages: Optional[List[str]] = None,
) -> str:
    """Build complete exploration phase prompt.

    Args:
        repo_name: Repository name
        repo_root: Repository root path
        known_languages: Pre-known languages (optional hint)

    Returns:
        Complete exploration prompt
    """
    base = ExplorationPrompt()
    parts = [base.get_full_prompt()]

    # Add context section
    context_lines = ["=== REPOSITORY CONTEXT ===", f"Name: {repo_name}"]
    if repo_root:
        context_lines.append(f"Root: {repo_root}")
    if known_languages:
        context_lines.append(f"Known languages: {', '.join(known_languages)}")
    context_lines.append("")

    parts.insert(0, "\n".join(context_lines))

    return "\n\n".join(parts)
