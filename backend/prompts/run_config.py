"""
Layer 3: USER PROMPT - Run Configuration Template

This changes per audit run. Contains:
- Repository metadata
- Scope configuration
- First-pass results
- Available tools
- Constraints
"""

import uuid
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class RunConfig:
    """Configuration for a single audit run."""
    repo_root: str
    repo_name: str
    commit_sha: Optional[str] = None
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)

    # Scope
    in_scope_components: list[str] = field(default_factory=list)
    out_of_scope_components: list[str] = field(default_factory=list)
    focus_areas: list[str] = field(default_factory=list)

    # First pass results (if any)
    first_pass_findings: list[dict] = field(default_factory=list)
    first_pass_coverage: dict = field(default_factory=dict)

    # Environment
    default_build_command: Optional[str] = None
    default_run_command: Optional[str] = None
    config_paths: list[str] = field(default_factory=list)

    # Constraints
    non_destructive: bool = True
    network_allowed: bool = False
    audit_jail_path: str = "./audit/"

    # Auto-generated
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


def generate_run_prompt(config: RunConfig) -> str:
    """Generate the layer 3 user prompt from run configuration."""

    # Build scope section
    in_scope = ", ".join(config.in_scope_components) if config.in_scope_components else "all"
    out_scope = ", ".join(config.out_of_scope_components) if config.out_of_scope_components else "none"

    # Build first-pass section
    first_pass_section = ""
    if config.first_pass_findings:
        findings_summary = []
        for f in config.first_pass_findings[:10]:  # Limit to first 10
            findings_summary.append(f"  - {f.get('severity', 'UNKNOWN')}: {f.get('title', 'Untitled')} in {f.get('file_path', 'unknown')}")
        first_pass_section = f"""
FIRST_PASS_RESULTS:
  findings_count: {len(config.first_pass_findings)}
  findings_preview:
{chr(10).join(findings_summary)}
"""

    # Build focus areas section
    focus_section = ""
    if config.focus_areas:
        focus_section = f"""
FOCUS_AREAS:
{chr(10).join(f'  - {area}' for area in config.focus_areas)}
"""

    prompt = f"""
RUN CONFIG
- run_id: {config.run_id}
- timestamp: {config.timestamp}
- repo_root: {config.repo_root}
- repo_name: {config.repo_name}
- commit: {config.commit_sha or 'HEAD'}
- languages: [{', '.join(config.languages)}]
- frameworks: [{', '.join(config.frameworks)}]

SCOPE:
- in_scope_components: [{in_scope}]
- out_of_scope_components: [{out_scope}]
{focus_section}
{first_pass_section}
ENVIRONMENT:
- default_build: {config.default_build_command or 'N/A'}
- default_run: {config.default_run_command or 'N/A'}
- config_paths: {config.config_paths or ['default']}

AVAILABLE_TOOLS:
- list_files(path, extensions?) - List files in directory
- read_file(path) - Read file content
- search_files(pattern) - Regex search across files
- get_file_tree() - Get directory structure
- find_sinks(sink_type) - Find dangerous sinks
- trace_dataflow(source, sink) - Trace data flow
- find_validators(function) - Find validation functions
- check_entrypoints() - Find API entrypoints
- report_finding(finding) - Report validated vulnerability
- log_candidate(candidate) - Log investigation candidate
- update_coverage(component, metrics) - Update coverage matrix

CONSTRAINTS:
- non_destructive_only: {config.non_destructive}
- network_allowed: {config.network_allowed}
- audit_jail: {config.audit_jail_path}

START TASK
Perform the second-pass security review. Re-validate any first-pass items, then conduct sink-first harvesting and deep validation until stop condition is met.

Begin by:
1. Mapping the codebase structure and trust boundaries
2. Identifying entry points and dangerous sinks
3. Creating initial candidate backlog
4. Starting systematic investigation

Log all actions using AUDIT_JSONL format.
"""
    return prompt.strip()


def create_run_config_from_project(
    repo_path: str,
    repo_name: str,
    languages: list[str],
    focus_areas: Optional[list[str]] = None,
    first_pass_findings: Optional[list[dict]] = None,
) -> RunConfig:
    """Create a RunConfig from project metadata."""
    return RunConfig(
        repo_root=repo_path,
        repo_name=repo_name,
        languages=languages,
        focus_areas=focus_areas or [],
        first_pass_findings=first_pass_findings or [],
    )
