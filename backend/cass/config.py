"""CASS configuration."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Phase(str, Enum):
    """CASS operation phases."""
    MAPPING = "mapping"      # Phase 1: Architecture discovery
    REVIEW = "review"        # User reviews knowledge graph
    SCANNING = "scanning"    # Phase 2: Security analysis


class ExplorationStrategy(str, Enum):
    """How the agent prioritizes exploration."""
    BREADTH_FIRST = "breadth_first"      # Map everything shallowly first
    DEPTH_FIRST = "depth_first"          # Follow each path deeply
    SECURITY_FIRST = "security_first"    # Prioritize high-risk areas


class CASSConfig(BaseModel):
    """Configuration for CASS."""

    # Exploration settings
    exploration_strategy: ExplorationStrategy = ExplorationStrategy.SECURITY_FIRST
    max_files_per_pass: int = Field(default=50, ge=1)
    max_depth: int = Field(default=10, ge=1)
    coverage_threshold: float = Field(default=0.8, ge=0.0, le=1.0)

    # Timeouts (seconds)
    mapping_timeout: int = Field(default=600, ge=60)  # 10 min default
    tool_timeout: int = Field(default=30, ge=5)

    # LLM settings
    model: str = "claude-sonnet-4-5-20250929"
    max_tokens_per_reasoning: int = Field(default=4096, ge=256)

    # Framework detection
    auto_detect_frameworks: bool = True
    known_frameworks: list[str] = Field(default_factory=list)

    # File filtering
    include_patterns: list[str] = Field(default_factory=lambda: ["**/*.py", "**/*.js", "**/*.ts", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.rs", "**/*.c", "**/*.cpp"])
    exclude_patterns: list[str] = Field(default_factory=lambda: ["**/node_modules/**", "**/.git/**", "**/vendor/**", "**/dist/**", "**/build/**", "**/__pycache__/**"])

    # Security focus
    prioritize_entry_points: bool = True
    prioritize_auth: bool = True
    prioritize_data_sinks: bool = True
    detect_memory_issues: bool = True
    detect_secrets: bool = True

    # Output
    emit_progress: bool = True
    progress_interval: int = Field(default=5, ge=1)  # seconds


class ScanConfig(BaseModel):
    """Configuration for Phase 2 scanning."""

    # What to scan
    scan_all_paths: bool = False
    min_risk_score: float = Field(default=0.3, ge=0.0, le=1.0)
    vulnerability_types: Optional[list[str]] = None  # None = all

    # Ultrathink integration
    use_ultrathink: bool = True
    ultrathink_min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)

    # Output
    max_findings: int = Field(default=100, ge=1)
    include_low_confidence: bool = False
