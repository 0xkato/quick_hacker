"""Enums for the campaign platform data model.

All enums inherit from (str, Enum) so their values serialize naturally
as strings in Pydantic models and SQLAlchemy columns.
"""

from enum import Enum


class CampaignStatus(str, Enum):
    CREATED = "created"
    PLANNING = "planning"
    EXTRACTING = "extracting"
    COMPILING = "compiling"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CampaignPreset(str, Enum):
    QUICK = "quick"
    MEDIUM = "medium"
    ADVANCED = "advanced"
    PRO = "pro"
    ULTRA = "ultra"
    EVIL = "evil"


class TargetKind(str, Enum):
    API_ROUTE = "api_route"
    PARSER = "parser"
    WORKFLOW = "workflow"
    BROWSER = "browser"
    CLI = "cli"
    MESSAGE_CONSUMER = "message_consumer"
    NATIVE_FUNCTION = "native_function"


class LaneSpecStatus(str, Enum):
    """Status of a lane specification. No 'running' -- that belongs to RunLaneStatus."""

    PLANNED = "planned"
    COMPILED = "compiled"
    VALIDATED = "validated"
    RETIRED = "retired"


class RunLaneStatus(str, Enum):
    """Status of a lane run. No 'retired' -- that belongs to LaneSpecStatus."""

    QUEUED = "queued"
    RUNNING = "running"
    STALLED = "stalled"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"


class RunnerJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"


class ArtifactType(str, Enum):
    CRASH = "crash"
    HANG = "hang"
    ORACLE_HIT = "oracle_hit"
    DIFFERENTIAL_FAILURE = "differential_failure"


class ArtifactClassification(str, Enum):
    ISSUE_CANDIDATE = "issue_candidate"
    HARNESS_ARTIFACT = "harness_artifact"
    FLAKY_UNCONFIRMED = "flaky_unconfirmed"


class AnalysisOutcome(str, Enum):
    BY_DESIGN = "by_design"
    RESEARCH_LEAD = "research_lead"
    NONE = "none"


class IssueDisposition(str, Enum):
    CONFIRMED_SECURITY_ISSUE = "confirmed_security_issue"
    CONFIRMED_NON_SECURITY_BUG = "confirmed_non_security_bug"
    HARDENING_OBSERVATION = "hardening_observation"


class IssueSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResourceProfile(str, Enum):
    LIGHT = "light"
    MEDIUM = "medium"
    HEAVY = "heavy"


class StructureModel(str, Enum):
    SCHEMA = "schema"
    STATE_MACHINE = "state_machine"
    GRAMMAR = "grammar"
    RAW = "raw"
    TYPED = "typed"


class InputProducer(str, Enum):
    MUTATION = "mutation"
    GENERATION = "generation"
    HYBRID = "hybrid"


class FeedbackModel(str, Enum):
    API_SURFACE = "api_surface"
    STATE_DEPTH = "state_depth"
    DIRECTED = "directed"
    DIFFERENTIAL = "differential"
