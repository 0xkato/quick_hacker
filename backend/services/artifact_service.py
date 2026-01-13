"""
Artifact Service - Manages investigation artifacts.

Provides content-hash deduplicated artifact storage and provenance tracking.
"""

from typing import Optional
from models.investigation_trace import Artifact, ArtifactType


class ArtifactService:
    """
    Manages investigation artifacts with content-hash deduplication.

    Artifacts are stored globally by artifact_id (content hash).
    """

    def __init__(self):
        # artifact_id -> Artifact (global deduplication)
        self._artifacts: dict[str, Artifact] = {}

    def create_artifact(
        self,
        artifact_id: str,
        artifact_type: ArtifactType,
        content: str | dict,
        summary: str,
        file_path: Optional[str] = None,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None
    ) -> Artifact:
        """
        Create or retrieve artifact (content-hash deduplication).

        If artifact_id already exists, returns existing artifact.
        This enables deduplication: same content → same artifact.

        Args:
            artifact_id: Content-hash ID (from generate_artifact_id)
            artifact_type: Type of artifact
            content: Artifact content
            summary: Human-readable summary (max 200 chars)
            file_path: Optional file reference
            line_start: Optional line start
            line_end: Optional line end

        Returns:
            Artifact (existing or newly created)
        """
        # Deduplication: return existing if present
        if artifact_id in self._artifacts:
            return self._artifacts[artifact_id]

        # Create new artifact
        artifact = Artifact(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            content=content,
            summary=summary,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end
        )

        self._artifacts[artifact_id] = artifact
        return artifact

    def get_artifact(self, artifact_id: str) -> Optional[Artifact]:
        """Get artifact by ID"""
        return self._artifacts.get(artifact_id)

    def get_all_artifacts(self) -> list[Artifact]:
        """Get all artifacts"""
        return list(self._artifacts.values())

    def get_artifacts_by_type(self, artifact_type: ArtifactType) -> list[Artifact]:
        """Get all artifacts of a specific type"""
        return [
            artifact for artifact in self._artifacts.values()
            if artifact.artifact_type == artifact_type
        ]

    def clear_artifacts(self) -> None:
        """Clear all artifacts"""
        self._artifacts.clear()

    def add_producer(self, span_id: str, artifact_id: str) -> bool:
        """
        Add a producer span for an artifact.

        Args:
            span_id: Span that produced this artifact
            artifact_id: Artifact ID

        Returns:
            True if successful, False if artifact not found
        """
        artifact = self.get_artifact(artifact_id)
        if not artifact:
            return False

        artifact.producer_spans.add(span_id)
        return True

    def add_consumer(self, span_id: str, artifact_id: str) -> bool:
        """
        Add a consumer span for an artifact.

        Args:
            span_id: Span that consumed this artifact
            artifact_id: Artifact ID

        Returns:
            True if successful, False if artifact not found
        """
        artifact = self.get_artifact(artifact_id)
        if not artifact:
            return False

        artifact.consumer_spans.add(span_id)
        return True

    def get_artifacts_by_producer(self, span_id: str) -> list[Artifact]:
        """Get all artifacts produced by a specific span"""
        return [
            artifact for artifact in self._artifacts.values()
            if span_id in artifact.producer_spans
        ]

    def get_artifacts_by_consumer(self, span_id: str) -> list[Artifact]:
        """Get all artifacts consumed by a specific span"""
        return [
            artifact for artifact in self._artifacts.values()
            if span_id in artifact.consumer_spans
        ]


# Global instance
artifact_service = ArtifactService()
