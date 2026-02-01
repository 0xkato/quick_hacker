"""Tests for project validation profile integration."""
import pytest
from services.project_service import Project
from models.validation_profile import ValidationProfile, AttackerRole


class TestProjectValidationProfile:
    def test_project_has_validation_profile_field(self):
        project = Project(
            id="test-123",
            name="Test Project",
        )
        assert hasattr(project, "validation_profile")
        assert project.validation_profile is None

    def test_project_with_validation_profile(self):
        profile = ValidationProfile(
            excluded_paths=["test/"],
            attacker_roles={"web": AttackerRole(can_control=["http"])},
        )
        project = Project(
            id="test-123",
            name="Test Project",
            validation_profile=profile.model_dump(),
        )
        assert project.validation_profile is not None
        assert project.validation_profile["excluded_paths"] == ["test/"]

    def test_project_serialization_with_profile(self):
        profile = ValidationProfile(excluded_paths=["tools/"])
        project = Project(
            id="test-123",
            name="Test Project",
            validation_profile=profile.model_dump(),
        )
        data = project.model_dump()
        restored = Project.model_validate(data)
        assert restored.validation_profile["excluded_paths"] == ["tools/"]

    def test_project_get_validation_profile(self):
        profile = ValidationProfile(excluded_paths=["test/"])
        project = Project(
            id="test-123",
            name="Test Project",
            validation_profile=profile.model_dump(),
        )
        retrieved = project.get_validation_profile()
        assert isinstance(retrieved, ValidationProfile)
        assert retrieved.excluded_paths == ["test/"]

    def test_project_get_validation_profile_when_none(self):
        project = Project(id="test-123", name="Test Project")
        retrieved = project.get_validation_profile()
        assert isinstance(retrieved, ValidationProfile)
        assert retrieved.excluded_paths == []
