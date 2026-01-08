"""Tests for CASS configuration."""

import pytest
from cass.config import CASSConfig, ExplorationStrategy, Phase


def test_default_config():
    """Default config should have sensible values."""
    config = CASSConfig()
    assert config.max_files_per_pass > 0
    assert config.max_depth > 0
    assert config.exploration_strategy == ExplorationStrategy.SECURITY_FIRST


def test_coverage_threshold():
    """Coverage threshold controls when mapping completes."""
    config = CASSConfig(coverage_threshold=0.9)
    assert config.coverage_threshold == 0.9


def test_phase_enum():
    """Phases should be defined."""
    assert Phase.MAPPING
    assert Phase.REVIEW
    assert Phase.SCANNING
