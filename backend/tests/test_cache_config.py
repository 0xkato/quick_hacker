# backend/tests/test_cache_config.py
import pytest
from pydantic import ValidationError
from config import Settings
import os


class TestCacheConfiguration:
    """Test cache configuration settings and validation."""

    def test_cache_enabled_default_true(self):
        settings = Settings()
        assert settings.tool_cache_enabled is True

    def test_cache_max_size_default(self):
        settings = Settings()
        assert settings.tool_cache_max_size == 1000

    def test_cache_ttl_default(self):
        settings = Settings()
        assert settings.tool_cache_ttl_seconds == 3600  # 1 hour

    def test_cache_enabled_env_override(self, monkeypatch):
        """Test that TOOL_CACHE_ENABLED env var overrides default."""
        monkeypatch.setenv("TOOL_CACHE_ENABLED", "false")
        settings = Settings()
        assert settings.tool_cache_enabled is False

    def test_cache_max_size_env_override(self, monkeypatch):
        """Test that TOOL_CACHE_MAX_SIZE env var overrides default."""
        monkeypatch.setenv("TOOL_CACHE_MAX_SIZE", "500")
        settings = Settings()
        assert settings.tool_cache_max_size == 500

    def test_cache_ttl_env_override(self, monkeypatch):
        """Test that TOOL_CACHE_TTL_SECONDS env var overrides default."""
        monkeypatch.setenv("TOOL_CACHE_TTL_SECONDS", "7200")
        settings = Settings()
        assert settings.tool_cache_ttl_seconds == 7200

    def test_cache_max_size_rejects_zero(self):
        """Test that max_size=0 raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(tool_cache_max_size=0)
        assert "greater than 0" in str(exc_info.value).lower()

    def test_cache_max_size_rejects_negative(self):
        """Test that negative max_size raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(tool_cache_max_size=-1)
        assert "greater than 0" in str(exc_info.value).lower()

    def test_cache_ttl_rejects_zero(self):
        """Test that ttl_seconds=0 raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(tool_cache_ttl_seconds=0)
        assert "greater than 0" in str(exc_info.value).lower()

    def test_cache_ttl_rejects_negative(self):
        """Test that negative ttl_seconds raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(tool_cache_ttl_seconds=-1)
        assert "greater than 0" in str(exc_info.value).lower()
