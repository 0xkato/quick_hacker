# backend/tests/test_cache_config.py
from config import Settings


class TestCacheConfiguration:
    def test_cache_enabled_default_true(self):
        settings = Settings()
        assert settings.tool_cache_enabled is True

    def test_cache_max_size_default(self):
        settings = Settings()
        assert settings.tool_cache_max_size == 1000

    def test_cache_ttl_default(self):
        settings = Settings()
        assert settings.tool_cache_ttl_seconds == 3600  # 1 hour
