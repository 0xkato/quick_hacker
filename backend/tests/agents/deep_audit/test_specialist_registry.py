# backend/tests/agents/deep_audit/test_specialist_registry.py
import pytest
from agents.deep_audit.specialists.registry import (
    SpecialistFamily,
    SpecialistRegistry,
    get_family_for_signal,
    get_specialists_for_signal,
)
from agents.deep_audit.foundation import SignalCategory


class TestSpecialistRegistry:
    def test_family_enum_has_14_families(self):
        """There are exactly 14 specialist families."""
        assert len(SpecialistFamily) == 14

    def test_get_family_for_sql_injection(self):
        """SQL injection routes to Injection family."""
        family = get_family_for_signal(SignalCategory.SQL_INJECTION)
        assert family == SpecialistFamily.INJECTION

    def test_get_family_for_buffer_overflow(self):
        """Buffer overflow routes to Memory Safety family."""
        family = get_family_for_signal(SignalCategory.BUFFER_OVERFLOW)
        assert family == SpecialistFamily.MEMORY_SAFETY

    def test_get_specialists_for_sql_injection(self):
        """SQL injection signal returns SQL Injection Auditor."""
        specialists = get_specialists_for_signal(SignalCategory.SQL_INJECTION)
        assert "sql_injection_auditor" in specialists

    def test_get_specialists_for_memory_copy(self):
        """Buffer overflow can match multiple memory specialists."""
        specialists = get_specialists_for_signal(SignalCategory.BUFFER_OVERFLOW)
        assert "oob_read_write_auditor" in specialists

    def test_registry_has_all_specialists(self):
        """Registry contains all 64 specialists."""
        registry = SpecialistRegistry()
        assert len(registry.all_specialists) == 64
