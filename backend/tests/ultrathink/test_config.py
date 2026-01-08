# tests/ultrathink/test_config.py
import pytest
from ultrathink.config import UltrathinkConfig, GateConfig
from models.schemas import ThinkingMode

def test_ultrathink_config_defaults():
    config = UltrathinkConfig()
    assert config.thinking_mode == ThinkingMode.AUTO
    assert config.min_thinking_tokens == 10000
    assert config.max_thinking_tokens == 50000
    assert len(config.gates) == 5

def test_gate_config_thresholds():
    gate = GateConfig(
        name="test_gate",
        confidence_threshold=0.85,
        thinking_budget_tokens=15000,
    )
    assert gate.confidence_threshold == 0.85
    assert gate.thinking_budget_tokens == 15000

def test_thinking_mode_auto_selects_native_for_claude():
    config = UltrathinkConfig(thinking_mode=ThinkingMode.AUTO)
    assert config.resolve_thinking_mode("claude-opus-4-5-20251101") == ThinkingMode.NATIVE
    assert config.resolve_thinking_mode("gpt-4o") == ThinkingMode.SIMULATED
    assert config.resolve_thinking_mode("llama3.3") == ThinkingMode.STRUCTURED
