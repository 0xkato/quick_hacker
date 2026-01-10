import pytest

from services.scan_tier_service import resolve_scan_budget


def test_defaults_to_quick():
    resolved = resolve_scan_budget(scan_tier=None, time_budget_seconds=None)
    assert resolved.scan_tier == "quick"
    assert resolved.time_budget_seconds == 5 * 60
    assert resolved.is_custom_budget is False


@pytest.mark.parametrize(
    ("tier", "seconds"),
    [
        ("quick", 5 * 60),
        ("medium", 15 * 60),
        ("advanced", 45 * 60),
        ("pro", 90 * 60),
        ("ultra", 4 * 60 * 60),
        ("evil", 24 * 60 * 60),
    ],
)
def test_known_tiers_map_to_seconds(tier: str, seconds: int):
    resolved = resolve_scan_budget(scan_tier=tier, time_budget_seconds=None)
    assert resolved.scan_tier == tier
    assert resolved.time_budget_seconds == seconds
    assert resolved.is_custom_budget is False


def test_invalid_tier_rejected_without_override():
    with pytest.raises(ValueError):
        resolve_scan_budget(scan_tier="fast", time_budget_seconds=None)


def test_override_bypasses_tier_validation():
    resolved = resolve_scan_budget(scan_tier="fast", time_budget_seconds=600)
    assert resolved.scan_tier == "fast"
    assert resolved.time_budget_seconds == 600
    assert resolved.is_custom_budget is True


@pytest.mark.parametrize("seconds", [0, 10, 59, 60 * 60 * 24 + 1])
def test_override_bounds(seconds: int):
    with pytest.raises(ValueError):
        resolve_scan_budget(scan_tier="custom", time_budget_seconds=seconds)

