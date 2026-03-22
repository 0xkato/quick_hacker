"""Tests for the campaigns router registration."""


def test_campaigns_route_registered():
    """Verify the /api/campaigns route is present in the app."""
    from main import app

    routes = [r.path for r in app.routes]
    assert any("/api/campaigns" in r for r in routes)


def test_plan_endpoint_registered():
    from main import app

    paths = [r.path for r in app.routes]
    assert any("plan" in p for p in paths)


def test_targets_endpoint_registered():
    from main import app

    paths = [r.path for r in app.routes]
    assert any("targets" in p for p in paths)


def test_start_endpoint_registered():
    from main import app

    paths = [r.path for r in app.routes]
    assert any("start" in p for p in paths)


def test_campaign_lanes_endpoint_registered():
    from main import app

    paths = [r.path for r in app.routes]
    assert any("/campaigns/" in p and "/lanes" in p for p in paths)


def test_lane_detail_endpoint_registered():
    from main import app

    paths = [r.path for r in app.routes]
    assert any("/lanes/" in p and "{lane_id}" in p for p in paths)
