"""Tests for the campaigns router registration."""


def test_campaigns_route_registered():
    """Verify the /api/campaigns route is present in the app."""
    from main import app

    routes = [r.path for r in app.routes]
    assert any("/api/campaigns" in r for r in routes)
