"""Tests for runs, artifacts, issues, targets, harnesses, oracle-packs router registration."""


def _get_paths():
    from main import app
    return [r.path for r in app.routes]


# --- Runs ---


def test_runs_routes():
    paths = _get_paths()
    assert any("/runs/" in p for p in paths)


def test_runs_metrics_route():
    paths = _get_paths()
    assert any("/runs/" in p and "metrics" in p for p in paths)


def test_runs_cancel_route():
    paths = _get_paths()
    assert any("/runs/" in p and "cancel" in p for p in paths)


def test_runs_logs_route():
    paths = _get_paths()
    assert any("/runs/" in p and "logs" in p for p in paths)


# --- Artifacts ---


def test_artifacts_routes():
    paths = _get_paths()
    assert any("/artifacts/" in p for p in paths)


def test_artifacts_replay_route():
    paths = _get_paths()
    assert any("/artifacts/" in p and "replay" in p for p in paths)


def test_artifacts_minimize_route():
    paths = _get_paths()
    assert any("/artifacts/" in p and "minimize" in p for p in paths)


def test_artifacts_classify_route():
    paths = _get_paths()
    assert any("/artifacts/" in p and "classify" in p for p in paths)


def test_artifacts_evidence_route():
    paths = _get_paths()
    assert any("/artifacts/" in p and "evidence" in p for p in paths)


def test_artifact_buckets_route():
    paths = _get_paths()
    assert any("/artifacts/buckets/" in p for p in paths)


# --- Issues ---


def test_issues_routes():
    paths = _get_paths()
    assert any("/issues/" in p for p in paths)


def test_issues_revalidate_route():
    paths = _get_paths()
    assert any("/issues/" in p and "revalidate" in p for p in paths)


def test_issues_regression_test_route():
    paths = _get_paths()
    assert any("/issues/" in p and "regression-test" in p for p in paths)


# --- Campaign sub-resources ---


def test_campaign_artifacts_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "artifacts" in p for p in paths)


def test_campaign_artifact_buckets_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "artifact-buckets" in p for p in paths)


def test_campaign_coverage_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "coverage" in p for p in paths)


def test_campaign_steering_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "steering" in p for p in paths)


def test_campaign_issues_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "issues" in p for p in paths)


def test_campaign_pause_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "pause" in p for p in paths)


def test_campaign_resume_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "resume" in p for p in paths)


def test_campaign_cancel_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "cancel" in p for p in paths)


def test_campaign_plan_route():
    paths = _get_paths()
    # Match GET plan (not POST plan which is the trigger)
    assert any("/campaigns/" in p and "/plan" in p for p in paths)


def test_campaign_plans_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "/plans" in p for p in paths)


def test_campaign_graph_route():
    paths = _get_paths()
    assert any("/campaigns/" in p and "graph" in p for p in paths)


def test_campaign_create_lane_route():
    """POST /api/campaigns/{id}/lanes creates a lane within a campaign."""
    from main import app

    paths_methods = [(r.path, r.methods) for r in app.routes if hasattr(r, "methods")]
    assert any(
        "/campaigns/" in p and p.endswith("/lanes") and "POST" in m
        for p, m in paths_methods
    )


# --- Targets ---


def test_targets_router_registered():
    paths = _get_paths()
    assert any("/api/targets/" in p for p in paths)


def test_targets_get_route():
    paths = _get_paths()
    assert any("/targets/{target_id}" in p for p in paths)


def test_targets_lanes_route():
    paths = _get_paths()
    assert any("/targets/" in p and "lanes" in p for p in paths)


def test_targets_reprioritize_route():
    paths = _get_paths()
    assert any("/targets/" in p and "reprioritize" in p for p in paths)


# --- Harnesses ---


def test_harnesses_router_registered():
    paths = _get_paths()
    assert any("/api/harnesses/" in p for p in paths)


def test_harnesses_get_route():
    paths = _get_paths()
    assert any("/harnesses/{harness_id}" in p for p in paths)


def test_harnesses_validation_route():
    paths = _get_paths()
    assert any("/harnesses/" in p and "validation" in p for p in paths)


def test_harnesses_revisions_route():
    paths = _get_paths()
    assert any("/harnesses/" in p and "revisions" in p for p in paths)


# --- Oracle Packs ---


def test_oracle_packs_router_registered():
    paths = _get_paths()
    assert any("/api/oracle-packs/" in p for p in paths)


def test_oracle_packs_get_route():
    paths = _get_paths()
    assert any("/oracle-packs/{oracle_pack_id}" in p for p in paths)


def test_oracle_packs_revisions_route():
    paths = _get_paths()
    assert any("/oracle-packs/" in p and "revisions" in p for p in paths)


# --- Lanes expanded ---


def test_lane_oracle_packs_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "oracle-packs" in p for p in paths)


def test_lane_recompile_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "recompile" in p for p in paths)


def test_lane_restart_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "restart" in p for p in paths)


def test_lane_steer_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "steer" in p for p in paths)


def test_lane_runs_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "runs" in p for p in paths)


def test_lane_coverage_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "coverage" in p for p in paths)


def test_lane_corpus_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "corpus" in p for p in paths)


def test_lane_corpus_prune_route():
    paths = _get_paths()
    assert any("/lanes/" in p and "corpus/prune" in p for p in paths)


# --- Reports expanded ---


def test_reports_campaigns_export_route():
    paths = _get_paths()
    assert any("/reports/campaigns/export" in p for p in paths)


def test_reports_issues_export_route():
    paths = _get_paths()
    assert any("/reports/issues/export" in p for p in paths)
