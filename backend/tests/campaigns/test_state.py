from campaigns.state import CampaignStateManager

def test_snapshot_update():
    m = CampaignStateManager()
    snap = m.update_snapshot("c1", status="running", phase="executing", target_count=5)
    assert snap.target_count == 5
    assert snap.status == "running"

def test_graph_data():
    m = CampaignStateManager()
    m.update_snapshot("c1", target_count=3, lane_count=2, artifact_count=1, issue_count=1)
    g = m.to_graph_data("c1")
    assert len(g["nodes"]) == 5  # campaign + targets + lanes + artifacts + issues
    assert len(g["edges"]) == 4

def test_empty_graph():
    m = CampaignStateManager()
    g = m.to_graph_data("nonexistent")
    assert g == {"nodes": [], "edges": []}
