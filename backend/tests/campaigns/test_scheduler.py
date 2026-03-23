from campaigns.scheduler import CampaignScheduler

def test_can_enqueue_lane():
    s = CampaignScheduler()
    assert s.can_enqueue_lane("c1") is True
    s.get_tracker("c1", max_parallel=2)
    s.record_lane_start("c1")
    s.record_lane_start("c1")
    assert s.can_enqueue_lane("c1") is False
    s.record_lane_complete("c1")
    assert s.can_enqueue_lane("c1") is True

def test_steering_guard():
    s = CampaignScheduler()
    assert s.can_steer("c1") is True
    s.record_steering_start("c1")
    assert s.can_steer("c1") is False
    s.record_steering_complete("c1")
    assert s.can_steer("c1") is True

def test_cleanup():
    s = CampaignScheduler()
    s.get_tracker("c1")
    s.cleanup_campaign("c1")
    assert s.can_enqueue_lane("c1") is True
