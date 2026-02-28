"""Tests for SignalFlowTracker — pipeline observability."""

import io
import sys
import pytest

from agents.deep_audit.signal_flow_tracker import SignalFlowTracker, SignalTrace


class TestSignalTrace:
    def test_defaults(self):
        t = SignalTrace(signal_id="sig-1", title="Test", severity="HIGH")
        assert t.final_disposition == "unknown"
        assert t.classification is None
        assert t.drop_stage is None
        assert t.stages == []


class TestSignalFlowTrackerBasics:
    def test_enter_creates_trace(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "SQL Injection in login", "HIGH")
        assert "sig-1" in tracker.traces
        assert tracker.traces["sig-1"].title == "SQL Injection in login"
        assert tracker.traces["sig-1"].severity == "HIGH"

    def test_enter_truncates_long_title(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "A" * 200, "MEDIUM")
        assert len(tracker.traces["sig-1"].title) == 80

    def test_record_stage_appends(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        tracker.record_stage("sig-1", "decider", "investigate")
        tracker.record_stage("sig-1", "specialist", "vulnerable")
        assert len(tracker.traces["sig-1"].stages) == 2
        assert tracker.traces["sig-1"].stages[0]["stage"] == "decider"
        assert tracker.traces["sig-1"].stages[1]["result"] == "vulnerable"

    def test_record_stage_on_unknown_signal_is_noop(self):
        tracker = SignalFlowTracker()
        tracker.record_stage("nonexistent", "decider", "investigate")
        assert len(tracker.traces) == 0

    def test_record_drop_sets_disposition(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        tracker.record_drop("sig-1", "decider", "not in scope")
        trace = tracker.traces["sig-1"]
        assert trace.final_disposition == "dismissed"
        assert trace.drop_stage == "decider"
        assert trace.drop_reason == "not in scope"
        assert trace.stages[-1]["result"] == "dropped"

    def test_record_drop_truncates_reason(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        tracker.record_drop("sig-1", "specialist", "X" * 500)
        assert len(tracker.traces["sig-1"].drop_reason) == 200


class TestTriagerClassification:
    def test_triager_security_vuln_sets_verified(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "SSRF", "HIGH")
        tracker.record_stage("sig-1", "triager", "SECURITY_VULNERABILITY")
        trace = tracker.traces["sig-1"]
        assert trace.final_disposition == "verified"
        assert trace.classification == "SECURITY_VULNERABILITY"

    def test_triager_hardening_sets_verified(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Weak TLS", "LOW")
        tracker.record_stage("sig-1", "triager", "HARDENING")
        trace = tracker.traces["sig-1"]
        assert trace.final_disposition == "verified"
        assert trace.classification == "HARDENING"

    def test_triager_dismissed_via_record_drop(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "False positive", "LOW")
        tracker.record_drop("sig-1", "triager", "dismissed/by_design")
        trace = tracker.traces["sig-1"]
        assert trace.final_disposition == "dismissed"
        assert trace.drop_stage == "triager"


class TestParseStats:
    def test_parse_stats_counter(self):
        tracker = SignalFlowTracker()
        tracker.record_parse("json_ok")
        tracker.record_parse("json_ok")
        tracker.record_parse("markdown_fallback")
        tracker.record_parse("parse_failure")
        assert tracker.parse_stats["json_ok"] == 2
        assert tracker.parse_stats["markdown_fallback"] == 1
        assert tracker.parse_stats["parse_failure"] == 1


class TestPersistStats:
    def test_persist_stats_counter(self):
        tracker = SignalFlowTracker()
        tracker.record_persist("saved")
        tracker.record_persist("saved")
        tracker.record_persist("deduped")
        tracker.record_persist("unverified_blocked")
        tracker.record_persist("db_error")
        assert tracker.persist_stats["saved"] == 2
        assert tracker.persist_stats["deduped"] == 1
        assert tracker.persist_stats["unverified_blocked"] == 1
        assert tracker.persist_stats["db_error"] == 1


class TestSummary:
    def _build_tracker(self):
        """Build a tracker with a realistic signal flow."""
        tracker = SignalFlowTracker()

        # Signal 1: Full success path
        tracker.enter("sig-1", "SQL Injection", "HIGH")
        tracker.record_stage("sig-1", "decider", "investigate")
        tracker.record_stage("sig-1", "coordinator", "injection")
        tracker.record_stage("sig-1", "specialist", "vulnerable")
        tracker.record_stage("sig-1", "triager", "SECURITY_VULNERABILITY")
        tracker.record_parse("json_ok")
        tracker.record_persist("saved")

        # Signal 2: Dismissed by decider
        tracker.enter("sig-2", "Non-issue", "LOW")
        tracker.record_drop("sig-2", "decider", "not in scope")

        # Signal 3: Specialist rejected
        tracker.enter("sig-3", "False positive SSRF", "MEDIUM")
        tracker.record_stage("sig-3", "decider", "investigate")
        tracker.record_stage("sig-3", "coordinator", "ssrf")
        tracker.record_drop("sig-3", "specialist", "mitigations block attack")

        # Signal 4: Pre-check dismissed
        tracker.enter("sig-4", "Already seen", "LOW")
        tracker.record_drop("sig-4", "pre_check", "previously dismissed")

        # Signal 5: Markdown fallback → saved
        tracker.enter("sig-5", "Path traversal", "HIGH")
        tracker.record_stage("sig-5", "decider", "investigate")
        tracker.record_stage("sig-5", "coordinator", "filesystem")
        tracker.record_stage("sig-5", "specialist", "vulnerable")
        tracker.record_stage("sig-5", "triager", "HARDENING")
        tracker.record_parse("markdown_fallback")
        tracker.record_persist("saved")

        # Signal 6: Parse failure → unverified blocked
        tracker.enter("sig-6", "XSS in template", "HIGH")
        tracker.record_stage("sig-6", "decider", "investigate")
        tracker.record_stage("sig-6", "coordinator", "injection")
        tracker.record_stage("sig-6", "specialist", "vulnerable")
        tracker.record_drop("sig-6", "triager", "dismissed/by_design")
        tracker.record_parse("parse_failure")
        tracker.record_persist("unverified_blocked")

        return tracker

    def test_summary_counts(self):
        tracker = self._build_tracker()
        s = tracker.summary()
        assert s["signals_entered"] == 6
        assert s["by_disposition"]["verified"] == 2
        assert s["by_disposition"]["dismissed"] == 4
        assert s["by_drop_stage"]["pre_check"] == 1
        assert s["by_drop_stage"]["decider"] == 1
        assert s["by_drop_stage"]["specialist"] == 1
        assert s["by_drop_stage"]["triager"] == 1

    def test_summary_classifications(self):
        tracker = self._build_tracker()
        s = tracker.summary()
        assert s["by_classification"]["SECURITY_VULNERABILITY"] == 1
        assert s["by_classification"]["HARDENING"] == 1

    def test_summary_parse_stats(self):
        tracker = self._build_tracker()
        s = tracker.summary()
        assert s["parse_stats"]["json_ok"] == 1
        assert s["parse_stats"]["markdown_fallback"] == 1
        assert s["parse_stats"]["parse_failure"] == 1

    def test_summary_persist_stats(self):
        tracker = self._build_tracker()
        s = tracker.summary()
        assert s["persist_stats"]["saved"] == 2
        assert s["persist_stats"]["unverified_blocked"] == 1

    def test_summary_warnings(self):
        tracker = self._build_tracker()
        s = tracker.summary()
        warnings = s["warnings"]
        assert any("markdown fallback" in w for w in warnings)
        assert any("parse failure" in w for w in warnings)
        assert any("UNVERIFIED" in w for w in warnings)

    def test_dropped_high_severity_signals(self):
        tracker = self._build_tracker()
        s = tracker.summary()
        dropped = s["dropped_high_severity"]
        # sig-6 is HIGH and dismissed at triager
        ids = [d["signal_id"] for d in dropped]
        assert "sig-6" in ids
        # sig-2 is LOW, should not appear
        assert "sig-2" not in ids

    def test_summary_text_is_concise(self):
        tracker = self._build_tracker()
        text = tracker.summary_text()
        assert "6 signals entered" in text
        assert "2 verified" in text
        assert "4 dismissed" in text
        assert "2 saved to DB" in text


class TestPrintReport:
    def test_print_report_output(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "SQL Injection", "HIGH")
        tracker.record_stage("sig-1", "decider", "investigate")
        tracker.record_stage("sig-1", "triager", "SECURITY_VULNERABILITY")
        tracker.record_parse("json_ok")
        tracker.record_persist("saved")

        captured = io.StringIO()
        sys.stdout = captured
        try:
            tracker.print_report()
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        assert "PIPELINE HEALTH REPORT" in output
        assert "Signals Entered:" in output
        assert "Saved to DB:" in output

    def test_empty_tracker_prints_no_signals_message(self):
        tracker = SignalFlowTracker()

        captured = io.StringIO()
        sys.stdout = captured
        try:
            tracker.print_report()
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        assert "No signals entered" in output

    def test_warnings_section_appears_for_markdown_fallback(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        tracker.record_stage("sig-1", "triager", "SECURITY_VULNERABILITY")
        tracker.record_parse("markdown_fallback")
        tracker.record_persist("saved")

        captured = io.StringIO()
        sys.stdout = captured
        try:
            tracker.print_report()
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        assert "WARNINGS" in output
        assert "markdown fallback" in output

    def test_dropped_high_sev_section_appears(self):
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Critical SSRF", "CRITICAL")
        tracker.record_drop("sig-1", "specialist", "not exploitable")

        captured = io.StringIO()
        sys.stdout = captured
        try:
            tracker.print_report()
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        assert "DROPPED HIGH-SEVERITY" in output
        assert "Critical SSRF" in output
        assert "specialist" in output


class TestSignalSource:
    def test_signal_trace_has_signal_source_field(self):
        """SignalTrace has a signal_source field defaulting to 'sink_hunter'."""
        trace = SignalTrace(signal_id="sig-1", title="Test", severity="HIGH")
        assert trace.signal_source == "sink_hunter"

    def test_enter_accepts_signal_source(self):
        """SignalFlowTracker.enter() accepts optional signal_source parameter."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH", signal_source="behavioral_sink")
        assert tracker.traces["sig-1"].signal_source == "behavioral_sink"

    def test_enter_defaults_signal_source(self):
        """SignalFlowTracker.enter() defaults signal_source to 'sink_hunter'."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "Test", "HIGH")
        assert tracker.traces["sig-1"].signal_source == "sink_hunter"

    def test_summary_includes_by_signal_source(self):
        """summary() includes by_signal_source counts."""
        tracker = SignalFlowTracker()
        tracker.enter("sig-1", "SQL Injection", "HIGH", signal_source="sink_hunter")
        tracker.enter("sig-2", "Missing auth", "HIGH", signal_source="policy_deviation")
        tracker.enter("sig-3", "IDOR", "MEDIUM", signal_source="behavioral_sink")

        s = tracker.summary()
        assert "by_signal_source" in s
        assert s["by_signal_source"]["sink_hunter"] == 1
        assert s["by_signal_source"]["policy_deviation"] == 1
        assert s["by_signal_source"]["behavioral_sink"] == 1


class TestFullPipelineFlow:
    """End-to-end test simulating the exact sequence of calls overseer.py makes."""

    def test_successful_finding_flow(self):
        tracker = SignalFlowTracker()

        # Overseer calls in _route_signal_through_pipeline
        tracker.enter("sig-abc", "SSRF via armory URL", "HIGH")
        tracker.record_stage("sig-abc", "decider", "investigate")
        tracker.record_stage("sig-abc", "coordinator", "ssrf")
        tracker.record_stage("sig-abc", "specialist", "vulnerable")
        # No devil's advocate (specialist agreed)
        tracker.record_stage("sig-abc", "triager", "SECURITY_VULNERABILITY")

        # Overseer calls in _run_triager
        tracker.record_parse("json_ok")

        # Overseer calls in _persist_finding_immediately
        tracker.record_persist("saved")

        s = tracker.summary()
        assert s["signals_entered"] == 1
        assert s["by_disposition"]["verified"] == 1
        assert s["by_classification"]["SECURITY_VULNERABILITY"] == 1
        assert s["persist_stats"]["saved"] == 1
        assert s["warnings"] == []

    def test_markdown_fallback_flow(self):
        """Simulates the exact bug we caught: triager returns markdown, fallback saves it."""
        tracker = SignalFlowTracker()

        tracker.enter("sig-def", "SSRF via armory URL", "HIGH")
        tracker.record_stage("sig-def", "decider", "investigate")
        tracker.record_stage("sig-def", "coordinator", "ssrf")
        tracker.record_stage("sig-def", "specialist", "vulnerable")
        tracker.record_stage("sig-def", "triager", "SECURITY_VULNERABILITY")

        # JSON failed, markdown fallback kicked in
        tracker.record_parse("markdown_fallback")
        tracker.record_persist("saved")

        s = tracker.summary()
        assert s["parse_stats"]["markdown_fallback"] == 1
        assert any("markdown fallback" in w for w in s["warnings"])
        # Finding still saved despite fallback
        assert s["persist_stats"]["saved"] == 1

    def test_total_loss_flow(self):
        """Simulates the original bug: triager returns unparseable output, finding lost."""
        tracker = SignalFlowTracker()

        tracker.enter("sig-ghi", "SSRF via armory URL", "HIGH")
        tracker.record_stage("sig-ghi", "decider", "investigate")
        tracker.record_stage("sig-ghi", "coordinator", "ssrf")
        tracker.record_stage("sig-ghi", "specialist", "vulnerable")
        # Triager returned garbage → UNVERIFIED
        tracker.record_drop("sig-ghi", "triager", "dismissed/by_design")
        tracker.record_parse("parse_failure")
        tracker.record_persist("unverified_blocked")

        s = tracker.summary()
        assert s["parse_stats"]["parse_failure"] == 1
        assert s["persist_stats"]["unverified_blocked"] == 1
        # HIGH severity signal dropped — should appear in warnings
        assert len(s["dropped_high_severity"]) == 1
        assert s["dropped_high_severity"][0]["signal_id"] == "sig-ghi"
        assert any("parse failure" in w for w in s["warnings"])
        assert any("UNVERIFIED" in w for w in s["warnings"])
