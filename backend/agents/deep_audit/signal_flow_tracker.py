"""Pipeline signal flow tracker for deep audit.

Instruments every decision point in the routing pipeline and produces
a clear end-of-scan health report showing where signals were dropped and why.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SignalTrace:
    """Tracks a single signal's journey through the pipeline."""

    signal_id: str
    title: str
    severity: str
    stages: list[dict] = field(default_factory=list)
    final_disposition: str = "unknown"  # persisted, dismissed, unverified, error, deduped
    classification: Optional[str] = None
    drop_stage: Optional[str] = None
    drop_reason: Optional[str] = None


class SignalFlowTracker:
    """Tracks signal flow through the deep audit routing pipeline.

    Usage:
        tracker = SignalFlowTracker()
        tracker.enter(signal_id, title, severity)
        tracker.record_stage(signal_id, "decider", "investigate")
        tracker.record_stage(signal_id, "specialist", "vulnerable")
        tracker.record_stage(signal_id, "triager", "SECURITY_VULNERABILITY")
        tracker.record_parse("json_ok")
        tracker.record_persist("saved")
        # ... at end of scan:
        tracker.print_report()
    """

    def __init__(self):
        self.traces: dict[str, SignalTrace] = {}
        self.parse_stats = Counter()  # json_ok, markdown_fallback, parse_failure
        self.persist_stats = Counter()  # saved, unverified_blocked, deduped, db_error

    def enter(self, signal_id: str, title: str, severity: str):
        """Signal enters the routing pipeline."""
        self.traces[signal_id] = SignalTrace(
            signal_id=signal_id,
            title=title[:80],
            severity=severity,
        )

    def record_stage(self, signal_id: str, stage: str, result: str, detail: str = ""):
        """Record a pipeline stage result for a signal."""
        trace = self.traces.get(signal_id)
        if not trace:
            return
        trace.stages.append({"stage": stage, "result": result, "detail": detail})
        if stage == "triager" and result in (
            "SECURITY_VULNERABILITY", "HARDENING", "BUG", "MISCONFIGURATION",
        ):
            trace.final_disposition = "verified"
            trace.classification = result

    def record_drop(self, signal_id: str, stage: str, reason: str):
        """Signal was dropped at this stage."""
        trace = self.traces.get(signal_id)
        if not trace:
            return
        trace.stages.append({"stage": stage, "result": "dropped", "detail": reason})
        trace.final_disposition = "dismissed"
        trace.drop_stage = stage
        trace.drop_reason = reason[:200] if reason else ""

    def record_parse(self, parse_type: str):
        """Track triager output parsing: json_ok, markdown_fallback, parse_failure."""
        self.parse_stats[parse_type] += 1

    def record_persist(self, result: str):
        """Track persistence: saved, unverified_blocked, deduped, db_error."""
        self.persist_stats[result] += 1

    def summary(self) -> dict:
        """Return structured summary of all signal flows."""
        total = len(self.traces)
        by_disposition = Counter(t.final_disposition for t in self.traces.values())
        by_drop_stage = Counter(
            t.drop_stage for t in self.traces.values() if t.drop_stage
        )
        by_classification = Counter(
            t.classification for t in self.traces.values() if t.classification
        )
        dropped_signals = [
            {
                "signal_id": t.signal_id,
                "title": t.title,
                "severity": t.severity,
                "drop_stage": t.drop_stage,
                "drop_reason": t.drop_reason,
            }
            for t in self.traces.values()
            if t.final_disposition in ("dismissed", "unknown")
            and t.severity in ("critical", "high", "CRITICAL", "HIGH")
        ]

        warnings = []
        if self.parse_stats["markdown_fallback"] > 0:
            warnings.append(
                f"{self.parse_stats['markdown_fallback']} signal(s) required markdown fallback parsing"
            )
        if self.parse_stats["parse_failure"] > 0:
            warnings.append(
                f"{self.parse_stats['parse_failure']} signal(s) lost to parse failure"
            )
        if self.persist_stats["unverified_blocked"] > 0:
            warnings.append(
                f"{self.persist_stats['unverified_blocked']} finding(s) blocked as UNVERIFIED"
            )
        if self.persist_stats["db_error"] > 0:
            warnings.append(
                f"{self.persist_stats['db_error']} finding(s) failed DB persistence"
            )

        return {
            "signals_entered": total,
            "by_disposition": dict(by_disposition),
            "by_drop_stage": dict(by_drop_stage),
            "by_classification": dict(by_classification),
            "parse_stats": dict(self.parse_stats),
            "persist_stats": dict(self.persist_stats),
            "dropped_high_severity": dropped_signals,
            "warnings": warnings,
        }

    def summary_text(self) -> str:
        """Return a concise text summary suitable for emit_log."""
        s = self.summary()
        total = s["signals_entered"]
        disp = s["by_disposition"]
        cls = s["by_classification"]
        parse = s["parse_stats"]
        persist = s["persist_stats"]

        parts = [
            f"Pipeline: {total} signals entered",
            f"{disp.get('verified', 0)} verified",
            f"{disp.get('dismissed', 0)} dismissed",
        ]
        if cls:
            cls_parts = [f"{v}x {k}" for k, v in sorted(cls.items())]
            parts.append(f"[{', '.join(cls_parts)}]")
        if parse.get("markdown_fallback", 0) > 0:
            parts.append(f"{parse['markdown_fallback']} markdown-fallback")
        if parse.get("parse_failure", 0) > 0:
            parts.append(f"{parse['parse_failure']} parse-fail")
        parts.append(f"{persist.get('saved', 0)} saved to DB")

        return " | ".join(parts)

    def print_report(self):
        """Print human-readable pipeline health report to stdout."""
        s = self.summary()
        total = s["signals_entered"]
        disp = s["by_disposition"]
        drop = s["by_drop_stage"]
        cls = s["by_classification"]
        parse = s["parse_stats"]
        persist = s["persist_stats"]
        warnings = s["warnings"]

        if total == 0:
            print("[Pipeline Health] No signals entered the routing pipeline.")
            return

        verified = disp.get("verified", 0)
        dismissed = disp.get("dismissed", 0)
        unknown = disp.get("unknown", 0)

        lines = [
            "",
            "=" * 55,
            "  PIPELINE HEALTH REPORT",
            "=" * 55,
            f"  Signals Entered:     {total:>3}",
            f"  |-- Pre-check Skip:  {drop.get('pre_check', 0):>3}  (previously dismissed)",
            f"  |-- Routed:          {total - drop.get('pre_check', 0):>3}",
            "  |",
            "  Routing Outcomes:",
            f"  |-- Decider Dismiss: {drop.get('decider', 0):>3}",
            f"  |-- Specialist Rej:  {drop.get('specialist', 0):>3}",
            f"  |-- Triager Dismiss: {drop.get('triager', 0):>3}",
            f"  |-- Verified:        {verified:>3}",
        ]
        if cls:
            for name, count in sorted(cls.items()):
                lines.append(f"  |   |-- {name}: {count}")
        lines.append("  |")
        lines.append("  Triager Parse Health:")
        lines.append(f"  |-- JSON OK:         {parse.get('json_ok', 0):>3}")
        fb = parse.get("markdown_fallback", 0)
        lines.append(f"  |-- Markdown Fallback:{fb:>3}{'  !!' if fb > 0 else ''}")
        pf = parse.get("parse_failure", 0)
        lines.append(f"  |-- Parse Failure:   {pf:>3}{'  XX' if pf > 0 else ''}")
        lines.append("  |")
        lines.append("  Persistence:")
        lines.append(f"  |-- Saved to DB:     {persist.get('saved', 0):>3}")
        lines.append(f"  |-- UNVERIFIED Block: {persist.get('unverified_blocked', 0):>3}")
        lines.append(f"  |-- Dedup Caught:    {persist.get('deduped', 0):>3}")
        lines.append(f"  |-- DB Error:        {persist.get('db_error', 0):>3}")

        if warnings:
            lines.append("  |")
            lines.append("  !! WARNINGS:")
            for w in warnings:
                lines.append(f"  |-- {w}")

        dropped_high = s["dropped_high_severity"]
        if dropped_high:
            lines.append("  |")
            lines.append("  DROPPED HIGH-SEVERITY SIGNALS:")
            for d in dropped_high:
                lines.append(
                    f"  |-- {d['signal_id']}: \"{d['title']}\" ({d['severity']})"
                )
                lines.append(
                    f"  |   Dropped at: {d['drop_stage']} -> {(d['drop_reason'] or 'unknown')[:100]}"
                )

        lines.append("=" * 55)
        lines.append("")

        print("\n".join(lines))
