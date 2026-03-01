"""Specialist Confidence Calibration System.

Tracks specialist accuracy over time and uses historical performance
to weight verdicts. This enables:
1. Higher trust for accurate specialists
2. Flagging specialists that dismiss too quickly
3. Triggering cross-validation for low-confidence specialists
"""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from pathlib import Path


@dataclass
class VerdictRecord:
    """A single specialist verdict with outcome tracking."""
    signal_id: str
    specialist_type: str  # MemorySinkHunter, InjectionSinkHunter, etc.
    verdict: str  # "vulnerable", "not_vulnerable", "needs_analysis"
    confidence: int  # 0-100
    analysis_time_seconds: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # Filled in later when final outcome is determined
    final_outcome: Optional[str] = None  # "true_positive", "false_positive", "true_negative", "false_negative"
    outcome_timestamp: Optional[str] = None


@dataclass
class SpecialistStats:
    """Aggregated statistics for a specialist type."""
    specialist_type: str
    total_verdicts: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    # Dismissal tracking
    total_dismissals: int = 0  # Verdicts of "not_vulnerable"
    quick_dismissals: int = 0  # Dismissals in under 30 seconds
    # Performance metrics
    avg_analysis_time: float = 0.0
    avg_confidence: float = 0.0

    @property
    def accuracy(self) -> float:
        """Calculate accuracy rate (correct verdicts / total with known outcomes)."""
        known = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if known == 0:
            return 0.0
        correct = self.true_positives + self.true_negatives
        return correct / known

    @property
    def dismissal_rate(self) -> float:
        """Calculate dismissal rate (dismissals / total verdicts)."""
        if self.total_verdicts == 0:
            return 0.0
        return self.total_dismissals / self.total_verdicts

    @property
    def quick_dismissal_rate(self) -> float:
        """Calculate quick dismissal rate (quick dismissals / total dismissals)."""
        if self.total_dismissals == 0:
            return 0.0
        return self.quick_dismissals / self.total_dismissals

    @property
    def false_negative_rate(self) -> float:
        """Calculate false negative rate (missed vulnerabilities)."""
        actual_positives = self.true_positives + self.false_negatives
        if actual_positives == 0:
            return 0.0
        return self.false_negatives / actual_positives

    @property
    def precision(self) -> float:
        """Calculate precision (true positives / predicted positives)."""
        predicted_positives = self.true_positives + self.false_positives
        if predicted_positives == 0:
            return 0.0
        return self.true_positives / predicted_positives

    @property
    def recall(self) -> float:
        """Calculate recall (true positives / actual positives)."""
        actual_positives = self.true_positives + self.false_negatives
        if actual_positives == 0:
            return 0.0
        return self.true_positives / actual_positives

    def to_dict(self) -> dict:
        """Convert to dictionary with computed metrics."""
        return {
            "specialist_type": self.specialist_type,
            "total_verdicts": self.total_verdicts,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "total_dismissals": self.total_dismissals,
            "quick_dismissals": self.quick_dismissals,
            "avg_analysis_time": self.avg_analysis_time,
            "avg_confidence": self.avg_confidence,
            # Computed metrics
            "accuracy": self.accuracy,
            "dismissal_rate": self.dismissal_rate,
            "quick_dismissal_rate": self.quick_dismissal_rate,
            "false_negative_rate": self.false_negative_rate,
            "precision": self.precision,
            "recall": self.recall,
        }


@dataclass
class CalibrationAlert:
    """Alert for calibration anomalies."""
    alert_type: str  # "high_dismissal_rate", "low_accuracy", "analysis_time_anomaly"
    specialist_type: str
    message: str
    severity: str  # "warning", "critical"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    data: dict = field(default_factory=dict)


class CalibrationStore:
    """Persistent storage for calibration data.

    Stores verdict records and computed statistics in the memories filesystem
    or a separate metrics directory.
    """

    # Batch write settings
    BATCH_SIZE = 10  # Write stats every N verdicts
    FLUSH_INTERVAL_SECONDS = 60  # Or after this many seconds

    def __init__(self, storage_path: str):
        """Initialize the calibration store.

        Args:
            storage_path: Base path for storing calibration data
        """
        self.storage_path = Path(storage_path)
        self.verdicts_path = self.storage_path / "verdicts.jsonl"
        self.stats_path = self.storage_path / "stats.json"
        self.alerts_path = self.storage_path / "alerts.jsonl"

        # Ensure directory exists
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # In-memory caches
        self._stats_cache: dict[str, SpecialistStats] = {}
        self._load_stats()

        # Batching state
        self._pending_verdicts: list[VerdictRecord] = []
        self._verdicts_since_save = 0
        self._last_save_time = datetime.now()
        self._stats_dirty = False

    def _load_stats(self):
        """Load stats from disk into cache."""
        if self.stats_path.exists():
            try:
                with open(self.stats_path) as f:
                    data = json.load(f)
                    for specialist_type, stats_dict in data.items():
                        self._stats_cache[specialist_type] = SpecialistStats(**stats_dict)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[Calibration] Failed to load stats: {e}")

    def _save_stats(self):
        """Save stats cache to disk."""
        data = {k: asdict(v) for k, v in self._stats_cache.items()}
        with open(self.stats_path, 'w') as f:
            json.dump(data, f, indent=2)

    def flush(self):
        """Flush pending verdicts and stats to disk.

        Call this periodically or at the end of a scan to ensure
        all data is persisted.
        """
        # Write pending verdicts
        if self._pending_verdicts:
            with open(self.verdicts_path, 'a') as f:
                for record in self._pending_verdicts:
                    f.write(json.dumps(asdict(record)) + '\n')
            self._pending_verdicts = []

        # Write stats if dirty
        if self._stats_dirty:
            self._save_stats()
            self._stats_dirty = False

        # Reset counters
        self._verdicts_since_save = 0
        self._last_save_time = datetime.now()

    def __del__(self):
        """Ensure pending data is flushed on cleanup."""
        try:
            if self._pending_verdicts or self._stats_dirty:
                self.flush()
        except Exception:
            pass  # Ignore errors during cleanup

    def record_verdict(self, record: VerdictRecord):
        """Record a specialist verdict with batched writes.

        Verdicts are buffered and written in batches to reduce I/O.
        Stats are saved every BATCH_SIZE verdicts or FLUSH_INTERVAL_SECONDS.

        Args:
            record: The verdict record to store
        """
        # Buffer the verdict for batch writing
        self._pending_verdicts.append(record)

        # Update in-memory stats
        stats = self._stats_cache.get(record.specialist_type)
        if not stats:
            stats = SpecialistStats(specialist_type=record.specialist_type)
            self._stats_cache[record.specialist_type] = stats

        stats.total_verdicts += 1

        # Track dismissals
        if record.verdict.lower() in ("not_vulnerable", "speculative", "invalid"):
            stats.total_dismissals += 1
            if record.analysis_time_seconds < 30:
                stats.quick_dismissals += 1

        # Update running averages
        n = stats.total_verdicts
        stats.avg_analysis_time = (
            (stats.avg_analysis_time * (n - 1) + record.analysis_time_seconds) / n
        )
        stats.avg_confidence = (
            (stats.avg_confidence * (n - 1) + record.confidence) / n
        )

        self._stats_dirty = True
        self._verdicts_since_save += 1

        # Check if we should flush
        time_since_save = (datetime.now() - self._last_save_time).total_seconds()
        should_flush = (
            self._verdicts_since_save >= self.BATCH_SIZE or
            time_since_save >= self.FLUSH_INTERVAL_SECONDS
        )

        if should_flush:
            self.flush()

    def record_outcome(self, signal_id: str, specialist_type: str, outcome: str):
        """Record the final outcome for a verdict.

        Args:
            signal_id: The signal ID
            specialist_type: The specialist type
            outcome: One of "true_positive", "false_positive", "true_negative", "false_negative"
        """
        stats = self._stats_cache.get(specialist_type)
        if not stats:
            return

        # Update stats based on outcome
        if outcome == "true_positive":
            stats.true_positives += 1
        elif outcome == "false_positive":
            stats.false_positives += 1
        elif outcome == "true_negative":
            stats.true_negatives += 1
        elif outcome == "false_negative":
            stats.false_negatives += 1

        self._save_stats()

    def get_stats(self, specialist_type: str) -> Optional[SpecialistStats]:
        """Get statistics for a specialist type.

        Args:
            specialist_type: The specialist type to look up

        Returns:
            SpecialistStats or None if no data
        """
        return self._stats_cache.get(specialist_type)

    def get_all_stats(self) -> dict[str, SpecialistStats]:
        """Get statistics for all specialists."""
        return self._stats_cache.copy()

    def record_alert(self, alert: CalibrationAlert):
        """Record a calibration alert.

        Args:
            alert: The alert to record
        """
        with open(self.alerts_path, 'a') as f:
            f.write(json.dumps(asdict(alert)) + '\n')


class ConfidenceCalibrator:
    """Calibrates specialist verdicts based on historical performance.

    Provides:
    1. Trust weights for specialists
    2. Flags for specialists needing cross-validation
    3. Alerts for calibration anomalies
    """

    # Thresholds for alerts
    HIGH_DISMISSAL_RATE_THRESHOLD = 0.8  # 80% dismissal rate
    LOW_ACCURACY_THRESHOLD = 0.6  # 60% accuracy
    QUICK_DISMISSAL_THRESHOLD = 0.5  # 50% of dismissals are quick
    MIN_VERDICTS_FOR_STATS = 5  # Minimum verdicts before stats are meaningful

    # Trust weights
    DEFAULT_TRUST_WEIGHT = 1.0
    HIGH_ACCURACY_BONUS = 0.2  # Bonus for >80% accuracy
    LOW_ACCURACY_PENALTY = 0.3  # Penalty for <60% accuracy
    HIGH_DISMISSAL_PENALTY = 0.2  # Penalty for high dismissal rate

    def __init__(self, store: CalibrationStore):
        """Initialize the calibrator.

        Args:
            store: CalibrationStore for data persistence
        """
        self.store = store

    def calculate_trust_weight(self, specialist_type: str) -> float:
        """Calculate trust weight for a specialist based on history.

        Higher weight = more trusted verdicts.

        Args:
            specialist_type: The specialist type

        Returns:
            Trust weight (0.5 to 1.5)
        """
        stats = self.store.get_stats(specialist_type)
        if not stats or stats.total_verdicts < self.MIN_VERDICTS_FOR_STATS:
            return self.DEFAULT_TRUST_WEIGHT

        weight = self.DEFAULT_TRUST_WEIGHT

        # Adjust based on accuracy
        if stats.accuracy > 0.8:
            weight += self.HIGH_ACCURACY_BONUS
        elif stats.accuracy < self.LOW_ACCURACY_THRESHOLD:
            weight -= self.LOW_ACCURACY_PENALTY

        # Penalize high dismissal rates
        if stats.dismissal_rate > self.HIGH_DISMISSAL_RATE_THRESHOLD:
            weight -= self.HIGH_DISMISSAL_PENALTY

        # Clamp to reasonable range
        return max(0.5, min(1.5, weight))

    def should_require_cross_validation(self, specialist_type: str) -> bool:
        """Determine if a specialist's verdicts should require cross-validation.

        Args:
            specialist_type: The specialist type

        Returns:
            True if cross-validation should be required
        """
        stats = self.store.get_stats(specialist_type)
        if not stats or stats.total_verdicts < self.MIN_VERDICTS_FOR_STATS:
            return False

        # Require cross-validation for:
        # 1. Low accuracy specialists
        if stats.accuracy < self.LOW_ACCURACY_THRESHOLD:
            return True

        # 2. High false negative rate (missing real vulnerabilities)
        if stats.false_negative_rate > 0.3:
            return True

        # 3. High quick dismissal rate
        if stats.quick_dismissal_rate > self.QUICK_DISMISSAL_THRESHOLD:
            return True

        return False

    def check_alerts(self, specialist_type: str) -> list[CalibrationAlert]:
        """Check for calibration anomalies and generate alerts.

        Args:
            specialist_type: The specialist type to check

        Returns:
            List of alerts (empty if no anomalies)
        """
        alerts = []
        stats = self.store.get_stats(specialist_type)

        if not stats or stats.total_verdicts < self.MIN_VERDICTS_FOR_STATS:
            return alerts

        # High dismissal rate
        if stats.dismissal_rate > self.HIGH_DISMISSAL_RATE_THRESHOLD:
            alert = CalibrationAlert(
                alert_type="high_dismissal_rate",
                specialist_type=specialist_type,
                message=f"{specialist_type} is dismissing {stats.dismissal_rate:.0%} of signals",
                severity="warning" if stats.dismissal_rate < 0.9 else "critical",
                data={"dismissal_rate": stats.dismissal_rate},
            )
            alerts.append(alert)
            self.store.record_alert(alert)

        # Low accuracy
        if stats.accuracy < self.LOW_ACCURACY_THRESHOLD:
            alert = CalibrationAlert(
                alert_type="low_accuracy",
                specialist_type=specialist_type,
                message=f"{specialist_type} accuracy is {stats.accuracy:.0%}",
                severity="warning" if stats.accuracy > 0.4 else "critical",
                data={"accuracy": stats.accuracy},
            )
            alerts.append(alert)
            self.store.record_alert(alert)

        # High quick dismissal rate
        if stats.quick_dismissal_rate > self.QUICK_DISMISSAL_THRESHOLD:
            alert = CalibrationAlert(
                alert_type="quick_dismissal_rate",
                specialist_type=specialist_type,
                message=f"{specialist_type} is making {stats.quick_dismissal_rate:.0%} quick dismissals",
                severity="warning",
                data={"quick_dismissal_rate": stats.quick_dismissal_rate},
            )
            alerts.append(alert)
            self.store.record_alert(alert)

        return alerts

    def weight_verdict(
        self,
        specialist_type: str,
        verdict: str,
        confidence: int,
    ) -> tuple[str, int]:
        """Apply trust weighting to a specialist verdict.

        Args:
            specialist_type: The specialist type
            verdict: The specialist's verdict
            confidence: The specialist's confidence (0-100)

        Returns:
            Tuple of (verdict, weighted_confidence)
        """
        trust_weight = self.calculate_trust_weight(specialist_type)

        # Apply weight to confidence
        weighted_confidence = int(confidence * trust_weight)
        weighted_confidence = max(0, min(100, weighted_confidence))

        return verdict, weighted_confidence

    def get_calibration_report(self) -> dict:
        """Generate a calibration report for all specialists.

        Returns:
            Report dictionary with stats and recommendations
        """
        all_stats = self.store.get_all_stats()

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "specialists": {},
            "recommendations": [],
        }

        for specialist_type, stats in all_stats.items():
            report["specialists"][specialist_type] = {
                **stats.to_dict(),
                "trust_weight": self.calculate_trust_weight(specialist_type),
                "requires_cross_validation": self.should_require_cross_validation(specialist_type),
            }

            # Add recommendations
            if stats.total_verdicts >= self.MIN_VERDICTS_FOR_STATS:
                if stats.accuracy < self.LOW_ACCURACY_THRESHOLD:
                    report["recommendations"].append({
                        "specialist": specialist_type,
                        "issue": "low_accuracy",
                        "recommendation": "Review specialist prompt and criteria",
                    })
                if stats.false_negative_rate > 0.3:
                    report["recommendations"].append({
                        "specialist": specialist_type,
                        "issue": "high_false_negatives",
                        "recommendation": "Specialist may be too conservative",
                    })
                if stats.dismissal_rate > self.HIGH_DISMISSAL_RATE_THRESHOLD:
                    report["recommendations"].append({
                        "specialist": specialist_type,
                        "issue": "high_dismissal_rate",
                        "recommendation": "Check if dismissal criteria are too lenient",
                    })

        return report
