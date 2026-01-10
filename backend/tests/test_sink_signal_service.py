import pytest

from models.sink_signals import SinkSignal, SinkSignalKind, SinkSignalStatus
from services.sink_signal_service import SinkSignalService


@pytest.mark.asyncio
async def test_sink_signal_dedup_and_no_downgrade(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    svc = SinkSignalService()

    project_id = "proj-1"
    fingerprint = "abc123def456"

    first = SinkSignal(
        fingerprint=fingerprint,
        kind=SinkSignalKind.SINK,
        label="Potential SQLi sink",
        file_path="src/db.py",
        line_number=10,
        status=SinkSignalStatus.UNREVIEWED,
        source="llm",
        llm_score=50,
        metadata={"a": 1},
    )
    await svc.upsert_signals(project_id=project_id, signals=[first])

    upgrade = SinkSignal(
        fingerprint=fingerprint,
        kind=SinkSignalKind.SINK,
        label="Potential SQLi sink",
        file_path="src/db.py",
        line_number=10,
        status=SinkSignalStatus.REVIEWED,
        source="llm",
        llm_score=60,
        metadata={"b": 2},
    )
    await svc.upsert_signals(project_id=project_id, signals=[upgrade])

    downgrade_attempt = SinkSignal(
        fingerprint=fingerprint,
        kind=SinkSignalKind.SINK,
        label="Potential SQLi sink",
        file_path="src/db.py",
        line_number=10,
        status=SinkSignalStatus.UNREVIEWED,
        source="llm",
        metadata={},
    )
    await svc.upsert_signals(project_id=project_id, signals=[downgrade_attempt])

    signals = await svc.list_signals(project_id=project_id)
    assert len(signals) == 1
    assert signals[0].status == SinkSignalStatus.REVIEWED
    assert signals[0].llm_score == 60
    assert signals[0].metadata["a"] == 1
    assert signals[0].metadata["b"] == 2

