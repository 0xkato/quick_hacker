"""Tests for Overseer tools (memories, finalize, dispatch)."""

import json
import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

from agents.deep_audit.state import CampaignState, Hypothesis, HypothesisStatus, Severity, Confidence
from agents.deep_audit.filesystem import MemoriesFilesystem
from agents.deep_audit.tools import memories, finalize


class TestMemoriesTools:
    """Tests for memory access tools."""

    @pytest.fixture
    def mock_filesystem(self, tmp_path):
        """Create a mock filesystem for testing."""
        # Create directories
        memories_dir = tmp_path / "memories"
        memories_dir.mkdir()
        (memories_dir / "scopes").mkdir()
        (memories_dir / "overseer").mkdir()

        # Create test files
        (memories_dir / "repo_profile.json").write_text(
            json.dumps({"languages": ["python"], "frameworks": ["fastapi"]})
        )
        (memories_dir / "scopes" / "backend").mkdir()
        (memories_dir / "scopes" / "backend" / "signals.json").write_text(
            json.dumps({"signals": []})
        )

        # Create mock filesystem
        fs = MagicMock(spec=MemoriesFilesystem)

        def mock_read(path):
            # Remove /memories/ prefix and resolve to tmp_path
            rel_path = path.replace("/memories/", "")
            file_path = memories_dir / rel_path
            if file_path.exists():
                return file_path.read_text()
            raise FileNotFoundError(f"File not found: {path}")

        def mock_write(path, content):
            rel_path = path.replace("/memories/", "")
            file_path = memories_dir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            return path

        def mock_ls(path):
            rel_path = path.replace("/memories", "").lstrip("/")
            dir_path = memories_dir / rel_path if rel_path else memories_dir
            if dir_path.exists():
                return [f.name for f in dir_path.iterdir()]
            raise FileNotFoundError(f"Directory not found: {path}")

        def mock_is_dir(path):
            rel_path = path.replace("/memories/", "")
            return (memories_dir / rel_path).is_dir()

        fs.read_file = mock_read
        fs.write_file = mock_write
        fs.ls = mock_ls
        fs.is_dir = mock_is_dir

        return fs, memories_dir

    def test_read_memories_json(self, mock_filesystem):
        """Test reading JSON file from memories."""
        fs, _ = mock_filesystem
        memories.set_filesystem(fs)

        result = memories.read_memories("/memories/repo_profile.json")
        data = json.loads(result)

        assert "languages" in data
        assert "python" in data["languages"]

    def test_read_memories_not_found(self, mock_filesystem):
        """Test reading non-existent file."""
        fs, _ = mock_filesystem
        memories.set_filesystem(fs)

        result = memories.read_memories("/memories/nonexistent.json")
        data = json.loads(result)

        assert "error" in data
        assert "not found" in data["error"].lower()

    def test_read_memories_invalid_path(self, mock_filesystem):
        """Test reading from invalid path."""
        fs, _ = mock_filesystem
        memories.set_filesystem(fs)

        result = memories.read_memories("/invalid/path.json")
        data = json.loads(result)

        assert "error" in data
        assert "must start with /memories/" in data["error"]

    def test_list_memories(self, mock_filesystem):
        """Test listing memories directory."""
        fs, _ = mock_filesystem
        memories.set_filesystem(fs)

        result = memories.list_memories("/memories/")
        data = json.loads(result)

        assert "directories" in data
        assert "files" in data
        assert "scopes" in data["directories"]
        assert "repo_profile.json" in data["files"]

    def test_write_artifact(self, mock_filesystem):
        """Test writing artifact to memories."""
        fs, memories_dir = mock_filesystem
        memories.set_filesystem(fs)

        content = json.dumps({"test": "data"})
        result = memories.write_artifact("/memories/test_artifact.json", content)
        data = json.loads(result)

        assert data["success"] is True
        assert data["path"] == "/memories/test_artifact.json"

    def test_write_synthesis(self, mock_filesystem):
        """Test writing wave synthesis."""
        fs, _ = mock_filesystem

        # Mock save_wave_synthesis
        fs.save_wave_synthesis = MagicMock(return_value="/memories/overseer/wave_1_synthesis.md")
        memories.set_filesystem(fs)

        result = memories.write_synthesis(1, "# Wave 1 Synthesis\n\nContent here.")
        data = json.loads(result)

        assert data["success"] is True
        assert "wave_1" in data["path"]


class TestFinalizeTools:
    """Tests for finalize tools."""

    @pytest.fixture
    def mock_state_and_fs(self, tmp_path):
        """Create mock state and filesystem."""
        state = CampaignState(
            project_id="test-project",
            scan_tier="standard",
            deadline=time.time() + 900,
        )

        # Add some test data
        state.hypotheses = [
            Hypothesis(
                id="h1",
                signal_type="sql_injection",
                location="api.py:45",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=HypothesisStatus.NEW,
            ),
            Hypothesis(
                id="h2",
                signal_type="xss",
                location="template.py:10",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=HypothesisStatus.CONFIRMED,
            ),
        ]

        state.confirmed_findings = [
            {
                "title": "XSS in template",
                "severity": "MEDIUM",
                "location": "template.py:10",
                "vulnerability_type": "xss",
                "description": "User input reflected in template",
            }
        ]

        # Create mock filesystem
        memories_dir = tmp_path / "memories"
        memories_dir.mkdir()
        (memories_dir / "overseer").mkdir()

        fs = MagicMock(spec=MemoriesFilesystem)
        fs.project_id = "test-project"

        def mock_write(path, content):
            rel_path = path.replace("/memories/", "")
            file_path = memories_dir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            return path

        fs.write_file = mock_write
        fs.save_campaign_state = MagicMock()

        return state, fs, memories_dir

    def test_update_campaign_state_hypotheses(self, mock_state_and_fs):
        """Test updating campaign state with new hypotheses."""
        state, fs, _ = mock_state_and_fs
        finalize.set_filesystem(fs)
        finalize.set_campaign_state(state)

        update = {
            "hypotheses": [
                {
                    "id": "h3",
                    "signal_type": "ssrf",
                    "location": "fetch.py:20",
                    "severity": "HIGH",
                    "confidence": "HIGH",  # Must be enum value
                }
            ]
        }

        result = finalize.update_campaign_state(json.dumps(update))
        data = json.loads(result)

        assert data["success"] is True
        assert data["summary"]["hypotheses_count"] == 3  # 2 original + 1 new

    def test_update_campaign_state_confirmed_findings(self, mock_state_and_fs):
        """Test updating campaign state with new findings."""
        state, fs, _ = mock_state_and_fs
        finalize.set_filesystem(fs)
        finalize.set_campaign_state(state)

        update = {
            "confirmed_findings": [
                {
                    "title": "SQL Injection",
                    "severity": "CRITICAL",
                    "location": "api.py:45",
                    "vulnerability_type": "sql_injection",
                }
            ]
        }

        result = finalize.update_campaign_state(json.dumps(update))
        data = json.loads(result)

        assert data["success"] is True
        assert data["summary"]["confirmed_findings_count"] == 2  # 1 original + 1 new

    def test_update_campaign_state_invalid_json(self, mock_state_and_fs):
        """Test updating with invalid JSON."""
        state, fs, _ = mock_state_and_fs
        finalize.set_filesystem(fs)
        finalize.set_campaign_state(state)

        result = finalize.update_campaign_state("not valid json")
        data = json.loads(result)

        assert "error" in data
        assert "Invalid JSON" in data["error"]

    def test_finalize_report(self, mock_state_and_fs):
        """Test generating final report."""
        state, fs, memories_dir = mock_state_and_fs
        finalize.set_filesystem(fs)
        finalize.set_campaign_state(state)

        result = finalize.finalize_report("Test completed successfully.")
        data = json.loads(result)

        assert data["success"] is True
        assert "final_report.md" in data["report_path"]
        assert data["summary"]["confirmed_findings"] == 1

        # Check report was written
        report_path = memories_dir / "overseer" / "final_report.md"
        assert report_path.exists()

        report_content = report_path.read_text()
        assert "Security Audit Final Report" in report_content
        assert "XSS in template" in report_content
        assert "Test completed successfully" in report_content


class TestDispatchTools:
    """Tests for dispatch tools."""

    @pytest.fixture
    def mock_dispatcher(self):
        """Create mock dispatcher."""
        from agents.deep_audit.dispatcher import WaveDispatcher, WaveResult, SubagentResult
        from datetime import datetime

        dispatcher = MagicMock(spec=WaveDispatcher)

        # Mock dispatch_wave
        async def mock_dispatch_wave(wave_plan, foundation_context=None):
            return WaveResult(
                wave_id=wave_plan.wave_id,
                tasks=wave_plan.tasks,
                results=[
                    SubagentResult(
                        task_id=task.task_id,
                        agent_type=task.agent_type,
                        status="completed",
                        output_path=task.deliverable,
                        started_at=datetime.utcnow(),
                        completed_at=datetime.utcnow(),
                    )
                    for task in wave_plan.tasks
                ],
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                all_succeeded=True,
            )

        dispatcher.dispatch_wave = AsyncMock(side_effect=mock_dispatch_wave)

        return dispatcher

    @pytest.mark.asyncio
    async def test_dispatch_wave(self, mock_dispatcher):
        """Test dispatching a wave of agents."""
        from agents.deep_audit.tools import dispatch

        dispatch.set_dispatcher(mock_dispatcher)

        wave_plan = {
            "wave_id": 1,
            "rationale": "Initial reconnaissance",
            "tasks": [
                {
                    "agent_type": "RepoProfiler",
                    "objective": "Map repo structure",
                    "scope": "/",
                    "deliverable": "/memories/repo_profile.json",
                }
            ]
        }

        result = await dispatch.dispatch_wave(json.dumps(wave_plan))
        data = json.loads(result)

        assert data["wave_id"] == 1
        assert data["all_succeeded"] is True
        assert len(data["results"]) == 1
        assert data["results"][0]["agent_type"] == "RepoProfiler"
        assert data["results"][0]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_dispatch_wave_invalid_json(self, mock_dispatcher):
        """Test dispatch with invalid JSON."""
        from agents.deep_audit.tools import dispatch

        dispatch.set_dispatcher(mock_dispatcher)

        result = await dispatch.dispatch_wave("not valid json")
        data = json.loads(result)

        assert "error" in data
        assert "Invalid JSON" in data["error"]

    @pytest.mark.asyncio
    async def test_dispatch_agent_single(self, mock_dispatcher):
        """Test dispatching a single agent."""
        from agents.deep_audit.tools import dispatch
        from agents.deep_audit.dispatcher import SubagentResult
        from datetime import datetime

        # Mock dispatch_single
        async def mock_dispatch_single(task, foundation_context=None):
            return SubagentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                status="completed",
                output_path=task.deliverable,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
            )

        mock_dispatcher.dispatch_single = AsyncMock(side_effect=mock_dispatch_single)
        dispatch.set_dispatcher(mock_dispatcher)

        result = await dispatch.dispatch_agent(
            agent_type="SinkHunter",
            objective="Find SQL injection sinks",
            scope="/backend",
            deliverable="/memories/scopes/backend/signals.json",
        )
        data = json.loads(result)

        assert data["agent_type"] == "SinkHunter"
        assert data["status"] == "completed"
