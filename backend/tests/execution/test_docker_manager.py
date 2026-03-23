"""Tests for execution.docker_manager — Docker network + compose management."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, call, patch

import httpx

from execution.docker_manager import DockerNetworkManager, TargetStackInfo


class TestCreateCampaignNetwork:
    """Network creation via docker CLI."""

    @patch("execution.docker_manager.subprocess.run")
    def test_creates_network_with_prefix(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        mgr = DockerNetworkManager()
        name = mgr.create_campaign_network("abc123")

        assert name == "qh_abc123"

    @patch("execution.docker_manager.subprocess.run")
    def test_calls_docker_network_create(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        mgr = DockerNetworkManager()
        mgr.create_campaign_network("abc123")

        mock_run.assert_called_once_with(
            ["docker", "network", "create", "--internal", "qh_abc123"],
            capture_output=True,
            text=True,
            check=True,
        )

    @patch("execution.docker_manager.subprocess.run")
    def test_propagates_docker_error(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        mgr = DockerNetworkManager()
        try:
            mgr.create_campaign_network("bad")
            assert False, "Should have raised"
        except subprocess.CalledProcessError:
            pass


class TestTeardownNetwork:
    """Network removal via docker CLI."""

    @patch("execution.docker_manager.subprocess.run")
    def test_calls_docker_network_rm(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        mgr = DockerNetworkManager()
        mgr.teardown_network("abc123")

        mock_run.assert_called_once_with(
            ["docker", "network", "rm", "qh_abc123"],
            capture_output=True,
            text=True,
            check=True,
        )


@patch(
    "execution.docker_manager._get_first_service_and_port",
    return_value=("app", 8080),
)
class TestLaunchTargetStack:
    """Compose stack launch."""

    @patch("execution.docker_manager.subprocess.run")
    def test_launches_compose_up(self, mock_run: MagicMock, _mock_port: MagicMock) -> None:
        # First call: compose up; second call: compose ps -q
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout="abc123\ndef456\n", stderr=""
            ),
        ]

        mgr = DockerNetworkManager()
        info = mgr.launch_target_stack("camp1", "/path/to/compose.yaml")

        assert isinstance(info, TargetStackInfo)
        assert info.network_name == "qh_camp1"
        assert info.compose_path == "/path/to/compose.yaml"

        # Verify compose up was called
        up_call = mock_run.call_args_list[0]
        assert up_call.args[0] == [
            "docker",
            "compose",
            "-f",
            "/path/to/compose.yaml",
            "up",
            "-d",
        ]

    @patch("execution.docker_manager.subprocess.run")
    def test_parses_container_ids(self, mock_run: MagicMock, _mock_port: MagicMock) -> None:
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout="aaa111\nbbb222\nccc333\n", stderr=""
            ),
        ]

        mgr = DockerNetworkManager()
        info = mgr.launch_target_stack("camp1", "/compose.yaml")

        assert info.container_ids == ["aaa111", "bbb222", "ccc333"]

    @patch("execution.docker_manager.subprocess.run")
    def test_passes_env_vars(self, mock_run: MagicMock, _mock_port: MagicMock) -> None:
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout="id1\n", stderr=""
            ),
        ]

        mgr = DockerNetworkManager()
        mgr.launch_target_stack(
            "camp1", "/compose.yaml", env_vars={"MY_VAR": "hello"}
        )

        up_call = mock_run.call_args_list[0]
        env = up_call.kwargs["env"]
        assert env["MY_VAR"] == "hello"
        assert env["QH_NETWORK"] == "qh_camp1"

    @patch("execution.docker_manager.subprocess.run")
    def test_sets_qh_network_env(self, mock_run: MagicMock, _mock_port: MagicMock) -> None:
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(
                args=[], returncode=0, stdout="id1\n", stderr=""
            ),
        ]

        mgr = DockerNetworkManager()
        mgr.launch_target_stack("camp1", "/compose.yaml")

        up_call = mock_run.call_args_list[0]
        assert up_call.kwargs["env"]["QH_NETWORK"] == "qh_camp1"


class TestTeardownTargetStack:
    """Compose stack teardown."""

    @patch("execution.docker_manager.subprocess.run")
    def test_calls_compose_down(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        mgr = DockerNetworkManager()
        mgr.teardown_target_stack("camp1", "/path/to/compose.yaml")

        mock_run.assert_called_once()
        cmd = mock_run.call_args.args[0]
        assert cmd == [
            "docker",
            "compose",
            "-f",
            "/path/to/compose.yaml",
            "down",
        ]

    @patch("execution.docker_manager.subprocess.run")
    def test_sets_qh_network_env_on_teardown(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        mgr = DockerNetworkManager()
        mgr.teardown_target_stack("camp1", "/compose.yaml")

        assert mock_run.call_args.kwargs["env"]["QH_NETWORK"] == "qh_camp1"


class TestWaitForHealthy:
    """Health polling with httpx."""

    @patch("execution.docker_manager.time.sleep")
    @patch("execution.docker_manager.httpx.get")
    def test_returns_true_on_immediate_200(
        self, mock_get: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        mgr = DockerNetworkManager()
        result = mgr.wait_for_healthy("http://localhost:3000")

        assert result is True
        mock_sleep.assert_not_called()

    @patch("execution.docker_manager.time.sleep")
    @patch("execution.docker_manager.httpx.get")
    def test_retries_on_connect_error(
        self, mock_get: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        # Fail twice, then succeed
        mock_get.side_effect = [
            httpx.ConnectError("refused"),
            httpx.ConnectError("refused"),
            mock_resp,
        ]

        mgr = DockerNetworkManager()
        result = mgr.wait_for_healthy("http://localhost:3000", timeout=30)

        assert result is True
        assert mock_get.call_count == 3

    @patch("execution.docker_manager.time.monotonic")
    @patch("execution.docker_manager.time.sleep")
    @patch("execution.docker_manager.httpx.get")
    def test_returns_false_on_timeout(
        self, mock_get: MagicMock, mock_sleep: MagicMock, mock_monotonic: MagicMock
    ) -> None:
        mock_get.side_effect = httpx.ConnectError("refused")

        # Call sequence for time.monotonic():
        # 1. deadline = monotonic() + timeout  => 0 + 5 = 5
        # 2. while monotonic() < deadline      => 0 < 5 -> enter loop
        # 3. remaining = deadline - monotonic() => 5 - 3 = 2 -> sleep(2)
        # 4. while monotonic() < deadline      => 6 >= 5 -> exit loop
        mock_monotonic.side_effect = [0, 0, 3, 6]

        mgr = DockerNetworkManager()
        result = mgr.wait_for_healthy("http://localhost:3000", timeout=5)

        assert result is False

    @patch("execution.docker_manager.time.sleep")
    @patch("execution.docker_manager.httpx.get")
    def test_custom_health_path(
        self, mock_get: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        mgr = DockerNetworkManager()
        mgr.wait_for_healthy("http://localhost:3000", health_path="/ready")

        mock_get.assert_called_with("http://localhost:3000/ready", timeout=5)

    @patch("execution.docker_manager.time.sleep")
    @patch("execution.docker_manager.httpx.get")
    def test_strips_trailing_slash_from_base_url(
        self, mock_get: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        mgr = DockerNetworkManager()
        mgr.wait_for_healthy("http://localhost:3000/", health_path="/health")

        mock_get.assert_called_with("http://localhost:3000/health", timeout=5)

    @patch("execution.docker_manager.time.sleep")
    @patch("execution.docker_manager.httpx.get")
    def test_retries_on_timeout_exception(
        self, mock_get: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_get.side_effect = [
            httpx.TimeoutException("timeout"),
            mock_resp,
        ]

        mgr = DockerNetworkManager()
        result = mgr.wait_for_healthy("http://localhost:3000", timeout=30)

        assert result is True
        assert mock_get.call_count == 2
