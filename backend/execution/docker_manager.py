"""Docker network manager for campaign target stacks.

Uses subprocess to call Docker CLI directly — no docker-py SDK dependency.
Each campaign gets an isolated ``qh_{campaign_id}`` network and its own
compose stack.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field

import httpx
import yaml

logger = logging.getLogger(__name__)


@dataclass
class TargetStackInfo:
    """Metadata about a launched target stack."""

    base_url: str
    network_name: str
    container_ids: list[str]
    compose_path: str


def _get_first_service_and_port(compose_path: str) -> tuple[str, int]:
    """Extract first service name and exposed port from a compose file.

    Parses the compose YAML and returns the first service that exposes a port.
    Falls back to (first_service_name, 8080) if no ports are declared.
    """
    with open(compose_path) as f:
        compose = yaml.safe_load(f)
    services = compose.get("services", {})
    for name, config in services.items():
        ports = config.get("ports", [])
        if ports:
            # Parse "8080:8080", "127.0.0.1:8080:8080", or "8080" formats
            port_str = str(ports[0])
            if ":" in port_str:
                parts = port_str.split(":")
                container_port = int(parts[-1].split("/")[0])
            else:
                container_port = int(port_str.split("/")[0])
            return name, container_port
        # Service without ports — try next
        continue
    # No service with ports found; fall back
    first_service = next(iter(services), "app")
    return first_service, 8080


class DockerNetworkManager:
    """Manage Docker networks and compose stacks for campaigns."""

    # ------------------------------------------------------------------
    # Network lifecycle
    # ------------------------------------------------------------------

    def create_campaign_network(self, campaign_id: str) -> str:
        """Create an isolated Docker network for a campaign.

        Returns the network name ``qh_{campaign_id}``.
        """
        network_name = f"qh_{campaign_id}"
        logger.info("Creating Docker network: %s", network_name)

        subprocess.run(
            ["docker", "network", "create", "--internal", network_name],
            capture_output=True,
            text=True,
            check=True,
        )
        return network_name

    def teardown_network(self, campaign_id: str) -> None:
        """Remove the campaign's Docker network."""
        network_name = f"qh_{campaign_id}"
        logger.info("Removing Docker network: %s", network_name)

        result = subprocess.run(
            ["docker", "network", "rm", network_name],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning("Network %s removal returned %d: %s",
                           network_name, result.returncode, result.stderr.strip())

    # ------------------------------------------------------------------
    # Target stack lifecycle
    # ------------------------------------------------------------------

    def launch_target_stack(
        self,
        campaign_id: str,
        compose_path: str,
        env_vars: dict[str, str] | None = None,
    ) -> TargetStackInfo:
        """Start a target stack via ``docker compose up -d``.

        Parameters
        ----------
        campaign_id:
            The campaign this stack belongs to.
        compose_path:
            Path to the docker-compose file.
        env_vars:
            Optional environment variables to pass to compose.

        Returns
        -------
        TargetStackInfo with base_url, network name, and container IDs.
        """
        network_name = f"qh_{campaign_id}"
        logger.info(
            "Launching target stack for campaign %s from %s",
            campaign_id,
            compose_path,
        )

        # Build the compose up command
        cmd = [
            "docker",
            "compose",
            "-f",
            compose_path,
            "up",
            "-d",
        ]

        # Merge env vars into a copy of the current environment
        import os

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        env["QH_NETWORK"] = network_name

        subprocess.run(cmd, capture_output=True, text=True, check=True, env=env)

        # Fetch container IDs from the compose project
        ps_result = subprocess.run(
            ["docker", "compose", "-f", compose_path, "ps", "-q"],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        container_ids = [
            cid.strip() for cid in ps_result.stdout.strip().splitlines() if cid.strip()
        ]

        # Resolve base_url from compose service name so workers in the same
        # Docker network can reach the target by hostname.
        service_name, port = _get_first_service_and_port(compose_path)
        base_url = f"http://{service_name}:{port}"

        return TargetStackInfo(
            base_url=base_url,
            network_name=network_name,
            container_ids=container_ids,
            compose_path=compose_path,
        )

    def teardown_target_stack(self, campaign_id: str, compose_path: str) -> None:
        """Tear down a target stack via ``docker compose down``.

        Parameters
        ----------
        campaign_id:
            The campaign whose stack should be stopped.
        compose_path:
            Path to the docker-compose file used during launch.
        """
        logger.info("Tearing down target stack for campaign %s", campaign_id)

        import os

        env = os.environ.copy()
        env["QH_NETWORK"] = f"qh_{campaign_id}"

        subprocess.run(
            ["docker", "compose", "-f", compose_path, "down"],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def wait_for_healthy(
        self,
        base_url: str,
        health_path: str = "/health",
        timeout: int = 30,
    ) -> bool:
        """Poll a health endpoint until it returns 200 or timeout expires.

        Parameters
        ----------
        base_url:
            Base URL of the target (e.g. ``http://localhost:3000``).
        health_path:
            Path appended to base_url for the health check.
        timeout:
            Maximum seconds to wait.

        Returns
        -------
        True if healthy, False if timed out.
        """
        url = f"{base_url.rstrip('/')}{health_path}"
        deadline = time.monotonic() + timeout
        logger.info("Waiting for %s to be healthy (timeout=%ds)", url, timeout)

        while time.monotonic() < deadline:
            try:
                resp = httpx.get(url, timeout=5)
                if resp.status_code == 200:
                    logger.info("Target healthy at %s", url)
                    return True
            except (httpx.ConnectError, httpx.TimeoutException):
                pass

            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(2, remaining))

        logger.warning("Target at %s did not become healthy within %ds", url, timeout)
        return False
