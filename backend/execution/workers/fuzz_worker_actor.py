"""Dramatiq actor for running fuzz lanes."""
import asyncio
import dramatiq
from execution.broker import get_broker

broker = get_broker()


@dramatiq.actor(queue_name="qh_fuzz")
def run_lane(job_data: dict):
    """Execute a methodology lane against a live target.

    Wraps the async execute_run_lane function.
    """
    from execution.workers.fuzz_worker import execute_run_lane

    print(f"[worker-fuzz] Received lane job: {job_data}")

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(execute_run_lane(
            run_lane_id=job_data["run_lane_id"],
            execution_bundle_id=job_data["execution_bundle_id"],
            campaign_id=job_data["campaign_id"],
            harness_code_ref=job_data.get("harness_code_ref", ""),
            compose_path=job_data.get("compose_path", ""),
            openapi_url=job_data.get("openapi_url", "openapi.json"),
            timeout_seconds=job_data.get("timeout_seconds", 1800),
            needs_docker_target=job_data.get("needs_docker_target"),
            repo_path=job_data.get("repo_path", ""),
            lane_spec_id=job_data.get("lane_spec_id", ""),
            engine_name=job_data.get("engine_name", ""),
        ))
    finally:
        loop.close()
