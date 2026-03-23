"""Dramatiq actor for packaging and validating harnesses."""
import dramatiq
from execution.broker import get_broker

# Initialize broker on module load
broker = get_broker()


@dramatiq.actor(queue_name="qh_package")
def package_lane_bundle(job_data: dict):
    """Package a lane bundle (harness + oracle + seeds).

    v1: This is a stub. The actual packaging happens synchronously
    in the campaign controller's compile_campaign method.
    """
    print(f"[worker-package] Received job: {job_data}")
    # TODO: Move compilation logic from controller to here


@dramatiq.actor(queue_name="qh_package")
def validate_harness(job_data: dict):
    """Validate a compiled harness.

    v1: Stub. Validation happens synchronously in controller.
    """
    print(f"[worker-package] Validation job: {job_data}")
