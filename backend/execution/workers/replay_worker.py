"""Dramatiq actor for replaying and minimizing artifacts."""
import dramatiq
from execution.broker import get_broker

broker = get_broker()


@dramatiq.actor(queue_name="qh_replay")
def replay_artifact(job_data: dict):
    """Replay an artifact for reproducibility confirmation.

    v1: Stub. Replay logic is in evidence/replayer.py but not wired to queue.
    """
    print(f"[worker-replay] Replay job: {job_data}")


@dramatiq.actor(queue_name="qh_replay")
def minimize_artifact(job_data: dict):
    """Minimize an artifact to its simplest reproducing form.

    v1: Stub.
    """
    print(f"[worker-replay] Minimize job: {job_data}")
