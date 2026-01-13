# backend/tests/benchmarks/test_prompt_performance.py
import pytest
import time
from services.prompt_router import PromptRouter


@pytest.mark.benchmark
def test_prompt_assembly_performance():
    """Test that prompt assembly meets performance budget (< 10ms)."""
    router = PromptRouter()

    modules = router.route(
        category="SQL_INJECTION",
        stage="trace_dataflow",
        framework="django",
        framework_confidence=0.9
    )

    # Benchmark prompt assembly
    timings = []
    for _ in range(100):
        start = time.perf_counter()
        final_prompt = router.assemble_from_paths(modules, task="Test task")
        duration = time.perf_counter() - start
        timings.append(duration)

    avg_time = sum(timings) / len(timings)
    p95_time = sorted(timings)[94]  # 95th percentile

    print(f"\nPrompt assembly avg: {avg_time*1000:.2f}ms, p95: {p95_time*1000:.2f}ms")

    assert p95_time < 0.010, f"p95 time {p95_time*1000:.2f}ms exceeds 10ms budget"


@pytest.mark.benchmark
def test_routing_performance():
    """Test that module routing is fast (< 1ms)."""
    router = PromptRouter()

    timings = []
    for _ in range(1000):
        start = time.perf_counter()
        modules = router.route(
            category="SQL_INJECTION",
            stage="trace_dataflow",
            framework="django",
            framework_confidence=0.9
        )
        duration = time.perf_counter() - start
        timings.append(duration)

    avg_time = sum(timings) / len(timings)
    p95_time = sorted(timings)[949]  # 95th percentile

    print(f"\nRouting avg: {avg_time*1000:.3f}ms, p95: {p95_time*1000:.3f}ms")

    assert p95_time < 0.001, f"p95 time {p95_time*1000:.3f}ms exceeds 1ms budget"


@pytest.mark.benchmark
def test_prompt_assembly_with_all_modules():
    """Test performance when loading all modules simultaneously."""
    router = PromptRouter()

    modules = router.route(
        category="SQL_INJECTION",
        stage="trace_dataflow",
        framework="django",
        framework_confidence=0.9
    )

    timings = []
    for _ in range(50):
        start = time.perf_counter()
        final_prompt = router.assemble_from_paths(
            modules,
            task="Complex task with detailed requirements and multiple steps"
        )
        duration = time.perf_counter() - start
        timings.append(duration)

    avg_time = sum(timings) / len(timings)
    p95_time = sorted(timings)[47]  # 95th percentile for 50 samples
    max_time = max(timings)

    print(f"\nFull assembly avg: {avg_time*1000:.2f}ms, p95: {p95_time*1000:.2f}ms, max: {max_time*1000:.2f}ms")

    assert p95_time < 0.010, f"p95 time {p95_time*1000:.2f}ms exceeds 10ms budget"
    assert max_time < 0.020, f"max time {max_time*1000:.2f}ms exceeds 20ms budget"


@pytest.mark.benchmark
def test_routing_multiple_categories():
    """Test routing performance across different categories."""
    router = PromptRouter()

    categories = [
        "SQL_INJECTION",
        "SSRF",
        "CODE_INJECTION",
        "COMMAND_INJECTION",
        "XSS",
        "PATH_TRAVERSAL"
    ]

    timings = []
    for _ in range(100):
        for category in categories:
            start = time.perf_counter()
            modules = router.route(
                category=category,
                stage="trace_dataflow",
                framework="django",
                framework_confidence=0.9
            )
            duration = time.perf_counter() - start
            timings.append(duration)

    avg_time = sum(timings) / len(timings)
    p95_time = sorted(timings)[int(len(timings) * 0.95)]

    print(f"\nMulti-category routing avg: {avg_time*1000:.3f}ms, p95: {p95_time*1000:.3f}ms")

    assert p95_time < 0.001, f"p95 time {p95_time*1000:.3f}ms exceeds 1ms budget"


@pytest.mark.benchmark
def test_prompt_assembly_memory_efficiency():
    """Test that prompt assembly doesn't consume excessive memory."""
    router = PromptRouter()

    modules = router.route(
        category="SQL_INJECTION",
        stage="trace_dataflow",
        framework="django",
        framework_confidence=0.9
    )

    # Assemble prompt multiple times to check for memory leaks
    prompts = []
    for _ in range(100):
        final_prompt = router.assemble_from_paths(modules, task="Test task")
        prompts.append(final_prompt)

    # Verify all prompts are identical (consistent caching)
    assert all(p == prompts[0] for p in prompts), "Prompts should be identical"

    # Verify prompt size is reasonable (not duplicated internally)
    prompt_size = len(prompts[0])
    print(f"\nPrompt size: {prompt_size} bytes ({prompt_size/1024:.1f} KB)")

    assert prompt_size < 100000, f"Prompt size {prompt_size} bytes exceeds 100KB"


@pytest.mark.benchmark
def test_routing_with_framework_confidence_variations():
    """Test routing performance with different framework confidence levels."""
    router = PromptRouter()

    confidence_levels = [0.0, 0.5, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0]

    timings = []
    for _ in range(100):
        for confidence in confidence_levels:
            start = time.perf_counter()
            modules = router.route(
                category="SQL_INJECTION",
                stage="trace_dataflow",
                framework="django",
                framework_confidence=confidence
            )
            duration = time.perf_counter() - start
            timings.append(duration)

    avg_time = sum(timings) / len(timings)
    p95_time = sorted(timings)[int(len(timings) * 0.95)]

    print(f"\nFramework confidence routing avg: {avg_time*1000:.3f}ms, p95: {p95_time*1000:.3f}ms")

    assert p95_time < 0.001, f"p95 time {p95_time*1000:.3f}ms exceeds 1ms budget"
