#!/usr/bin/env python3
"""
Test script to verify ReAct agent uses cache correctly.
"""
import tempfile
import os
import subprocess
from services.tool_cache import ToolCache
from agents.tools import ToolExecutor

def test_tool_executor_cache():
    """Test that ToolExecutor properly uses cache."""
    print("Testing ToolExecutor cache integration...\n")

    # Create a temporary directory with test file and git repo
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize git repo (required for caching)
        subprocess.run(['git', 'init'], cwd=tmpdir, capture_output=True, check=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmpdir, capture_output=True, check=True)
        subprocess.run(['git', 'config', 'user.name', 'Test User'], cwd=tmpdir, capture_output=True, check=True)

        # Create test file
        test_file = os.path.join(tmpdir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('def hello():\n    print("hello")\n')

        # Commit the file
        subprocess.run(['git', 'add', 'test.py'], cwd=tmpdir, capture_output=True, check=True)
        subprocess.run(['git', 'commit', '-m', 'Initial commit'], cwd=tmpdir, capture_output=True, check=True)

        print(f"✓ Created git repository with test file")

        # Create cache
        cache = ToolCache(max_size=100, ttl_seconds=3600)
        print(f"✓ Created cache with max_size=100, ttl=3600s")

        # Create ToolExecutor with cache
        executor = ToolExecutor(tmpdir, project_id='test-project', cache=cache)
        print(f"✓ Created ToolExecutor with cache\n")

        # Check that executor has _tool_core with cache
        if not hasattr(executor, '_tool_core'):
            print("✗ ToolExecutor missing _tool_core attribute")
            return False

        if not hasattr(executor._tool_core, 'cache'):
            print("✗ ToolCore missing cache attribute")
            return False

        if executor._tool_core.cache is not cache:
            print("✗ ToolCore cache is not the same instance")
            return False

        print("✓ ToolExecutor._tool_core.cache is properly wired")

        # Check git HEAD tracker
        if executor._tool_core.git_head_tracker is None:
            print("✗ GitHeadTracker not initialized")
            return False

        git_head = executor._tool_core.git_head_tracker.get_current_head()
        if git_head is None:
            print("✗ Git HEAD is None")
            return False

        print(f"✓ Git HEAD available: {git_head[:8]}...\n")

        # Test that cache is being used by calling through ToolCore
        print("Testing cache behavior:")
        import asyncio

        # First call - should be a miss
        result1 = asyncio.run(executor._tool_core.read_file('test.py'))
        metrics1 = cache.get_metrics()
        print(f"  First read_file call:")
        print(f"    Hits: {metrics1['hits']}, Misses: {metrics1['misses']}, Size: {metrics1['size']}")

        # Second call - should be a hit
        result2 = asyncio.run(executor._tool_core.read_file('test.py'))
        metrics2 = cache.get_metrics()
        print(f"  Second read_file call:")
        print(f"    Hits: {metrics2['hits']}, Misses: {metrics2['misses']}, Size: {metrics2['size']}")

        # Verify results
        print("\nVerification:")
        if metrics1['misses'] == 1 and metrics1['hits'] == 0:
            print("  ✓ First call was a cache miss (expected)")
        else:
            print(f"  ✗ First call metrics incorrect: {metrics1}")
            return False

        if metrics2['hits'] == 1 and metrics2['misses'] == 1:
            print("  ✓ Second call was a cache hit (expected)")
        else:
            print(f"  ✗ Second call metrics incorrect: {metrics2}")
            return False

        if result1['content'] == result2['content']:
            print("  ✓ Both calls returned the same content")
        else:
            print("  ✗ Contents differ")
            return False

        if metrics2['size'] == 1:
            print("  ✓ Cache has 1 entry")
        else:
            print(f"  ✗ Cache size incorrect: {metrics2['size']}")
            return False

        print("\n✓ All tests passed! ReAct agent caching is working correctly.")
        return True

if __name__ == '__main__':
    success = test_tool_executor_cache()
    exit(0 if success else 1)
