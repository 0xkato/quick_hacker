# Flow Tree Enhancements - Integration Tests

This directory contains comprehensive integration tests for the 5 major flow tree enhancements implemented in this project.

## Test Coverage

### 1. Call Tracing Integration (`TestCallTracingIntegration`)

Tests call tracing functionality with depth limits across multiple files:

- **test_call_tracing_respects_depth_limit**: Verifies that call tracing stops at the configured `max_call_depth`
- **test_call_tracing_across_files**: Validates that call nodes are properly created when functions call across file boundaries
- **test_call_depth_increments_correctly**: Ensures call depth tracking increments correctly as we trace deeper into the call chain

### 2. Function Extraction Integration (`TestFunctionExtractionIntegration`)

Tests multi-language function extraction:

- **test_python_function_extraction**: Validates extraction of Python functions with line numbers
- **test_typescript_function_extraction**: Tests extraction of TypeScript arrow functions and methods
- **test_go_function_extraction**: Verifies Go function and method extraction (including receiver methods)
- **test_rust_function_extraction**: Tests Rust function extraction from impl blocks

### 3. Call Node Creation (`TestCallNodeCreation`)

Tests automatic creation of call nodes during function analysis:

- **test_call_nodes_created_during_analysis**: Verifies that analyzing a function creates call nodes for all invoked functions
- **test_external_call_nodes**: Tests that external library calls are properly marked as "external" node types

### 4. Context Tracking (`TestContextTracking`)

Tests investigation context management:

- **test_context_preserves_investigation_root**: Ensures context maintains the investigation root (candidate node) across operations
- **test_file_node_deduplication**: Validates that file nodes are deduplicated to prevent duplicate entries

### 5. Flow Statistics (`TestFlowStats`)

Tests flow metrics and statistics:

- **test_stats_with_multiple_node_types**: Verifies accurate counting of nodes by type
- **test_stats_with_different_statuses**: Tests status tracking (pending, running, completed)

### 6. End-to-End Integration (`TestEndToEndIntegration`)

Tests complete workflows:

- **test_complete_investigation_flow**: Validates entire flow from scan → entry point → file → function → call → finding
- **test_multiple_investigation_branches**: Tests parallel investigation trees with multiple entry points

## Running the Tests

### Run All Integration Tests

```bash
cd backend
pytest tests/integration/test_flow_enhancements.py -v
```

### Run Specific Test Class

```bash
# Test only call tracing
pytest tests/integration/test_flow_enhancements.py::TestCallTracingIntegration -v

# Test only function extraction
pytest tests/integration/test_flow_enhancements.py::TestFunctionExtractionIntegration -v
```

### Run Single Test

```bash
pytest tests/integration/test_flow_enhancements.py::TestCallTracingIntegration::test_call_tracing_respects_depth_limit -v
```

### Run with Coverage

```bash
pytest tests/integration/test_flow_enhancements.py --cov=backend.services --cov-report=html
```

### Run in Watch Mode

```bash
# Install pytest-watch first
pip install pytest-watch

# Run
ptw tests/integration/test_flow_enhancements.py -v
```

## Test Architecture

### Mock Flow Service

The tests use a `MockFlowService` class that implements the core flow service interface:

- `initialize_flow()`: Create new investigation flow
- `add_node()`: Add nodes to the flow graph
- `update_context()`: Update investigation context (file, function, depth)
- `get_or_create_file_node()`: Deduplicate file nodes
- `update_node_status()`: Change node status (pending → running → completed)
- `get_flow_stats()`: Calculate flow statistics

This mock allows testing the integration between different components without requiring the full backend stack.

### Test Data Structures

Tests use dataclasses that mirror the production types:

```python
@dataclass
class FlowNode:
    id: str
    type: NodeType
    label: str
    status: str
    data: dict
    timestamp: str

@dataclass
class FlowContext:
    current_file: Optional[str]
    current_function: Optional[str]
    current_candidate_node_id: Optional[str]
    investigation_root_id: Optional[str]
    call_depth: int
    max_call_depth: int
```

## Expected Test Results

All 15 tests should pass:

```
============================= test session starts ==============================
collected 15 items

tests/integration/test_flow_enhancements.py::TestCallTracingIntegration::test_call_tracing_respects_depth_limit PASSED [  6%]
tests/integration/test_flow_enhancements.py::TestCallTracingIntegration::test_call_tracing_across_files PASSED [ 13%]
tests/integration/test_flow_enhancements.py::TestCallTracingIntegration::test_call_depth_increments_correctly PASSED [ 20%]
tests/integration/test_flow_enhancements.py::TestFunctionExtractionIntegration::test_python_function_extraction PASSED [ 26%]
tests/integration/test_flow_enhancements.py::TestFunctionExtractionIntegration::test_typescript_function_extraction PASSED [ 33%]
tests/integration/test_flow_enhancements.py::TestFunctionExtractionIntegration::test_go_function_extraction PASSED [ 40%]
tests/integration/test_flow_enhancements.py::TestFunctionExtractionIntegration::test_rust_function_extraction PASSED [ 46%]
tests/integration/test_flow_enhancements.py::TestCallNodeCreation::test_call_nodes_created_during_analysis PASSED [ 53%]
tests/integration/test_flow_enhancements.py::TestCallNodeCreation::test_external_call_nodes PASSED [ 60%]
tests/integration/test_flow_enhancements.py::TestContextTracking::test_context_preserves_investigation_root PASSED [ 66%]
tests/integration/test_flow_enhancements.py::TestContextTracking::test_file_node_deduplication PASSED [ 73%]
tests/integration/test_flow_enhancements.py::TestFlowStats::test_stats_with_multiple_node_types PASSED [ 80%]
tests/integration/test_flow_enhancements.py::TestFlowStats::test_stats_with_different_statuses PASSED [ 86%]
tests/integration/test_flow_enhancements.py::TestEndToEndIntegration::test_complete_investigation_flow PASSED [ 93%]
tests/integration/test_flow_enhancements.py::TestEndToEndIntegration::test_multiple_investigation_branches PASSED [100%]

============================== 15 passed in 0.03s ==============================
```

## Frontend Integration Tests

Frontend integration tests are documented in:
- `test_frontend_integration_spec.md` - Full specification of frontend tests
- `integration.test.tsx.template` - TypeScript test template

To use the frontend tests:

1. Copy `integration.test.tsx.template` to `frontend/components/FlowVisualization/__tests__/integration.test.tsx`
2. Install dependencies:
   ```bash
   cd frontend
   npm install --save-dev @testing-library/react @testing-library/user-event @testing-library/jest-dom
   ```
3. Run tests:
   ```bash
   npm test -- integration.test.tsx
   ```

## Integration with Real Implementation

When the actual `FlowService` is implemented, these tests should be updated to:

1. Replace `MockFlowService` with the real service
2. Add database/persistence layer tests
3. Test WebSocket event emission
4. Add performance benchmarks
5. Test error handling and edge cases

## Performance Expectations

These integration tests are designed to run quickly:

- Individual test: < 10ms
- Full test suite: < 100ms
- With coverage: < 500ms

## Continuous Integration

Add to your CI pipeline:

```yaml
# .github/workflows/test.yml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - run: pytest backend/tests/integration/ -v --cov
```

## Troubleshooting

### Tests fail with "ModuleNotFoundError"

Make sure you're in the backend directory and have installed dependencies:

```bash
cd backend
pip install -r requirements.txt  # or requirements-dev.txt
```

### Slow test execution

Integration tests should be fast. If they're slow:

1. Check for unnecessary I/O operations
2. Ensure mocks are being used properly
3. Profile with `pytest --profile`

### Test flakiness

These tests should be deterministic. If you see flaky failures:

1. Check for timing issues in async code
2. Verify test isolation (no shared state)
3. Add explicit waits where needed

## Related Documentation

- [Flow Visualization Tree Structure Design](../../../docs/plans/2026-01-11-flow-visualization-tree-structure-design.md)
- [Frontend Integration Test Spec](./test_frontend_integration_spec.md)
- [Frontend Test Template](./integration.test.tsx.template)
