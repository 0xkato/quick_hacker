const test = require('node:test');
const assert = require('node:assert/strict');

async function loadNavigator() {
  try {
    // eslint-disable-next-line no-undef
    return await import('./flowNavigator.js');
  } catch (err) {
    assert.fail(`Expected flowNavigator.js to exist and be importable, but got: ${String(err)}`);
  }
}

test('indexNodesByType returns nodes of a specific type', async () => {
  const { indexNodesByType } = await loadNavigator();
  assert.equal(typeof indexNodesByType, 'function');

  const nodes = [
    { id: 'a', type: 'finding', label: 'HIGH: SQLi', data: { severity: 'high' } },
    { id: 'b', type: 'dangerous_sink', label: '⚠️ EXEC sink' },
    { id: 'c', type: 'finding', label: 'CRITICAL: RCE', data: { severity: 'critical' } },
    // This is a tool-call node that may have type "finding" but is not an actual finding node.
    { id: 'tool', type: 'finding', label: 'report_finding: {...}', data: { tool: 'report_finding', args: { severity: 'high' } } },
  ];

  const results = indexNodesByType(nodes, 'finding');
  assert.deepEqual(
    results.map((r) => r.id),
    ['c', 'a'],
    'Expected findings to be returned in deterministic order (severity, then label)'
  );
});

test('expandAncestors expands parent chain without mutating input', async () => {
  const { expandAncestors } = await loadNavigator();
  assert.equal(typeof expandAncestors, 'function');

  const edges = [
    { source: 'root', target: 'steps' },
    { source: 'steps', target: 'finding' },
  ];

  const collapsed = { root: true, steps: true, finding: false };
  const next = expandAncestors(collapsed, 'finding', edges);

  assert.notEqual(next, collapsed, 'Expected a new object');
  assert.equal(collapsed.root, true, 'Expected input not to be mutated');
  assert.equal(next.root, false);
  assert.equal(next.steps, false);
  assert.equal(next.finding, false);
});
