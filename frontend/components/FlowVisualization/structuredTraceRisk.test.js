const test = require('node:test');
const assert = require('node:assert/strict');

const {
  computeStructuredTraceRiskLevels,
  getStructuredTraceRiskRingClass,
} = require('./structuredTraceRisk');

test('computeStructuredTraceRiskLevels marks findings without propagation', () => {
  const nodes = [
    { id: 'root', type: 'structured_root' },
    { id: 'steps', type: 'steps' },
    { id: 'tool', type: 'tool_call' },
    { id: 'finding', type: 'finding', data: { severity: 'high' } },
  ];
  const edges = [
    { source: 'root', target: 'steps' },
    { source: 'steps', target: 'tool' },
    { source: 'steps', target: 'finding' },
  ];

  const risk = computeStructuredTraceRiskLevels(nodes, edges);

  assert.equal(risk.root, 'none');
  assert.equal(risk.steps, 'finding');
  assert.equal(risk.tool, 'none');
  assert.equal(risk.finding, 'finding');
});

test('computeStructuredTraceRiskLevels marks sinks without propagation', () => {
  const nodes = [
    { id: 'root', type: 'structured_root' },
    { id: 'steps', type: 'steps' },
    { id: 'sink', type: 'dangerous_sink' },
  ];
  const edges = [
    { source: 'root', target: 'steps' },
    { source: 'steps', target: 'sink' },
  ];

  const risk = computeStructuredTraceRiskLevels(nodes, edges);

  assert.equal(risk.root, 'none');
  assert.equal(risk.steps, 'sink');
  assert.equal(risk.sink, 'sink');
});

test('computeStructuredTraceRiskLevels ignores non-finding "finding" nodes', () => {
  const nodes = [
    { id: 'root', type: 'structured_root' },
    { id: 'steps', type: 'steps' },
    // Tool-call shaped node that should not count as an actual finding.
    { id: 'tool', type: 'finding', label: 'report_finding: {...}', data: { tool: 'report_finding', args: { severity: 'high' } } },
  ];
  const edges = [
    { source: 'root', target: 'steps' },
    { source: 'steps', target: 'tool' },
  ];

  const risk = computeStructuredTraceRiskLevels(nodes, edges);

  assert.equal(risk.root, 'none');
  assert.equal(risk.steps, 'none');
  assert.equal(risk.tool, 'none');
});

test('getStructuredTraceRiskRingClass maps risk tiers', () => {
  assert.match(
    getStructuredTraceRiskRingClass({ risk: 'none', isTouchedEntrypoint: false }),
    /ring-vsc-success/
  );
  assert.match(
    getStructuredTraceRiskRingClass({ risk: 'sink', isTouchedEntrypoint: false }),
    /ring-sev-medium/
  );
  assert.match(
    getStructuredTraceRiskRingClass({ risk: 'finding', isTouchedEntrypoint: false }),
    /ring-sev-critical/
  );
});

test('getStructuredTraceRiskRingClass uses accent for touched entrypoint', () => {
  assert.match(
    getStructuredTraceRiskRingClass({ risk: 'none', isTouchedEntrypoint: true }),
    /ring-vsc-accent/
  );
});
