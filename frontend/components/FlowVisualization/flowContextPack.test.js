const test = require('node:test');
const assert = require('node:assert/strict');

async function loadContextPack() {
  try {
    // eslint-disable-next-line no-undef
    return await import('./flowContextPack.js');
  } catch (err) {
    assert.fail(`Expected flowContextPack.js to exist and be importable, but got: ${String(err)}`);
  }
}

test('getStructuredSubgraph returns only structured edges and connected nodes', async () => {
  const { getStructuredSubgraph } = await loadContextPack();
  assert.equal(typeof getStructuredSubgraph, 'function');

  const flow = {
    session_id: 'a1',
    nodes: [
      { id: 'start', type: 'user_input', label: 'start' },
      { id: 'root', type: 'structured_root', label: 'Structured Trace' },
      { id: 'global', type: 'global_recon', label: 'Global Recon' },
      { id: 'steps', type: 'steps', label: 'Steps', data: { file_path: 'a.py' } },
      { id: 'tool', type: 'tool_call', label: 'read_file' },
      { id: 'finding', type: 'finding', label: 'HIGH: Test', data: { severity: 'high', finding_id: 'f1' } },
      { id: 'legacyOnly', type: 'analysis', label: 'legacy' },
    ],
    edges: [
      { id: 'e0', source: 'start', target: 'root', kind: 'legacy' },
      { id: 'e1', source: 'root', target: 'global', kind: 'structured' },
      { id: 'e2', source: 'global', target: 'steps', kind: 'structured' },
      { id: 'e3', source: 'steps', target: 'tool', kind: 'structured' },
      { id: 'e4', source: 'steps', target: 'finding', kind: 'structured' },
      { id: 'e5', source: 'start', target: 'legacyOnly', kind: 'legacy' },
    ],
  };

  const sub = getStructuredSubgraph(flow);
  assert.equal(sub.edges.length, 4);
  assert.deepEqual(
    sub.edges.map((e) => e.id).sort(),
    ['e1', 'e2', 'e3', 'e4']
  );
  assert.deepEqual(
    sub.nodes.map((n) => n.id).sort(),
    ['finding', 'global', 'root', 'steps', 'tool']
  );
});

test('buildFlowContextPack includes selected node, path, and matching finding details', async () => {
  const { buildFlowContextPack } = await loadContextPack();
  assert.equal(typeof buildFlowContextPack, 'function');

  const flow = {
    session_id: 'a1',
    nodes: [
      { id: 'root', type: 'structured_root', label: 'Structured Trace' },
      { id: 'global', type: 'global_recon', label: 'Global Recon' },
      { id: 'steps', type: 'steps', label: 'Steps', data: { file_path: 'a.py' } },
      { id: 'finding', type: 'finding', label: 'HIGH: SQLi', data: { severity: 'high', finding_id: 'f1' } },
    ],
    edges: [
      { id: 'e1', source: 'root', target: 'global', kind: 'structured' },
      { id: 'e2', source: 'global', target: 'steps', kind: 'structured' },
      { id: 'e3', source: 'steps', target: 'finding', kind: 'structured' },
    ],
  };

  const findings = [
    {
      id: 'f1',
      severity: 'high',
      title: 'SQL injection',
      description: 'User input reaches query',
      file_path: 'a.py',
      line_start: 10,
      vulnerability_type: 'sql_injection',
    },
  ];

  const pack = buildFlowContextPack({ flow, nodeId: 'finding', findings });
  assert.equal(pack.selected_node.id, 'finding');
  assert.equal(pack.selected_node.type, 'finding');

  assert.ok(Array.isArray(pack.path));
  assert.deepEqual(
    pack.path.map((p) => p.id),
    ['root', 'global', 'steps', 'finding']
  );

  assert.equal(pack.finding.id, 'f1');
  assert.equal(pack.finding.title, 'SQL injection');
});

test('buildFlowContextPack truncates very large fields', async () => {
  const { buildFlowContextPack } = await loadContextPack();

  const flow = {
    session_id: 'a1',
    nodes: [
      {
        id: 'finding',
        type: 'finding',
        label: 'HIGH: Big',
        llm_reasoning: 'x'.repeat(10000),
        tool_result_summary: 'y'.repeat(10000),
        code_context: 'z'.repeat(10000),
        data: { severity: 'high' },
      },
    ],
    edges: [],
  };

  const pack = buildFlowContextPack({ flow, nodeId: 'finding', findings: [] });
  assert.ok(pack.selected_node.llm_reasoning.length < 5000);
  assert.ok(pack.selected_node.tool_result_summary.length < 5000);
  assert.ok(pack.selected_node.code_context.length < 5000);
});

