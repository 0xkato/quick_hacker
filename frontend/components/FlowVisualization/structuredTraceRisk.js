function maxRisk(a, b) {
  const priority = { none: 0, sink: 1, finding: 2 };
  return priority[b] > priority[a] ? b : a;
}

function isActualFindingNode(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type !== 'finding') return false;
  const data = node.data && typeof node.data === 'object' ? node.data : null;
  if (!data) return false;
  const hasSeverity = typeof data.severity === 'string' && data.severity.trim();
  const hasFindingId = typeof data.finding_id === 'string' && data.finding_id.trim();
  const hasFindingPayload = data.finding && typeof data.finding === 'object';
  return Boolean(hasSeverity || hasFindingId || hasFindingPayload);
}

function baseRisk(node) {
  if (!node) return 'none';
  if (isActualFindingNode(node)) return 'finding';
  if (node.type === 'dangerous_sink') return 'sink';
  return 'none';
}

/**
 * Computes a risk tier per node.
 *
 * Design goal for Structured Trace:
 * - Leaf nodes: sinks (yellow) + findings (red)
 * - Collapsible containers (steps/file/function): inherit the max risk of their subtree
 * - Global containers (root/global_recon/folder/etc): stay green to avoid painting the whole graph
 *
 * @param {{id: string, type: string}[]} nodes
 * @param {{source: string, target: string}[]} edges
 * @returns {Record<string, 'none' | 'sink' | 'finding'>}
 */
function computeStructuredTraceRiskLevels(nodes, edges) {
  const nodeById = new Map((nodes || []).map((n) => [n.id, n]));
  const childrenById = new Map();
  for (const edge of edges || []) {
    if (!edge || typeof edge.source !== 'string' || typeof edge.target !== 'string') continue;
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) continue;
    const current = childrenById.get(edge.source) || [];
    current.push(edge.target);
    childrenById.set(edge.source, current);
  }

  const memo = new Map();
  const visiting = new Set();

  const dfs = (nodeId) => {
    const cached = memo.get(nodeId);
    if (cached) return cached;

    const node = nodeById.get(nodeId);
    if (!node) return 'none';

    if (visiting.has(nodeId)) return baseRisk(node);
    visiting.add(nodeId);

    let risk = baseRisk(node);
    const children = childrenById.get(nodeId) || [];
    for (const childId of children) {
      risk = maxRisk(risk, dfs(childId));
    }

    visiting.delete(nodeId);
    memo.set(nodeId, risk);
    return risk;
  };

  const containerTypes = new Set(['steps', 'function', 'file']);

  const riskById = {};
  for (const node of nodes || []) {
    const own = baseRisk(node);
    // Only propagate into local, user-collapsible containers.
    riskById[node.id] = containerTypes.has(node.type) ? dfs(node.id) : own;
  }
  return riskById;
}

/**
 * Tailwind ring classes for Structured Trace tiering.
 *
 * Priority: finding (red) > sink (yellow) > touched (blue) > normal (green)
 *
 * @param {{risk: 'none'|'sink'|'finding', isTouchedEntrypoint: boolean}} opts
 */
function getStructuredTraceRiskRingClass({ risk, isTouchedEntrypoint }) {
  if (risk === 'finding') return 'ring-2 ring-node-finding ring-offset-1 ring-offset-vsc-bg';
  if (risk === 'sink') return 'ring-2 ring-node-sink ring-offset-1 ring-offset-vsc-bg';
  if (isTouchedEntrypoint) return 'ring-2 ring-node-touched ring-offset-1 ring-offset-vsc-bg';
  return 'ring-2 ring-node-normal ring-offset-1 ring-offset-vsc-bg';
}

module.exports = {
  computeStructuredTraceRiskLevels,
  getStructuredTraceRiskRingClass,
};
