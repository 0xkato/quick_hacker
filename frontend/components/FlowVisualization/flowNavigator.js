const SEVERITY_PRIORITY = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

function normalizeSeverity(value) {
  if (typeof value !== 'string') return 'unknown';
  const s = value.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(SEVERITY_PRIORITY, s) ? s : 'unknown';
}

function inferSeverityFromLabel(label) {
  if (typeof label !== 'string') return 'unknown';
  const prefix = label.split(':', 1)[0];
  return normalizeSeverity(prefix);
}

function inferSeverity(node) {
  if (!node || typeof node !== 'object') return 'unknown';
  const direct = node.data && typeof node.data === 'object' ? node.data.severity : undefined;
  if (typeof direct === 'string' && direct.trim()) return normalizeSeverity(direct);
  return inferSeverityFromLabel(node.label);
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

/**
 * Index nodes by type for quick navigation in the Structured Trace UI.
 *
 * @param {{id: string, type: string, label: string, data?: any}[]} nodes
 * @param {string} type
 */
function indexNodesByType(nodes, type) {
  const filtered = (nodes || []).filter((n) => {
    if (!n || n.type !== type) return false;
    if (type === 'finding') return isActualFindingNode(n);
    return true;
  });
  const items = filtered.map((n) => ({
    id: n.id,
    type: n.type,
    label: n.label,
    severity: type === 'finding' ? inferSeverity(n) : undefined,
    file_path: n.data && typeof n.data === 'object' ? n.data.file_path : undefined,
    line_number: n.data && typeof n.data === 'object' ? n.data.line_number : undefined,
  }));

  items.sort((a, b) => {
    if (type === 'finding') {
      const ap = SEVERITY_PRIORITY[normalizeSeverity(a.severity)];
      const bp = SEVERITY_PRIORITY[normalizeSeverity(b.severity)];
      if (bp !== ap) return bp - ap;
    }
    return String(a.label).localeCompare(String(b.label));
  });

  return items;
}

/**
 * Expand all ancestors for a target node id in a parent-pointer tree (best-effort).
 *
 * @param {Record<string, boolean>} collapsed
 * @param {string} targetId
 * @param {{source: string, target: string}[]} edges
 * @returns {Record<string, boolean>}
 */
function expandAncestors(collapsed, targetId, edges) {
  const next = { ...(collapsed || {}) };
  if (typeof targetId !== 'string' || !targetId) return next;
  next[targetId] = false;

  const visited = new Set();
  let current = targetId;

  while (current && !visited.has(current)) {
    visited.add(current);
    const parentEdge = (edges || []).find((e) => e && e.target === current);
    if (!parentEdge || typeof parentEdge.source !== 'string' || !parentEdge.source) break;
    next[parentEdge.source] = false;
    current = parentEdge.source;
  }

  return next;
}

module.exports = {
  indexNodesByType,
  expandAncestors,
};
