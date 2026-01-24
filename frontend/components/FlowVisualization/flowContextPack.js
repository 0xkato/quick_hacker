const DEFAULT_MAX_FIELD_CHARS = 4000;

function truncate(value, maxChars = DEFAULT_MAX_FIELD_CHARS) {
  if (typeof value !== 'string') return value;
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}\n... [truncated]`;
}

function normalizeEdgeKind(edge) {
  if (!edge || typeof edge !== 'object') return 'legacy';
  const kind = edge.kind;
  return typeof kind === 'string' && kind.trim() ? kind.trim() : 'legacy';
}

function getStructuredSubgraph(flow) {
  const nodes = Array.isArray(flow?.nodes) ? flow.nodes : [];
  const edges = Array.isArray(flow?.edges) ? flow.edges : [];
  const structuredEdges = edges.filter((e) => normalizeEdgeKind(e) === 'structured');

  const nodeIds = new Set();
  for (const edge of structuredEdges) {
    if (!edge) continue;
    if (typeof edge.source === 'string') nodeIds.add(edge.source);
    if (typeof edge.target === 'string') nodeIds.add(edge.target);
  }

  const structuredNodes = nodes.filter((n) => n && nodeIds.has(n.id));
  return { nodes: structuredNodes, edges: structuredEdges };
}

function getNodeData(node) {
  if (!node || typeof node !== 'object') return null;
  const data = node.data;
  return data && typeof data === 'object' ? data : null;
}

function summarizeNode(node) {
  const data = getNodeData(node);
  const filePath = data?.file_path || data?.file || data?.full_path;
  const lineNumber = data?.line_number || data?.line_start;
  const findingId = data?.finding_id;
  const severity = data?.severity;

  return {
    id: node.id,
    type: node.type,
    label: node.label,
    file_path: typeof filePath === 'string' ? filePath : undefined,
    line_number: typeof lineNumber === 'number' ? lineNumber : undefined,
    severity: typeof severity === 'string' ? severity : undefined,
    finding_id: typeof findingId === 'string' ? findingId : undefined,
  };
}

function buildParentByChild(edges) {
  const parentByChild = new Map();
  for (const edge of edges || []) {
    if (!edge || typeof edge.source !== 'string' || typeof edge.target !== 'string') continue;
    if (!edge.source || !edge.target) continue;
    if (parentByChild.has(edge.target)) continue;
    parentByChild.set(edge.target, edge.source);
  }
  return parentByChild;
}

function buildPath(nodeId, parentByChild) {
  const path = [];
  const visited = new Set();
  let current = nodeId;

  while (typeof current === 'string' && current && !visited.has(current)) {
    visited.add(current);
    path.push(current);
    current = parentByChild.get(current);
  }

  return path.reverse();
}

function selectFinding(findings, findingId) {
  if (!Array.isArray(findings) || typeof findingId !== 'string' || !findingId) return null;
  const match = findings.find((f) => f && f.id === findingId);
  if (!match) return null;
  return {
    id: match.id,
    severity: match.severity ?? null,
    title: match.title,
    description: match.description,
    file_path: match.file_path,
    line_start: match.line_start,
    line_end: match.line_end,
    vulnerability_type: match.vulnerability_type,
    attack_scenario: match.attack_scenario,
    recommended_fix: match.recommended_fix,
    confidence: match.confidence,
  };
}

function buildFlowContextPack({ flow, nodeId, findings }) {
  const allNodes = Array.isArray(flow?.nodes) ? flow.nodes : [];
  const selected = allNodes.find((n) => n && n.id === nodeId) || null;

  const structuredEdges = Array.isArray(flow?.edges)
    ? flow.edges.filter((e) => normalizeEdgeKind(e) === 'structured')
    : [];

  const parentByChild = buildParentByChild(structuredEdges);
  const pathIds = buildPath(nodeId, parentByChild);

  const nodeById = new Map(allNodes.map((n) => [n.id, n]));
  const path = pathIds
    .map((id) => nodeById.get(id))
    .filter(Boolean)
    .map(summarizeNode);

  const selectedSummary = selected
    ? {
        ...summarizeNode(selected),
        llm_reasoning: truncate(selected.llm_reasoning),
        tool_result_summary: truncate(selected.tool_result_summary),
        code_context: truncate(selected.code_context),
      }
    : { id: nodeId, type: 'unknown', label: '' };

  const findingId = getNodeData(selected)?.finding_id;
  const finding = selectFinding(findings, findingId);

  return {
    version: 1,
    session_id: typeof flow?.session_id === 'string' ? flow.session_id : undefined,
    selected_node: selectedSummary,
    path,
    finding,
  };
}

module.exports = {
  getStructuredSubgraph,
  buildFlowContextPack,
};

