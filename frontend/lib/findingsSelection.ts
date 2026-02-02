import type { Agent, Finding } from '../types';

export interface AutoSelectFindingsAgentArgs {
  agents: Agent[];
  findings: Finding[];
  selectedAgentId: string | null;
  selectedFindingsAgentId: string | null;
  userSelectedFindingsAgentId: boolean;
}

/**
 * Compute the Findings view agent selection.
 */
export function autoSelectFindingsAgentId({
  agents,
  findings,
  selectedAgentId,
  selectedFindingsAgentId,
  userSelectedFindingsAgentId,
}: AutoSelectFindingsAgentArgs): string | null {
  if (agents.length === 0) return null;

  const agentIds = new Set(agents.map((a) => a.id));

  // Respect manual selection, including "all agents" (null).
  if (userSelectedFindingsAgentId) {
    if (!selectedFindingsAgentId) return null;
    return agentIds.has(selectedFindingsAgentId) ? selectedFindingsAgentId : null;
  }

  const currentSelection = selectedFindingsAgentId && agentIds.has(selectedFindingsAgentId)
    ? selectedFindingsAgentId
    : null;

  const findingsByAgent = new Map<string, number>();
  for (const finding of findings) {
    findingsByAgent.set(finding.agent_id, (findingsByAgent.get(finding.agent_id) || 0) + 1);
  }

  // Prefer the currently-selected Flow agent when it has findings.
  if (selectedAgentId && agentIds.has(selectedAgentId) && (findingsByAgent.get(selectedAgentId) || 0) > 0) {
    return selectedAgentId;
  }

  // Pick the agent with the most findings (falling back to first).
  let bestAgentId = agents[0]?.id ?? null;
  let bestCount = bestAgentId ? findingsByAgent.get(bestAgentId) || 0 : 0;
  for (const agent of agents) {
    const count = findingsByAgent.get(agent.id) || 0;
    if (count > bestCount) {
      bestAgentId = agent.id;
      bestCount = count;
    }
  }

  // No current selection: use best.
  if (!currentSelection) return bestAgentId;

  // Auto-upgrade selection if another agent has more findings.
  const currentCount = findingsByAgent.get(currentSelection) || 0;
  if (bestAgentId && bestCount > currentCount) return bestAgentId;

  return currentSelection;
}
