import { test, expect } from '@playwright/test';

import { autoSelectFindingsAgentId } from './lib/findingsSelection';
import type { Agent, Finding } from './types';

function makeAgent(overrides: Partial<Agent>): Agent {
  return {
    id: 'agent-id',
    repo_id: 'repo-id',
    name: 'agent',
    agent_type: 'deep_audit',
    status: 'completed',
    provider_config: { provider: 'openai', model: 'gpt-4o-mini' },
    created_at: new Date().toISOString(),
    files_analyzed: 0,
    findings_count: 0,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: 'finding-id',
    agent_id: 'agent-id',
    repo_id: 'repo-id',
    severity: 'high',
    title: 'Finding',
    description: 'Description',
    file_path: 'app.py',
    line_start: 1,
    vulnerability_type: 'command_injection',
    confidence: 0.5,
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

test('autoSelectFindingsAgentId prefers agent with findings after findings load', () => {
  const agents: Agent[] = [
    makeAgent({ id: 'agent-zero', name: 'Zero', findings_count: 0 }),
    makeAgent({ id: 'agent-six', name: 'Six', findings_count: 6 }),
  ];

  // Initial load: user enters Findings view before findings are loaded.
  const initialSelection = autoSelectFindingsAgentId({
    agents,
    findings: [],
    selectedAgentId: null,
    selectedFindingsAgentId: null,
    userSelectedFindingsAgentId: false,
  });

  expect(initialSelection).toBe('agent-zero');

  // Later: findings arrive for a different agent. We should auto-switch to the agent
  // with findings when the user hasn't manually selected an agent.
  const afterFindingsLoadSelection = autoSelectFindingsAgentId({
    agents,
    findings: [makeFinding({ agent_id: 'agent-six' })],
    selectedAgentId: null,
    selectedFindingsAgentId: initialSelection,
    userSelectedFindingsAgentId: false,
  });

  expect(afterFindingsLoadSelection).toBe('agent-six');
});

