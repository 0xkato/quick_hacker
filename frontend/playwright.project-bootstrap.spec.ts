import { test, expect } from '@playwright/test';

import type { Agent, FileNode, Finding } from './types';
import type { Project } from './lib/api';
import { fetchProjectBootstrapData } from './lib/projectBootstrap';

test('fetchProjectBootstrapData uses project.id for API calls', async () => {
  const project: Project = {
    id: 'proj_123',
    name: 'Test Project',
    description: '',
    repo_url: 'https://example.com/repo.git',
    repo_name: 'repo',
    repo_branch: 'main',
    languages: [],
    file_count: 0,
    created_at: new Date().toISOString(),
    last_accessed: new Date().toISOString(),
    is_cloned: true,
    path: '/tmp/repo',
  };

  let treeRepoId: string | null = null;
  let agentsRepoId: string | null = null;
  let findingsRepoId: string | null = null;

  const deps = {
    getTree: async (repoId: string): Promise<FileNode> => {
      treeRepoId = repoId;
      return { name: 'root', path: '', is_dir: true, children: [] };
    },
    listAgents: async (repoId: string): Promise<Agent[]> => {
      agentsRepoId = repoId;
      return [];
    },
    getAllFindings: async (repoId: string): Promise<Finding[]> => {
      findingsRepoId = repoId;
      return [];
    },
  };

  await fetchProjectBootstrapData(project, deps);

  expect(treeRepoId).toBe(project.id);
  expect(agentsRepoId).toBe(project.id);
  expect(findingsRepoId).toBe(project.id);
});

test('fetchProjectBootstrapData tolerates partial failures', async () => {
  const project: Project = {
    id: 'proj_456',
    name: 'Test Project',
    description: '',
    repo_url: 'https://example.com/repo.git',
    repo_name: 'repo',
    repo_branch: 'main',
    languages: [],
    file_count: 0,
    created_at: new Date().toISOString(),
    last_accessed: new Date().toISOString(),
    is_cloned: true,
    path: '/tmp/repo',
  };

  const deps = {
    getTree: async (_repoId: string): Promise<FileNode> => {
      throw new Error('tree failed');
    },
    listAgents: async (repoId: string): Promise<Agent[]> => {
      return [
        {
          id: 'agent_1',
          repo_id: repoId,
          name: 'Agent 1',
          agent_type: 'deep_audit',
          status: 'completed',
          provider_config: { provider: 'openai', model: 'gpt-4.1' },
          created_at: new Date().toISOString(),
          files_analyzed: 0,
          findings_count: 0,
        },
      ];
    },
    getAllFindings: async (repoId: string): Promise<Finding[]> => {
      return [
        {
          id: 'finding_1',
          agent_id: 'agent_1',
          repo_id: repoId,
          severity: 'high',
          title: 'Test finding',
          description: 'desc',
          file_path: 'src/app.ts',
          line_start: 1,
          vulnerability_type: 'Test',
          confidence: 0.5,
          created_at: new Date().toISOString(),
        },
      ];
    },
  };

  const data = await fetchProjectBootstrapData(project, deps);

  expect(data.fileTree).toBeNull();
  expect(data.agents).toHaveLength(1);
  expect(data.findings).toHaveLength(1);
});
