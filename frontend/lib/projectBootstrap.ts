import type { Agent, FileNode, Finding } from '../types';
import type { Project } from './api';

export interface ProjectBootstrapDeps {
  getTree: (repoId: string) => Promise<FileNode>;
  listAgents: (repoId: string) => Promise<Agent[]>;
  getAllFindings: (repoId: string) => Promise<Finding[]>;
}

export interface ProjectBootstrapData {
  fileTree: FileNode | null;
  agents: Agent[];
  findings: Finding[];
}

export async function fetchProjectBootstrapData(
  project: Project,
  deps: ProjectBootstrapDeps
): Promise<ProjectBootstrapData> {
  // Load all data in parallel for faster page load
  const needsFileTree = project.repo_name || project.is_cloned;

  const [agentsResult, findingsResult, fileTreeResult] = await Promise.allSettled([
    deps.listAgents(project.id),
    deps.getAllFindings(project.id),
    needsFileTree ? deps.getTree(project.id) : Promise.resolve(null),
  ]);

  const agents = agentsResult.status === 'fulfilled' ? agentsResult.value : [];
  if (agentsResult.status === 'rejected') {
    console.error('[bootstrap] Failed to load agents:', agentsResult.reason);
  }

  const findings = findingsResult.status === 'fulfilled' ? findingsResult.value : [];
  if (findingsResult.status === 'rejected') {
    console.error('[bootstrap] Failed to load findings:', findingsResult.reason);
  }

  const fileTree = fileTreeResult.status === 'fulfilled' ? fileTreeResult.value : null;
  if (fileTreeResult.status === 'rejected') {
    console.error('[bootstrap] Failed to load file tree:', fileTreeResult.reason);
  }

  return {
    fileTree,
    agents,
    findings,
  };
}
