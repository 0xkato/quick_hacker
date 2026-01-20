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
  const [agents, findings] = await Promise.all([
    deps.listAgents(project.id),
    deps.getAllFindings(project.id),
  ]);

  let fileTree: FileNode | null = null;
  if (project.repo_name || project.is_cloned) {
    fileTree = await deps.getTree(project.id);
  }

  return {
    fileTree,
    agents,
    findings,
  };
}
