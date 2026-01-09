'use client';

import { useState, useEffect } from 'react';
import {
  FolderOpen,
  Plus,
  Trash2,
  GitBranch,
  RefreshCw,
  LogOut,
  AlertTriangle,
  X,
  FolderGit2,
} from 'lucide-react';
import clsx from 'clsx';
import { projects as projectsApi, type Project, type ProjectStatus } from '@/lib/api';

interface ProjectSelectorProps {
  onProjectEnter: (project: Project) => void;
  onProjectExit: () => void;
}

interface CloneConfirmDialogProps {
  currentProject: Project;
  onConfirm: () => void;
  onCancel: () => void;
}

function CloneConfirmDialog({ currentProject, onConfirm, onCancel }: CloneConfirmDialogProps) {
  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onCancel()}>
      <div className="modal-content max-w-md">
        <div className="modal-header">
          <div className="flex items-center gap-2 text-vsc-warning">
            <AlertTriangle className="w-5 h-5" />
            <h2 className="text-vsc-base font-medium">Clone in Another Project?</h2>
          </div>
          <button onClick={onCancel} className="btn-icon">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="modal-body">
          <p className="text-vsc-sm text-vsc-text-muted mb-4">
            You are currently in project <span className="text-vsc-text font-medium">&quot;{currentProject.name}&quot;</span>.
          </p>
          <p className="text-vsc-sm text-vsc-text-muted">
            Do you want to exit the current project and clone into a new one?
          </p>
        </div>

        <div className="modal-footer">
          <button onClick={onCancel} className="btn btn-secondary">
            Cancel
          </button>
          <button onClick={onConfirm} className="btn btn-primary">
            Exit & Clone
          </button>
        </div>
      </div>
    </div>
  );
}

interface CreateProjectModalProps {
  onClose: () => void;
  onCreated: (project: Project) => void;
}

function CreateProjectModal({ onClose, onCreated }: CreateProjectModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setIsLoading(true);
    setError(null);

    try {
      const project = await projectsApi.create(name.trim(), description.trim());
      onCreated(project);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create project');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal-content max-w-md">
        <div className="modal-header">
          <h2 className="text-vsc-base font-medium">Create Project</h2>
          <button onClick={onClose} className="btn-icon">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body space-y-4">
          <div>
            <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
              Project Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="my-audit-project"
              className="input"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
              Description <span className="normal-case">(optional)</span>
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Security audit for..."
              rows={2}
              className="input resize-none"
            />
          </div>

          {error && (
            <div className="text-vsc-error text-vsc-sm bg-vsc-error/10 p-2 rounded border border-vsc-error/30">
              {error}
            </div>
          )}
        </form>

        <div className="modal-footer">
          <button type="button" onClick={onClose} className="btn btn-secondary">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isLoading || !name.trim()}
            className="btn btn-primary"
          >
            {isLoading ? 'Creating...' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}

interface QuickCloneModalProps {
  currentProject: Project | null;
  onClose: () => void;
  onCloned: (project: Project) => void;
}

function QuickCloneModal({ currentProject, onClose, onCloned }: QuickCloneModalProps) {
  const [url, setUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [projectName, setProjectName] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  const handleClone = async (force: boolean = false) => {
    if (!url.trim()) return;

    if (currentProject && !force) {
      setShowConfirm(true);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const project = await projectsApi.quickClone(
        url.trim(),
        branch.trim() || undefined,
        projectName.trim() || undefined,
        force
      );
      onCloned(project);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clone repository');
    } finally {
      setIsLoading(false);
    }
  };

  if (showConfirm && currentProject) {
    return (
      <CloneConfirmDialog
        currentProject={currentProject}
        onConfirm={() => {
          setShowConfirm(false);
          handleClone(true);
        }}
        onCancel={() => setShowConfirm(false)}
      />
    );
  }

  return (
    <div className="modal-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal-content max-w-lg">
        <div className="modal-header">
          <h2 className="text-vsc-base font-medium">Quick Clone</h2>
          <button onClick={onClose} className="btn-icon">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={(e) => { e.preventDefault(); handleClone(); }} className="modal-body space-y-4">
          <div>
            <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
              Repository URL
            </label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com/user/repo"
              className="input"
              autoFocus
              data-testid="quick-clone-url"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
                Branch <span className="normal-case">(optional)</span>
              </label>
              <input
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="main"
                className="input"
              />
            </div>

            <div>
              <label className="block text-vsc-xs text-vsc-text-muted mb-2 uppercase tracking-wider">
                Project Name <span className="normal-case">(optional)</span>
              </label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="Auto from repo"
                className="input"
              />
            </div>
          </div>

          {currentProject && (
            <div className="text-vsc-warning text-vsc-sm bg-vsc-warning/10 p-2 rounded border border-vsc-warning/30 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>You&apos;re currently in project &quot;{currentProject.name}&quot;</span>
            </div>
          )}

          {error && (
            <div className="text-vsc-error text-vsc-sm bg-vsc-error/10 p-2 rounded border border-vsc-error/30">
              {error}
            </div>
          )}
        </form>

        <div className="modal-footer">
          <button type="button" onClick={onClose} className="btn btn-secondary">
            Cancel
          </button>
          <button
            onClick={() => handleClone()}
            disabled={isLoading || !url.trim()}
            className="btn btn-primary"
            data-testid="quick-clone-submit"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Cloning...
              </>
            ) : (
              <>
                <GitBranch className="w-4 h-4" />
                Clone & Enter
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

function ProjectCard({
  project,
  onEnter,
  onDelete,
}: {
  project: Project;
  onEnter: () => void;
  onDelete: () => void;
}) {
  const [isDeleting, setIsDeleting] = useState(false);

  const handleDelete = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete project "${project.name}"? This cannot be undone.`)) return;

    setIsDeleting(true);
    try {
      await projectsApi.delete(project.id);
      onDelete();
    } catch (err) {
      console.error('Failed to delete project:', err);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div
      onClick={onEnter}
      className={clsx(
        'border border-vsc-border-subtle rounded-lg p-4 cursor-pointer transition-all',
        'hover:border-vsc-accent hover:bg-vsc-hover group'
      )}
    >
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          {project.is_cloned ? (
            <FolderGit2 className="w-5 h-5 text-vsc-accent" />
          ) : (
            <FolderOpen className="w-5 h-5 text-vsc-text-muted" />
          )}
          <h3 className="font-medium text-vsc-text">{project.name}</h3>
        </div>
        <button
          onClick={handleDelete}
          disabled={isDeleting}
          className="btn-icon opacity-0 group-hover:opacity-100 hover:text-vsc-error"
          title="Delete project"
        >
          {isDeleting ? (
            <RefreshCw className="w-4 h-4 animate-spin" />
          ) : (
            <Trash2 className="w-4 h-4" />
          )}
        </button>
      </div>

      {project.description && (
        <p className="text-vsc-sm text-vsc-text-muted mb-3 line-clamp-2">
          {project.description}
        </p>
      )}

      <div className="flex items-center gap-4 text-vsc-xs text-vsc-text-muted">
        {project.is_cloned && project.repo_name && (
          <>
            <span className="flex items-center gap-1">
              <GitBranch className="w-3 h-3" />
              {project.repo_branch || 'main'}
            </span>
            <span>{project.file_count} files</span>
            {project.languages.length > 0 && (
              <span>{project.languages.slice(0, 3).join(', ')}</span>
            )}
          </>
        )}
        {!project.is_cloned && (
          <span className="text-vsc-text-muted italic">No repository cloned</span>
        )}
      </div>
    </div>
  );
}

export function ProjectSelector({ onProjectEnter, onProjectExit }: ProjectSelectorProps) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showCloneModal, setShowCloneModal] = useState(false);

  useEffect(() => {
    loadProjectStatus();
  }, []);

  const loadProjectStatus = async () => {
    setIsLoading(true);
    try {
      const [projectList, status] = await Promise.all([
        projectsApi.list(),
        projectsApi.getStatus(),
      ]);
      setProjects(projectList);
      setCurrentProject(status.current_project);

      if (status.current_project) {
        onProjectEnter(status.current_project);
      }
    } catch (err) {
      console.error('Failed to load projects:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleEnterProject = async (project: Project) => {
    try {
      const enteredProject = await projectsApi.enter(project.id);
      setCurrentProject(enteredProject);
      onProjectEnter(enteredProject);
    } catch (err) {
      console.error('Failed to enter project:', err);
    }
  };

  const handleExitProject = async () => {
    try {
      await projectsApi.exit();
      setCurrentProject(null);
      onProjectExit();
      loadProjectStatus();
    } catch (err) {
      console.error('Failed to exit project:', err);
    }
  };

  const handleProjectCreated = (project: Project) => {
    setProjects((prev) => [project, ...prev]);
  };

  const handleProjectCloned = (project: Project) => {
    setProjects((prev) => {
      const existing = prev.find((p) => p.id === project.id);
      if (existing) {
        return prev.map((p) => (p.id === project.id ? project : p));
      }
      return [project, ...prev];
    });
    setCurrentProject(project);
    onProjectEnter(project);
  };

  const handleProjectDeleted = (projectId: string) => {
    setProjects((prev) => prev.filter((p) => p.id !== projectId));
  };

  // If we're in a project, show the project header bar
  if (currentProject) {
    return (
      <div className="bg-vsc-activitybar border-b border-vsc-border-subtle px-3 py-1.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FolderGit2 className="w-4 h-4 text-vsc-accent" />
          <span className="text-vsc-sm font-medium text-vsc-text">{currentProject.name}</span>
          {currentProject.repo_name && (
            <span className="text-vsc-xs text-vsc-text-muted">
              ({currentProject.repo_name})
            </span>
          )}
        </div>
        <button
          onClick={handleExitProject}
          className="btn btn-secondary btn-sm flex items-center gap-1"
          title="Exit project"
        >
          <LogOut className="w-3 h-3" />
          Exit
        </button>
      </div>
    );
  }

  // Show project selector screen
  return (
    <div className="h-full flex flex-col bg-vsc-bg">
      {/* Header */}
      <div className="bg-vsc-activitybar px-6 py-4 border-b border-vsc-border-subtle">
        <h1 className="text-xl font-semibold text-vsc-text mb-1">Projects</h1>
        <p className="text-vsc-sm text-vsc-text-muted">
          Select a project to start auditing or create a new one
        </p>
      </div>

      {/* Actions */}
      <div className="px-6 py-4 border-b border-vsc-border-subtle flex gap-2">
        <button
          onClick={() => setShowCloneModal(true)}
          className="btn btn-primary"
          data-testid="project-quick-clone"
        >
          <GitBranch className="w-4 h-4" />
          Quick Clone
        </button>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-secondary"
        >
          <Plus className="w-4 h-4" />
          New Project
        </button>
      </div>

      {/* Project list */}
      <div className="flex-1 overflow-auto p-6">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <RefreshCw className="w-6 h-6 text-vsc-text-muted animate-spin" />
          </div>
        ) : projects.length === 0 ? (
          <div className="text-center py-12">
            <FolderOpen className="w-12 h-12 text-vsc-text-muted mx-auto mb-4" />
            <h3 className="text-vsc-text font-medium mb-2">No projects yet</h3>
            <p className="text-vsc-sm text-vsc-text-muted mb-4">
              Get started by cloning a repository
            </p>
            <button
              onClick={() => setShowCloneModal(true)}
              className="btn btn-primary"
            >
              <GitBranch className="w-4 h-4" />
              Clone Repository
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {projects.map((project) => (
              <ProjectCard
                key={project.id}
                project={project}
                onEnter={() => handleEnterProject(project)}
                onDelete={() => handleProjectDeleted(project.id)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Modals */}
      {showCreateModal && (
        <CreateProjectModal
          onClose={() => setShowCreateModal(false)}
          onCreated={handleProjectCreated}
        />
      )}

      {showCloneModal && (
        <QuickCloneModal
          currentProject={currentProject}
          onClose={() => setShowCloneModal(false)}
          onCloned={handleProjectCloned}
        />
      )}
    </div>
  );
}

// Current project header component for use in the main layout
export function ProjectHeader({
  project,
  onExit,
}: {
  project: Project;
  onExit: () => void;
}) {
  return (
    <div className="bg-vsc-activitybar border-b border-vsc-border-subtle px-3 py-1.5 flex items-center justify-between">
      <div className="flex items-center gap-2">
        <FolderGit2 className="w-4 h-4 text-vsc-accent" />
        <span className="text-vsc-sm font-medium text-vsc-text">{project.name}</span>
        {project.repo_name && (
          <span className="text-vsc-xs text-vsc-text-muted">
            ({project.repo_name})
          </span>
        )}
      </div>
      <button
        onClick={onExit}
        className="btn btn-secondary btn-sm flex items-center gap-1"
        title="Exit project"
      >
        <LogOut className="w-3 h-3" />
        Exit
      </button>
    </div>
  );
}
