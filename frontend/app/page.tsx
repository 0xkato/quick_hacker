'use client';

import { useState, useCallback, useEffect } from 'react';
import {
  Files,
  Search,
  GitBranch,
  Bug,
  Settings,
  ChevronRight,
  RefreshCw,
  Circle,
  X,
  MessageSquare,
  LogOut,
  FolderGit2,
  Network,
  Brain,
} from 'lucide-react';
import { MonacoEditor } from '@/components/Editor/MonacoEditor';
import { FileTree } from '@/components/FileExplorer/FileTree';
import { AgentManager } from '@/components/AgentPanel/AgentManager';
import { FindingsList } from '@/components/FindingsPanel/FindingsList';
import { ChatPanel } from '@/components/ChatPanel/ChatPanel';
import { SettingsModal } from '@/components/SettingsModal/SettingsModal';
import { ProjectSelector } from '@/components/ProjectSelector/ProjectSelector';
import { FlowVisualization } from '@/components/FlowVisualization/FlowVisualization';
import { LLMInteractionPanel } from '@/components/LLMInteractionPanel';
import { ReportModal } from '@/components/ReportPanel';
import { useWebSocket } from '@/hooks/useWebSocket';
import { files, agents as agentsApi, projects as projectsApi, initializeAuth, type Project } from '@/lib/api';
import type {
  FileNode,
  FileContent,
  Agent,
  Finding,
  AgentProgress,
  InvestigationFlow,
  LLMInteraction,
  ToolDetail,
  InvestigationReport,
} from '@/types';

type ActivityView = 'explorer' | 'search' | 'agents' | 'findings' | 'flow' | 'llm';

export default function Home() {
  // Project state
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [isProjectLoading, setIsProjectLoading] = useState(true);
  const [isAuthReady, setIsAuthReady] = useState(false);

  // State
  const [fileTree, setFileTree] = useState<FileNode | null>(null);
  const [currentFile, setCurrentFile] = useState<FileContent | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agentProgress, setAgentProgress] = useState<Record<string, AgentProgress>>({});
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [agentFlow, setAgentFlow] = useState<InvestigationFlow | null>(null);

  // Observability state
  const [llmInteractions, setLlmInteractions] = useState<LLMInteraction[]>([]);
  const [toolDetails, setToolDetails] = useState<ToolDetail[]>([]);

  // Report state
  const [currentReport, setCurrentReport] = useState<InvestigationReport | null>(null);
  const [showReportModal, setShowReportModal] = useState(false);

  // UI state
  const [activeView, setActiveView] = useState<ActivityView>('explorer');
  const [showSidebar, setShowSidebar] = useState(true);
  const [showPanel, setShowPanel] = useState(true);
  const [showChat, setShowChat] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // WebSocket - only connect after auth is ready
  const { isConnected } = useWebSocket({
    enabled: isAuthReady,
    onFinding: useCallback((finding: Finding) => {
      setFindings((prev) => [finding, ...prev]);
    }, []),
    onProgress: useCallback((agentId: string, progress: AgentProgress) => {
      setAgentProgress((prev) => ({ ...prev, [agentId]: progress }));
      // Check for flow updates in progress data
      if (progress && (progress as any).type === 'flow_update' && (progress as any).flow) {
        if (agentId === selectedAgentId) {
          setAgentFlow((progress as any).flow);
        }
      }
    }, [selectedAgentId]),
    onAgentStatus: useCallback((agentId: string, status: string) => {
      setAgents((prev) =>
        prev.map((a) =>
          a.id === agentId ? { ...a, status: status as Agent['status'] } : a
        )
      );
    }, []),
    // Observability handlers
    onLLMRequest: useCallback((agentId: string, interaction: LLMInteraction) => {
      if (!selectedAgentId || agentId === selectedAgentId) {
        setLlmInteractions((prev) => [...prev, interaction]);
      }
    }, [selectedAgentId]),
    onLLMResponse: useCallback((agentId: string, interaction: LLMInteraction) => {
      if (!selectedAgentId || agentId === selectedAgentId) {
        setLlmInteractions((prev) => [...prev, interaction]);
      }
    }, [selectedAgentId]),
    onToolDetail: useCallback((agentId: string, detail: ToolDetail) => {
      if (!selectedAgentId || agentId === selectedAgentId) {
        setToolDetails((prev) => [...prev, detail]);
      }
    }, [selectedAgentId]),
    onReportReady: useCallback(async (agentId: string, reportId: string) => {
      // Auto-fetch and show report when ready
      try {
        const report = await agentsApi.getReport(agentId, reportId);
        setCurrentReport(report);
        setShowReportModal(true);
      } catch (err) {
        console.error('Failed to load report:', err);
      }
    }, []),
  });

  // Load flow and observability data when agent is selected
  useEffect(() => {
    if (!selectedAgentId) {
      setAgentFlow(null);
      setLlmInteractions([]);
      setToolDetails([]);
      return;
    }

    const loadFlow = async () => {
      try {
        const flow = await agentsApi.getFlow(selectedAgentId);
        setAgentFlow(flow);
      } catch (err) {
        console.error('Failed to load flow:', err);
      }
    };

    const loadObservability = async () => {
      try {
        const [interactions, details] = await Promise.all([
          agentsApi.getLLMInteractions(selectedAgentId),
          agentsApi.getToolDetails(selectedAgentId),
        ]);
        setLlmInteractions(interactions);
        setToolDetails(details);
      } catch (err) {
        console.error('Failed to load observability data:', err);
      }
    };

    loadFlow();
    loadObservability();
    // Poll for updates while agent is running
    const interval = setInterval(loadFlow, 2000);
    return () => clearInterval(interval);
  }, [selectedAgentId]);

  // Initialize auth and check project status on mount
  useEffect(() => {
    const initialize = async () => {
      try {
        // Initialize authentication first
        await initializeAuth();
        setIsAuthReady(true);

        // Then check project status
        const status = await projectsApi.getStatus();
        if (status.current_project) {
          setCurrentProject(status.current_project);
          // Load project data when restoring from a previous session
          await loadProjectData(status.current_project);
        }
      } catch (err) {
        console.error('Failed to initialize:', err);
        // Still mark auth as ready to allow reconnection attempts
        setIsAuthReady(true);
      } finally {
        setIsProjectLoading(false);
      }
    };
    initialize();
  }, []);

  // Load project data when entering a project
  const loadProjectData = async (project: Project) => {
    // Skip only if definitely no repo info at all
    if (!project.repo_name && !project.is_cloned) return;

    try {
      // Try to load file tree - the backend will handle path resolution
      const tree = await files.getTree(project.id);
      setFileTree(tree);
    } catch (err) {
      console.error('Failed to load file tree:', err);
      // Don't block other data loading if tree fails
    }

    try {
      const projectAgents = await agentsApi.list(project.id);
      setAgents(projectAgents);
      const allFindings = await agentsApi.getAllFindings(project.id);
      setFindings(allFindings);
    } catch (err) {
      console.error('Failed to load agents/findings:', err);
    }
  };

  // Handle entering a project
  const handleProjectEnter = async (project: Project) => {
    setCurrentProject(project);
    setCurrentFile(null);
    setSelectedPath(null);
    setAgents([]);
    setFindings([]);
    setFileTree(null);
    await loadProjectData(project);
  };

  // Handle exiting a project
  const handleProjectExit = async () => {
    try {
      await projectsApi.exit();
    } catch (err) {
      console.error('Failed to exit project:', err);
    }
    setCurrentProject(null);
    setCurrentFile(null);
    setSelectedPath(null);
    setAgents([]);
    setFindings([]);
    setFileTree(null);
  };

  // Select file
  const handleFileSelect = async (path: string) => {
    if (!currentProject) return;

    setSelectedPath(path);

    try {
      const content = await files.getContent(currentProject.id, path);
      setCurrentFile(content);
    } catch (err) {
      console.error('Failed to load file:', err);
    }
  };

  // Finding click - navigate to file
  const handleFindingClick = async (finding: Finding) => {
    await handleFileSelect(finding.file_path);
  };

  // Agent callbacks
  const handleAgentCreated = (agent: Agent) => {
    setAgents((prev) => [agent, ...prev]);
  };

  const handleAgentUpdated = (agent: Agent) => {
    setAgents((prev) => prev.map((a) => (a.id === agent.id ? agent : a)));
  };

  const handleAgentDeleted = (agentId: string) => {
    setAgents((prev) => prev.filter((a) => a.id !== agentId));
    setFindings((prev) => prev.filter((f) => f.agent_id !== agentId));
  };

  // View report for an agent
  const handleViewReport = async (agentId: string) => {
    try {
      const report = await agentsApi.getReport(agentId);
      setCurrentReport(report);
      setShowReportModal(true);
    } catch (err) {
      console.error('Failed to load report:', err);
    }
  };

  // Download report
  const handleDownloadReport = async (format: 'md' | 'json' | 'svg') => {
    if (!currentReport) return;

    try {
      const blob = await agentsApi.downloadReport(currentReport.agent_id, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${currentReport.agent_id}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download report:', err);
    }
  };

  // Count running agents and findings
  const runningAgents = agents.filter((a) => a.status === 'running').length;
  const criticalFindings = findings.filter((f) => f.severity === 'critical').length;
  const highFindings = findings.filter((f) => f.severity === 'high').length;

  // Show loading while checking project status
  if (isProjectLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-vsc-bg">
        <RefreshCw className="w-8 h-8 text-vsc-accent animate-spin" />
      </div>
    );
  }

  // Show project selector if not in a project
  if (!currentProject) {
    return (
      <ProjectSelector
        onProjectEnter={handleProjectEnter}
        onProjectExit={handleProjectExit}
      />
    );
  }

  return (
    <div className="h-screen flex flex-col bg-vsc-bg">
      {/* Project header bar */}
      <header className="h-9 bg-vsc-activitybar flex items-center justify-between px-3 border-b border-vsc-border-subtle select-none">
        <div className="flex items-center gap-3">
          <span className="text-vsc-text-muted text-vsc-xs">quick_hack</span>
          <div className="flex items-center gap-2 text-vsc-text">
            <FolderGit2 className="w-4 h-4 text-vsc-accent" />
            <span className="text-vsc-sm font-medium">{currentProject.name}</span>
            {currentProject.repo_name && (
              <span className="text-vsc-xs text-vsc-text-muted">
                ({currentProject.repo_name})
              </span>
            )}
          </div>
        </div>
        <button
          onClick={handleProjectExit}
          className="btn btn-secondary btn-sm flex items-center gap-1"
          title="Exit project"
        >
          <LogOut className="w-3 h-3" />
          Exit
        </button>
      </header>

      {/* Main layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Activity bar */}
        <aside className="w-12 bg-vsc-activitybar flex flex-col items-center py-1 border-r border-vsc-border-subtle">
          <button
            onClick={() => {
              setActiveView('explorer');
              setShowSidebar(true);
            }}
            className={`activity-icon ${activeView === 'explorer' && showSidebar ? 'active' : ''}`}
            title="Explorer"
          >
            <Files className="w-6 h-6" />
          </button>
          <button
            onClick={() => {
              setActiveView('agents');
              setShowSidebar(true);
            }}
            className={`activity-icon ${activeView === 'agents' && showSidebar ? 'active' : ''}`}
            title="Agents"
          >
            <Bug className="w-6 h-6" />
            {runningAgents > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-vsc-success rounded-full" />
            )}
          </button>
          <button
            onClick={() => {
              setActiveView('findings');
              setShowSidebar(true);
            }}
            className={`activity-icon ${activeView === 'findings' && showSidebar ? 'active' : ''}`}
            title="Findings"
          >
            <Search className="w-6 h-6" />
            {(criticalFindings > 0 || highFindings > 0) && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-sev-critical rounded-full" />
            )}
          </button>
          <button
            onClick={() => {
              setActiveView('flow');
              setShowSidebar(false);
            }}
            className={`activity-icon ${activeView === 'flow' ? 'active' : ''}`}
            title="Investigation Flow"
          >
            <Network className="w-6 h-6" />
          </button>
          <button
            onClick={() => {
              setActiveView('llm');
              setShowSidebar(false);
            }}
            className={`activity-icon ${activeView === 'llm' ? 'active' : ''}`}
            title="LLM Interactions"
          >
            <Brain className="w-6 h-6" />
            {llmInteractions.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-vsc-accent rounded-full" />
            )}
          </button>

          <div className="flex-1" />

          <button
            onClick={() => setShowChat(!showChat)}
            className={`activity-icon ${showChat ? 'active' : ''}`}
            title="AI Chat"
          >
            <MessageSquare className="w-5 h-5" />
          </button>

          <button
            onClick={() => setShowSettings(true)}
            className="activity-icon"
            title="Settings"
          >
            <Settings className="w-5 h-5" />
          </button>
        </aside>

        {/* Sidebar */}
        {showSidebar && (
          <aside className="w-64 bg-vsc-sidebar flex flex-col border-r border-vsc-border-subtle">
            {/* Sidebar header with view title */}
            <div className="panel-header">
              <span>
                {activeView === 'explorer' && 'EXPLORER'}
                {activeView === 'agents' && 'AGENTS'}
                {activeView === 'findings' && 'FINDINGS'}
              </span>
              <button
                onClick={() => setShowSidebar(false)}
                className="btn-icon"
              >
                <X className="w-4 h-4" />
              </button>
            </div>


            {/* Sidebar content based on active view */}
            <div className="flex-1 overflow-hidden">
              {activeView === 'explorer' && (
                <FileTree
                  tree={fileTree}
                  selectedPath={selectedPath}
                  onFileSelect={handleFileSelect}
                />
              )}

              {activeView === 'agents' && (
                <AgentManager
                  repoId={currentProject.id}
                  agents={agents}
                  progress={agentProgress}
                  onAgentCreated={handleAgentCreated}
                  onAgentUpdated={handleAgentUpdated}
                  onAgentDeleted={handleAgentDeleted}
                  onViewReport={handleViewReport}
                />
              )}

              {activeView === 'findings' && (
                <FindingsList
                  findings={findings}
                  onFindingClick={handleFindingClick}
                />
              )}
            </div>
          </aside>
        )}

        {/* Main content area */}
        <main className="flex-1 flex flex-col overflow-hidden bg-vsc-bg">
          {/* Flow visualization view */}
          {activeView === 'flow' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Agent selector for flow */}
              <div className="h-10 bg-vsc-sidebar border-b border-vsc-border-subtle flex items-center px-3 gap-2">
                <Network className="w-4 h-4 text-vsc-text-muted" />
                <span className="text-vsc-sm text-vsc-text-muted">Investigation Flow</span>
                <select
                  value={selectedAgentId || ''}
                  onChange={(e) => setSelectedAgentId(e.target.value || null)}
                  className="ml-2 px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm"
                >
                  <option value="">Select agent...</option>
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name} ({agent.status})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex-1">
                <FlowVisualization agentId={selectedAgentId} flow={agentFlow} />
              </div>
            </div>
          )}

          {/* LLM Interactions view */}
          {activeView === 'llm' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Agent selector for LLM view */}
              <div className="h-10 bg-vsc-sidebar border-b border-vsc-border-subtle flex items-center px-3 gap-2">
                <Brain className="w-4 h-4 text-vsc-text-muted" />
                <span className="text-vsc-sm text-vsc-text-muted">LLM Interactions</span>
                <select
                  value={selectedAgentId || ''}
                  onChange={(e) => setSelectedAgentId(e.target.value || null)}
                  className="ml-2 px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm"
                >
                  <option value="">Select agent...</option>
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name} ({agent.status})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex-1">
                <LLMInteractionPanel
                  agentId={selectedAgentId}
                  interactions={llmInteractions}
                  toolDetails={toolDetails}
                  isConnected={isConnected}
                />
              </div>
            </div>
          )}

          {/* Tab bar */}
          {activeView !== 'flow' && activeView !== 'llm' && currentFile && (
            <div className="h-9 bg-vsc-sidebar flex items-end border-b border-vsc-border-subtle">
              <div className="tab active">
                <span className="truncate max-w-[200px]">
                  {currentFile.path.split('/').pop()}
                </span>
                <button
                  onClick={() => {
                    setCurrentFile(null);
                    setSelectedPath(null);
                  }}
                  className="ml-1 p-0.5 rounded hover:bg-vsc-hover"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* Breadcrumb */}
          {activeView !== 'flow' && activeView !== 'llm' && currentFile && (
            <div className="breadcrumb border-b border-vsc-border-subtle">
              {currentFile.path.split('/').map((part, idx, arr) => (
                <span key={idx} className="flex items-center">
                  {idx > 0 && <ChevronRight className="breadcrumb-separator w-3 h-3" />}
                  <span className={idx === arr.length - 1 ? 'text-vsc-text' : 'breadcrumb-item'}>
                    {part}
                  </span>
                </span>
              ))}
            </div>
          )}

          {/* Editor */}
          {activeView !== 'flow' && activeView !== 'llm' && (
            <div className="flex-1 overflow-hidden">
              <MonacoEditor
                file={currentFile}
                findings={findings.filter((f) => f.file_path === currentFile?.path)}
              />
            </div>
          )}
        </main>

        {/* Right panel - can show agents or findings in split view */}
        {showPanel && currentFile && findings.filter((f) => f.file_path === currentFile?.path).length > 0 && (
          <aside className="w-80 bg-vsc-sidebar border-l border-vsc-border-subtle flex flex-col">
            <div className="panel-header">
              <span>FILE FINDINGS</span>
              <button
                onClick={() => setShowPanel(false)}
                className="btn-icon"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-auto">
              <FindingsList
                findings={findings.filter((f) => f.file_path === currentFile?.path)}
                onFindingClick={handleFindingClick}
              />
            </div>
          </aside>
        )}
      </div>

      {/* Status bar */}
      <footer className="h-6 bg-vsc-statusbar flex items-center px-3 text-vsc-xs text-white select-none">
        <div className="flex items-center gap-3">
          {/* Connection status */}
          <span className="flex items-center gap-1">
            <Circle className={`w-2 h-2 ${isConnected ? 'fill-vsc-success text-vsc-success' : 'fill-vsc-error text-vsc-error'}`} />
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>

          {/* Branch */}
          {currentProject.repo_branch && (
            <span className="flex items-center gap-1">
              <GitBranch className="w-3 h-3" />
              {currentProject.repo_branch}
            </span>
          )}
        </div>

        <div className="flex-1" />

        <div className="flex items-center gap-3">
          {/* File info */}
          {currentProject.file_count > 0 && (
            <span>{currentProject.file_count} files</span>
          )}

          {/* Running agents */}
          {runningAgents > 0 && (
            <span className="flex items-center gap-1">
              <RefreshCw className="w-3 h-3 animate-spin" />
              {runningAgents} scanning
            </span>
          )}

          {/* Findings count */}
          <span className="flex items-center gap-1">
            {findings.length} findings
            {criticalFindings > 0 && (
              <span className="text-sev-critical">({criticalFindings} critical)</span>
            )}
          </span>
        </div>
      </footer>

      {/* Chat Panel (left pop-out) */}
      <ChatPanel
        isOpen={showChat}
        onToggle={() => setShowChat(!showChat)}
        currentFile={currentFile}
        findings={findings}
        onRequestSettings={() => setShowSettings(true)}
      />

      {/* Settings Modal */}
      <SettingsModal
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
      />

      {/* Report Modal */}
      {currentReport && (
        <ReportModal
          report={currentReport}
          isOpen={showReportModal}
          onClose={() => {
            setShowReportModal(false);
            setCurrentReport(null);
          }}
          onDownload={handleDownloadReport}
        />
      )}
    </div>
  );
}
