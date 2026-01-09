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
import { AuthModal } from '@/components/Auth';
import { SessionControls } from '@/components/SessionControls';
import { ResumeDialog } from '@/components/ResumeDialog';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useAuth } from '@/hooks/useAuth';
import { files, agents as agentsApi, calltree as calltreeApi, projects as projectsApi, session as sessionApi, initializeAuth, setAuthFunctions, type Project } from '@/lib/api';
import type {
  FileNode,
  FileContent,
  Agent,
  Finding,
  AgentProgress,
  InvestigationFlow,
  CallTreeRoute,
  LLMInteraction,
  ToolDetail,
  InvestigationReport,
  SessionStatus,
  SnapshotInfo,
} from '@/types';

type ActivityView = 'explorer' | 'search' | 'agents' | 'findings' | 'flow' | 'llm';
type ThreatModel = 'A' | 'AB' | 'ABC';

export default function Home() {
  // Project state
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [isProjectLoading, setIsProjectLoading] = useState(true);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [isThreatModelSaving, setIsThreatModelSaving] = useState(false);

  // State
  const [fileTree, setFileTree] = useState<FileNode | null>(null);
  const [currentFile, setCurrentFile] = useState<FileContent | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agentProgress, setAgentProgress] = useState<Record<string, AgentProgress>>({});
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [agentFlow, setAgentFlow] = useState<InvestigationFlow | null>(null);
  const [diagramMode, setDiagramMode] = useState<'investigation' | 'calltree'>('investigation');
  const [callTreeRoutes, setCallTreeRoutes] = useState<CallTreeRoute[]>([]);
  const [selectedRouteId, setSelectedRouteId] = useState<string | null>(null);
  const [callTreeFlow, setCallTreeFlow] = useState<InvestigationFlow | null>(null);
  const [isCallTreeRoutesLoading, setIsCallTreeRoutesLoading] = useState(false);
  const [isCallTreeLoading, setIsCallTreeLoading] = useState(false);

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
  const [showAuthModal, setShowAuthModal] = useState(false);

  // Session hibernation state
  const [sessionStatus, setSessionStatus] = useState<SessionStatus>('active');
  const [snapshotInfo, setSnapshotInfo] = useState<SnapshotInfo | null>(null);
  const [showResumeDialog, setShowResumeDialog] = useState(false);

  // Auth state
  const { user, isAuthenticated, isLoading: isAuthLoading, logout, getAccessToken, refreshToken } = useAuth();

  // Set up API auth functions
  useEffect(() => {
    setAuthFunctions(getAccessToken, refreshToken);
  }, [getAccessToken, refreshToken]);

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

    let errorCount = 0;
    const maxErrors = 3; // Stop polling after 3 consecutive errors
    let intervalId: NodeJS.Timeout | null = null;

    const loadFlow = async () => {
      try {
        const flow = await agentsApi.getFlow(selectedAgentId);
        setAgentFlow(flow);
        errorCount = 0; // Reset on success
      } catch (err) {
        console.error('Failed to load flow:', err);
        errorCount++;
        // Stop polling after too many errors (agent likely doesn't exist)
        if (errorCount >= maxErrors && intervalId) {
          console.log('Stopping flow polling due to repeated errors');
          clearInterval(intervalId);
          intervalId = null;
        }
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

    // Check if selected agent exists and get its status
    const selectedAgent = agents.find(a => a.id === selectedAgentId);

    // If agents are loaded but selected agent doesn't exist, clear selection
    if (agents.length > 0 && !selectedAgent) {
      console.log('Selected agent not found, clearing selection');
      setSelectedAgentId(null);
      return;
    }

    // Only poll if the selected agent is running
    const isRunning = selectedAgent?.status === 'running' || selectedAgent?.status === 'pending';

    if (isRunning) {
      intervalId = setInterval(loadFlow, 2000);
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [selectedAgentId, agents]);

  // Load call-tree routes when enabled
  useEffect(() => {
    const projectId = currentProject?.id;
    if (!projectId || diagramMode !== 'calltree') {
      setCallTreeRoutes([]);
      setSelectedRouteId(null);
      setCallTreeFlow(null);
      setIsCallTreeRoutesLoading(false);
      setIsCallTreeLoading(false);
      return;
    }

    let cancelled = false;
    setIsCallTreeRoutesLoading(true);

    (async () => {
      try {
        const routes = await calltreeApi.listRoutes(projectId);
        if (!cancelled) {
          setCallTreeRoutes(routes);
          setSelectedRouteId((prev) => {
            if (!prev) return prev;
            if (routes.some((r) => r.id === prev)) return prev;
            setCallTreeFlow(null);
            return null;
          });
        }
      } catch (err) {
        console.error('Failed to load call-tree routes:', err);
        if (!cancelled) setCallTreeRoutes([]);
      } finally {
        if (!cancelled) setIsCallTreeRoutesLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [currentProject?.id, diagramMode]);

  // Build call tree when a route is selected
  useEffect(() => {
    const projectId = currentProject?.id;
    if (!projectId || diagramMode !== 'calltree' || !selectedRouteId) {
      setCallTreeFlow(null);
      setIsCallTreeLoading(false);
      return;
    }

    let cancelled = false;
    setIsCallTreeLoading(true);

    (async () => {
      try {
        const flow = await calltreeApi.getTree(projectId, selectedRouteId, {
          maxDepth: 6,
          maxNodes: 250,
          includeExternal: true,
        });
        if (!cancelled) setCallTreeFlow(flow);
      } catch (err) {
        console.error('Failed to build call tree:', err);
        if (!cancelled) setCallTreeFlow(null);
      } finally {
        if (!cancelled) setIsCallTreeLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [currentProject?.id, diagramMode, selectedRouteId]);

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

  // Check for existing snapshot on project load
  useEffect(() => {
    if (!currentProject || !isAuthReady) return;

    const checkSnapshot = async () => {
      try {
        const info = await sessionApi.getSnapshotInfo();
        setSnapshotInfo(info);
      } catch (err) {
        console.error('Failed to check snapshot:', err);
      }
    };

    checkSnapshot();
  }, [currentProject?.id, isAuthReady]);

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

  const handleThreatModelChange = async (threatModel: ThreatModel) => {
    if (!currentProject) return;
    setIsThreatModelSaving(true);
    try {
      const updated = await projectsApi.update(currentProject.id, { threat_model: threatModel });
      setCurrentProject(updated);
    } catch (err) {
      console.error('Failed to update threat model:', err);
    } finally {
      setIsThreatModelSaving(false);
    }
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

  // Session restore handler
  const handleRestoreSession = useCallback(async () => {
    try {
      setSessionStatus('resuming');
      const result = await sessionApi.resume();

      // Restore findings from snapshot
      if (result.snapshot.findings) {
        setFindings(result.snapshot.findings as unknown as Finding[]);
      }

      // Restore UI state
      const ui = result.snapshot.ui_state;
      if (ui.active_view) {
        setActiveView(ui.active_view as typeof activeView);
      }
      if (ui.selected_file) {
        setSelectedPath(ui.selected_file);
      }
      if (ui.selected_agent_id) {
        setSelectedAgentId(ui.selected_agent_id);
      }

      setSessionStatus('active');
      setShowResumeDialog(false);
      setSnapshotInfo(null);

      // Delete snapshot after restore
      await sessionApi.deleteSnapshot();
    } catch (err) {
      console.error('Failed to restore session:', err);
      setSessionStatus('active');
    }
  }, []);

  // Handle showing dialog or auto-restore when snapshotInfo changes
  useEffect(() => {
    if (!snapshotInfo) return;

    // Check if we have running agents (conflict)
    const hasRunning = agents.some(a => a.status === 'running');

    if (hasRunning) {
      // Show conflict dialog
      setShowResumeDialog(true);
    } else {
      // Auto-restore if no conflict
      handleRestoreSession();
    }
  }, [snapshotInfo, agents, handleRestoreSession]);

  const handleKeepCurrent = useCallback(async () => {
    setShowResumeDialog(false);
    // Optionally delete the snapshot
    try {
      await sessionApi.deleteSnapshot();
      setSnapshotInfo(null);
    } catch (err) {
      console.error('Failed to delete snapshot:', err);
    }
  }, []);

  const handleSessionPaused = useCallback(() => {
    // Could show a toast notification here
    console.log('Session paused successfully');
  }, []);

  const handleSessionError = useCallback((error: string) => {
    console.error('Session error:', error);
    // Could show error toast here
  }, []);

  // Count running agents and findings
  const runningAgents = agents.filter((a) => a.status === 'running').length;
  const criticalFindings = findings.filter((f) => f.severity === 'critical').length;
  const highFindings = findings.filter((f) => f.severity === 'high').length;
  const selectedAgent = selectedAgentId ? agents.find((a) => a.id === selectedAgentId) : null;
  const canQueueInvestigations = Boolean(
    selectedAgent && ['deep_scan', 'custom', 'strict_analysis', 'ultra_strict'].includes(selectedAgent.agent_type)
  );

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
          <div className="flex items-center gap-2">
            <span className="text-vsc-xs text-vsc-text-muted">Threat model</span>
            <select
              value={(currentProject.threat_model || 'AB') as ThreatModel}
              onChange={(e) => handleThreatModelChange(e.target.value as ThreatModel)}
              disabled={isThreatModelSaving}
              className="px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-xs disabled:opacity-50"
              title="Attacker model used for automated triage"
            >
              <option value="A">Internet (A)</option>
              <option value="AB">Internet + Auth (A+B)</option>
              <option value="ABC">Internet + Auth + Insider (A+B+C)</option>
            </select>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {isAuthenticated ? (
            <div className="flex items-center gap-4">
              <span className="text-gray-400">
                {user?.username}
              </span>
              <button
                onClick={logout}
                className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded"
              >
                Logout
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowAuthModal(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded font-medium"
            >
              Login
            </button>
          )}
          <SessionControls
            sessionStatus={sessionStatus}
            onStatusChange={setSessionStatus}
            hasRunningAgents={agents.some(a => a.status === 'running')}
            activeView={activeView}
            selectedFile={selectedPath}
            openPanels={[
              showSidebar ? 'sidebar' : '',
              showPanel ? 'panel' : '',
              showChat ? 'chat' : '',
            ].filter(Boolean)}
            selectedAgentId={selectedAgentId}
            onPaused={handleSessionPaused}
            onError={handleSessionError}
          />
          <button
            onClick={handleProjectExit}
            className="btn btn-secondary btn-sm flex items-center gap-1"
            title="Exit project"
          >
            <LogOut className="w-3 h-3" />
            Exit
          </button>
        </div>
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
              <span
                className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-vsc-accent scan-indicator"
              />
            )}
            {runningAgents === 0 && agents.some(a => a.status === 'paused') && (
              <span
                className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-vsc-accent scan-indicator-paused"
              />
            )}
            {runningAgents === 0 && agents.some(a => a.status === 'completed' && a.findings_count > 0) &&
             !agents.some(a => a.status === 'running' || a.status === 'paused') && (
              <span
                className={`absolute top-2 right-2 w-1.5 h-1.5 rounded-full ${
                  findings.some(f => f.severity === 'critical') ? 'bg-sev-critical' :
                  findings.some(f => f.severity === 'high') ? 'bg-sev-high' : 'bg-vsc-accent'
                }`}
              />
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
              {/* Diagram selector */}
              <div className="h-10 bg-vsc-sidebar border-b border-vsc-border-subtle flex items-center px-3 gap-2">
                <Network className="w-4 h-4 text-vsc-text-muted" />
                <select
                  value={diagramMode}
                  onChange={(e) => setDiagramMode(e.target.value as 'investigation' | 'calltree')}
                  className="px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm"
                  data-testid="diagram-mode-select"
                >
                  <option value="investigation">Investigation Flow</option>
                  <option value="calltree">Call Tree (FastAPI)</option>
                </select>

                {diagramMode === 'investigation' ? (
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
                ) : (
                  <select
                    value={selectedRouteId || ''}
                    onChange={(e) => setSelectedRouteId(e.target.value || null)}
                    className="ml-2 px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm min-w-[320px]"
                    disabled={isCallTreeRoutesLoading}
                    data-testid="calltree-route-select"
                  >
                    <option value="">
                      {isCallTreeRoutesLoading
                        ? 'Loading routes...'
                        : callTreeRoutes.length === 0
                          ? 'No FastAPI routes found'
                          : 'Select route...'}
                    </option>
                    {callTreeRoutes.map((route) => (
                      <option key={route.id} value={route.id}>
                        {(route.label || `${route.method} ${route.path}`)} ({route.handler})
                      </option>
                    ))}
                  </select>
                )}
              </div>
              <div className="flex-1">
                {diagramMode === 'investigation' ? (
                  <FlowVisualization
                    agentId={selectedAgentId}
                    flow={agentFlow}
                    variant="investigation"
                    onQueueInvestigation={
                      canQueueInvestigations
                        ? async (nodeId) => {
                          if (!selectedAgentId) return;
                          const res = await agentsApi.queueInvestigation(selectedAgentId, nodeId);
                          if (!res.queued) {
                            throw new Error(res.reason || 'Not queued');
                          }
                          const updated = await agentsApi.getFlow(selectedAgentId);
                          setAgentFlow(updated);
                        }
                        : undefined
                    }
                  />
                ) : (
                  <FlowVisualization
                    agentId={selectedRouteId}
                    flow={callTreeFlow}
                    variant="calltree"
                    emptySelectionText="Select a route to view call tree"
                    emptyFlowText={isCallTreeLoading ? 'Building call tree...' : 'No call tree data'}
                  />
                )}
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
              <div className="flex-1 overflow-hidden min-h-0">
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
          <span className="flex items-center gap-1" data-testid="ws-connection-status">
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

      {/* Auth Modal */}
      <AuthModal
        isOpen={showAuthModal}
        onClose={() => setShowAuthModal(false)}
      />

      {/* Resume Dialog */}
      {showResumeDialog && snapshotInfo && (
        <ResumeDialog
          snapshotInfo={snapshotInfo}
          onRestore={handleRestoreSession}
          onKeepCurrent={handleKeepCurrent}
          onClose={() => setShowResumeDialog(false)}
        />
      )}
    </div>
  );
}
