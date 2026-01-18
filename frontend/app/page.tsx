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
import { FindingDrawer } from '@/components/FindingsPanel/FindingDrawer';
import { ChatPanel } from '@/components/ChatPanel/ChatPanel';
import { SettingsModal } from '@/components/SettingsModal/SettingsModal';
import { ProjectSelector } from '@/components/ProjectSelector/ProjectSelector';
import { FlowVisualization } from '@/components/FlowVisualization/FlowVisualization';
import { TreeLayout } from '@/components/InvestigationFlow';
import { LLMInteractionPanel } from '@/components/LLMInteractionPanel';
import { ReportModal } from '@/components/ReportPanel';
import { ThreatModelModal } from '@/components/ThreatModel/ThreatModelModal';
import { AuthModal, AuthScreen } from '@/components/Auth';
import { SessionControls } from '@/components/SessionControls';
import { ResumeDialog } from '@/components/ResumeDialog';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useAuth } from '@/hooks/useAuth';
import { useInvestigationFlow } from '@/hooks/useInvestigationFlow';
import { useAgentManagement } from '@/hooks/useAgentManagement';
import { useFindingsManagement } from '@/hooks/useFindingsManagement';
import { useProjectWorkspace } from '@/hooks/useProjectWorkspace';
import { usePanelLayout, type ActivityView } from '@/hooks/usePanelLayout';
import { useSessionManagement } from '@/hooks/useSessionManagement';
import { useObservability } from '@/hooks/useObservability';
import { useCallTree } from '@/hooks/useCallTree';
import { featureFlags, FeatureFlag } from '@/lib/featureFlags';
import { agents as agentsApi, projects as projectsApi, setAuthFunctions, type Project } from '@/lib/api';
import type {
  InvestigationReport,
} from '@/types';

type ThreatModel = 'A' | 'AB' | 'ABC';

export default function Home() {
  // Project state
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [isProjectLoading, setIsProjectLoading] = useState(true);
  const [showThreatModelModal, setShowThreatModelModal] = useState(false);
  const [threatModelPresetPreview, setThreatModelPresetPreview] = useState<ThreatModel | null>(null);

  // Report state
  const [currentReport, setCurrentReport] = useState<InvestigationReport | null>(null);
  const [showReportModal, setShowReportModal] = useState(false);

  // Modal state
  const [showSettings, setShowSettings] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);

  // Auth state
  const { user, isAuthenticated, isLoading: isAuthLoading, logout, getAccessToken, refreshToken } = useAuth();

  // Feature flag state
  const [useSpanBasedFlow, setUseSpanBasedFlow] = useState(false);
  const [diagramMode, setDiagramMode] = useState<'investigation' | 'calltree'>('investigation');

  // Custom hooks for state management
  const panels = usePanelLayout();
  const workspace = useProjectWorkspace({ currentProject });
  const agentMgmt = useAgentManagement({ projectId: currentProject?.id || null, isAuthenticated });
  const findingsMgmt = useFindingsManagement({
    projectId: currentProject?.id || null,
    agents: agentMgmt.agents,
    selectedAgentId: agentMgmt.selectedAgentId,
    activeView: panels.activeView,
  });
  const sessionMgmt = useSessionManagement({
    currentProjectId: currentProject?.id || null,
    isAuthenticated,
    agents: agentMgmt.agents,
  });
  const observability = useObservability({
    selectedAgentId: agentMgmt.selectedAgentId,
    isAuthenticated,
  });
  const callTree = useCallTree({
    projectId: currentProject?.id || null,
    diagramMode,
    isAuthenticated,
  });

  // Span-based flow reconstruction (only when feature enabled)
  const flowEvents = agentMgmt.agentFlow?.nodes || [];
  const { spans, edges: spanEdges, isLoading: isReconstructing } = useInvestigationFlow(
    agentMgmt.selectedAgentId || '',
    useSpanBasedFlow ? flowEvents : []
  );

  // Fetch feature flags on mount
  useEffect(() => {
    if (user) {
      featureFlags.fetchFlags(user.id).then(() => {
        const enabled = featureFlags.isEnabled(FeatureFlag.SPAN_BASED_FLOW);
        setUseSpanBasedFlow(enabled);
      }).catch(error => {
        console.error('Failed to fetch feature flags:', error);
        // Default to false on error
        setUseSpanBasedFlow(false);
      });
    }
  }, [user]);

  // Auto-select agent for findings view - now handled by useFindingsManagement hook
  // Persist selected agent across refreshes - now handled by useAgentManagement hook

  // Set up API auth functions
  useEffect(() => {
    setAuthFunctions(getAccessToken, refreshToken);
  }, [getAccessToken, refreshToken]);

  // WebSocket - only connect after auth is ready (JWT or legacy session token)
  const { isConnected } = useWebSocket({
    enabled: isAuthenticated,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onFinding: useCallback((finding: any) => {
      // Only add finding if it belongs to an agent in the current project
      findingsMgmt.setFindings((prev) => {
        // Check if this finding's agent belongs to current project
        const belongsToCurrentProject = agentMgmt.agents.some(agent => agent.id === finding.agent_id);
        if (!belongsToCurrentProject) {
          console.log(`Ignoring finding from agent ${finding.agent_id} (different project)`);
          return prev;
        }
        return [finding, ...prev];
      });
    }, [agentMgmt.agents, findingsMgmt.setFindings]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onProgress: useCallback((agentId: string, progress: any) => {
      agentMgmt.setAgentProgress((prev) => ({ ...prev, [agentId]: progress }));
      // Check for flow updates in progress data
      if (progress && (progress as any).type === 'flow_update' && (progress as any).flow) {
        if (agentId === agentMgmt.selectedAgentId) {
          agentMgmt.setAgentFlow((progress as any).flow);
        }
      }
    }, [agentMgmt.selectedAgentId, agentMgmt.setAgentProgress, agentMgmt.setAgentFlow]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onAgentStatus: useCallback((agentId: string, status: string) => {
      agentMgmt.setAgents((prev) =>
        prev.map((a) =>
          a.id === agentId ? { ...a, status: status as any } : a
        )
      );
    }, [agentMgmt.setAgents]),
    // Observability handlers
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onLLMRequest: useCallback((agentId: string, interaction: any) => {
      if (!agentMgmt.selectedAgentId || agentId === agentMgmt.selectedAgentId) {
        observability.setLlmInteractions((prev) => [...prev, interaction]);
      }
    }, [agentMgmt.selectedAgentId, observability.setLlmInteractions]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onLLMResponse: useCallback((agentId: string, interaction: any) => {
      if (!agentMgmt.selectedAgentId || agentId === agentMgmt.selectedAgentId) {
        observability.setLlmInteractions((prev) => [...prev, interaction]);
      }
    }, [agentMgmt.selectedAgentId, observability.setLlmInteractions]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onToolDetail: useCallback((agentId: string, detail: any) => {
      if (!agentMgmt.selectedAgentId || agentId === agentMgmt.selectedAgentId) {
        observability.setToolDetails((prev) => [...prev, detail]);
      }
    }, [agentMgmt.selectedAgentId, observability.setToolDetails]),
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

  // Load flow and observability data - now handled by useAgentManagement and useObservability hooks
  // Load call-tree routes and build call tree - now handled by useCallTree hook

  // Initialize auth and check project status on mount
  useEffect(() => {
    if (isAuthLoading || !isAuthenticated) {
      return;
    }

    setIsProjectLoading(true);
    let cancelled = false;
    const initialize = async () => {
      try {
        const status = await projectsApi.getStatus();
        if (cancelled) return;
        if (status.current_project) {
          setCurrentProject(status.current_project);
          // Load project data when restoring from a previous session
          await loadProjectData(status.current_project);
        }
      } catch (err) {
        console.error('Failed to initialize:', err);
      } finally {
        if (!cancelled) setIsProjectLoading(false);
      }
    };
    initialize();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthLoading, isAuthenticated]);

  // Check for existing snapshot - now handled by useSessionManagement hook

  // Load project data when entering a project
  const loadProjectData = async (project: Project) => {
    // Load file tree
    await workspace.loadFileTree();

    // Load agents and findings
    try {
      await agentMgmt.refreshAgents();
      await findingsMgmt.refreshFindings();
    } catch (err) {
      console.error('Failed to load agents/findings:', err);
    }
  };

  // Handle entering a project
  const handleProjectEnter = async (project: Project) => {
    setCurrentProject(project);
    workspace.clearFile();
    agentMgmt.setAgents([]);
    findingsMgmt.setFindings([]);
    workspace.setFileTree(null);
    findingsMgmt.setSelectedFindingsAgentId(null);
    findingsMgmt.setUserSelectedFindingsAgentId(false);
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
    workspace.clearFile();
    agentMgmt.setAgents([]);
    findingsMgmt.setFindings([]);
    workspace.setFileTree(null);
    findingsMgmt.setSelectedFindingsAgentId(null);
    findingsMgmt.setUserSelectedFindingsAgentId(false);
  };

  const openThreatModelModal = (preset?: ThreatModel) => {
    if (!currentProject) return;
    setThreatModelPresetPreview(preset || (currentProject.threat_model || 'AB'));
    setShowThreatModelModal(true);
  };

  const handleThreatModelProfileUpdated = async () => {
    if (!currentProject) return;
    try {
      const refreshed = await projectsApi.get(currentProject.id);
      setCurrentProject(refreshed);
    } catch (err) {
      console.error('Failed to refresh project after threat model update:', err);
    }
  };

  // Select file
  const handleFileSelect = async (path: string) => {
    await workspace.selectFile(path);
  };

  // Finding click - open drawer
  const handleFindingClick = (finding: any) => {
    findingsMgmt.setSelectedFindingForDrawer(finding);
  };

  // Navigate to file from drawer
  const handleNavigateToFile = async (filePath: string) => {
    await handleFileSelect(filePath);
  };

  // Agent callbacks
  const handleAgentCreated = (agent: any) => {
    agentMgmt.setAgents((prev) => [agent, ...prev]);
  };

  const handleAgentUpdated = (agent: any) => {
    agentMgmt.setAgents((prev) => prev.map((a) => (a.id === agent.id ? agent : a)));
  };

  const handleAgentDeleted = (agentId: string) => {
    agentMgmt.setAgents((prev) => prev.filter((a) => a.id !== agentId));
    findingsMgmt.setFindings((prev) => prev.filter((f) => f.agent_id !== agentId));
  };

  // View report for an agent
  const handleViewReport = async (agentId: string) => {
    const report = await agentMgmt.loadReport(agentId);
    if (report) {
      setCurrentReport(report);
      setShowReportModal(true);
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
    await sessionMgmt.restoreSession({
      onFindingsRestore: (findings) => findingsMgmt.setFindings(findings),
      onActiveViewRestore: (view) => panels.setActiveView(view),
      onSelectedFileRestore: (path) => workspace.setSelectedPath(path),
      onSelectedAgentRestore: (agentId) => agentMgmt.selectAgent(agentId),
    });
  }, [sessionMgmt, findingsMgmt, panels, workspace, agentMgmt]);

  // Handle showing dialog or auto-restore when snapshotInfo changes
  useEffect(() => {
    if (!sessionMgmt.snapshotInfo) return;

    // Check if we have running agents (conflict)
    const hasRunning = agentMgmt.agents.some(a => a.status === 'running');

    if (!hasRunning) {
      // Auto-restore if no conflict
      handleRestoreSession();
    }
  }, [sessionMgmt.snapshotInfo, agentMgmt.agents, handleRestoreSession]);

  const handleKeepCurrent = useCallback(async () => {
    await sessionMgmt.keepCurrentSession();
  }, [sessionMgmt]);

  const handleSessionPaused = useCallback(() => {
    // Could show a toast notification here
    console.log('Session paused successfully');
  }, []);

  const handleSessionError = useCallback((error: string) => {
    console.error('Session error:', error);
    // Could show error toast here
  }, []);

  // Count running agents and findings
  const runningAgents = agentMgmt.agents.filter((a) => a.status === 'running').length;
  const criticalFindings = findingsMgmt.findings.filter((f) => f.severity === 'critical').length;
  const highFindings = findingsMgmt.findings.filter((f) => f.severity === 'high').length;
  const selectedAgent = agentMgmt.selectedAgentId ? agentMgmt.agents.find((a) => a.id === agentMgmt.selectedAgentId) : null;
  const canQueueInvestigations = Boolean(
    selectedAgent &&
      ['deep_scan', 'deep_audit', 'custom', 'strict_analysis', 'ultra_strict'].includes(selectedAgent.agent_type)
  );

  // Show loading while checking project status
  // Auth gate: Show loading while checking authentication
  if (isAuthLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-vsc-bg">
        <RefreshCw className="w-8 h-8 text-vsc-accent animate-spin" />
      </div>
    );
  }

  // Auth gate: Show login screen if not authenticated
  if (!isAuthenticated) {
    return <AuthScreen />;
  }

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
              onChange={(e) => openThreatModelModal(e.target.value as ThreatModel)}
              className="px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-xs"
              title="Opens the Project Threat Model editor (changes require explicit reset/save)"
            >
              <option value="A">Internet (A)</option>
              <option value="AB">Internet + Auth (A+B)</option>
              <option value="ABC">Internet + Auth + Insider (A+B+C)</option>
            </select>
            {currentProject.profile_review_status === 'unreviewed' && (
              <button
                onClick={() => openThreatModelModal()}
                className="px-2 py-0.5 rounded text-vsc-xs bg-yellow-900/40 text-yellow-200 border border-yellow-800 hover:bg-yellow-900/60"
                title="Preset-derived profile; review to confirm attacker capabilities + repo_checkout semantics"
              >
                Unreviewed
              </button>
            )}
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
            sessionStatus={sessionMgmt.sessionStatus}
            onStatusChange={sessionMgmt.setSessionStatus}
            hasRunningAgents={agentMgmt.agents.some(a => a.status === 'running')}
            activeView={panels.activeView}
            selectedFile={workspace.selectedPath}
            openPanels={[
              panels.showSidebar ? 'sidebar' : '',
              panels.showPanel ? 'panel' : '',
              panels.showChat ? 'chat' : '',
            ].filter(Boolean)}
            selectedAgentId={agentMgmt.selectedAgentId}
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
              panels.setActiveView('explorer');
              panels.setShowSidebar(true);
            }}
            className={`activity-icon ${panels.activeView === 'explorer' && panels.showSidebar ? 'active' : ''}`}
            title="Explorer"
          >
            <Files className="w-6 h-6" />
          </button>
          <button
            onClick={() => {
              panels.setActiveView('agents');
              panels.setShowSidebar(true);
            }}
            className={`activity-icon ${panels.activeView === 'agents' && panels.showSidebar ? 'active' : ''}`}
            title="Agents"
          >
            <Bug className="w-6 h-6" />
            {runningAgents > 0 && (
              <span
                className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-vsc-accent scan-indicator"
              />
            )}
            {runningAgents === 0 && agentMgmt.agents.some(a => a.status === 'paused') && (
              <span
                className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-vsc-accent scan-indicator-paused"
              />
            )}
            {runningAgents === 0 && agentMgmt.agents.some(a => a.status === 'completed' && a.findings_count > 0) &&
             !agentMgmt.agents.some(a => a.status === 'running' || a.status === 'paused') && (
              <span
                className={`absolute top-2 right-2 w-1.5 h-1.5 rounded-full ${
                  findingsMgmt.findings.some(f => f.severity === 'critical') ? 'bg-sev-critical' :
                  findingsMgmt.findings.some(f => f.severity === 'high') ? 'bg-sev-high' : 'bg-vsc-accent'
                }`}
              />
            )}
          </button>
          <button
            onClick={() => {
              panels.setActiveView('findings');
              panels.setShowSidebar(true);
            }}
            className={`activity-icon ${panels.activeView === 'findings' && panels.showSidebar ? 'active' : ''}`}
            title="Findings"
          >
            <Search className="w-6 h-6" />
            {(criticalFindings > 0 || highFindings > 0) && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-sev-critical rounded-full" />
            )}
          </button>
          <button
            onClick={() => {
              panels.setActiveView('flow');
              panels.setShowSidebar(false);
            }}
            className={`activity-icon ${panels.activeView === 'flow' ? 'active' : ''}`}
            title="Investigation Flow"
          >
            <Network className="w-6 h-6" />
          </button>
          <button
            onClick={() => {
              panels.setActiveView('llm');
              panels.setShowSidebar(false);
            }}
            className={`activity-icon ${panels.activeView === 'llm' ? 'active' : ''}`}
            title="LLM Interactions"
          >
            <Brain className="w-6 h-6" />
            {observability.llmInteractions.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-vsc-accent rounded-full" />
            )}
          </button>

          <div className="flex-1" />

          <button
            onClick={panels.toggleChat}
            className={`activity-icon ${panels.showChat ? 'active' : ''}`}
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
        {panels.showSidebar && (
          <aside className="w-64 bg-vsc-sidebar flex flex-col border-r border-vsc-border-subtle">
            {/* Sidebar header with view title */}
            <div className="panel-header">
              <span>
                {panels.activeView === 'explorer' && 'EXPLORER'}
                {panels.activeView === 'agents' && 'AGENTS'}
                {panels.activeView === 'findings' && 'FINDINGS'}
              </span>
              <button
                onClick={() => panels.setShowSidebar(false)}
                className="btn-icon"
              >
                <X className="w-4 h-4" />
              </button>
            </div>


            {/* Sidebar content based on active view */}
            <div className="flex-1 overflow-hidden">
              {panels.activeView === 'explorer' && (
                <FileTree
                  tree={workspace.fileTree}
                  selectedPath={workspace.selectedPath}
                  onFileSelect={handleFileSelect}
                />
              )}

              {panels.activeView === 'agents' && (
                <AgentManager
                  repoId={currentProject.id}
                  agents={agentMgmt.agents}
                  progress={agentMgmt.agentProgress}
                  onAgentCreated={handleAgentCreated}
                  onAgentUpdated={handleAgentUpdated}
                  onAgentDeleted={handleAgentDeleted}
                  onViewReport={handleViewReport}
                />
              )}

              {panels.activeView === 'findings' && (
                <div className="h-full flex flex-col overflow-hidden">
                  {/* Agent selector for findings */}
                  <div className="h-10 bg-vsc-sidebar border-b border-vsc-border-subtle flex items-center px-3 gap-2 flex-shrink-0">
                    <Bug className="w-4 h-4 text-vsc-text-muted" />
                    <select
                      value={findingsMgmt.selectedFindingsAgentId || ''}
                      onChange={(e) => {
                        findingsMgmt.setUserSelectedFindingsAgentId(true);
                        findingsMgmt.setSelectedFindingsAgentId(e.target.value || null);
                      }}
                      className="flex-1 px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm"
                    >
                      {!findingsMgmt.selectedFindingsAgentId && <option value="">Select an agent...</option>}
                      {agentMgmt.agents.map((agent) => (
                        <option key={agent.id} value={agent.id}>
                          {agent.name} ({findingsMgmt.findings.filter(f => f.agent_id === agent.id).length} findings)
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="flex-1 overflow-hidden">
                    <FindingsList
                      key={findingsMgmt.selectedFindingsAgentId || 'none'}
                      findings={
                        findingsMgmt.selectedFindingsAgentId
                          ? findingsMgmt.findings.filter(f => f.agent_id === findingsMgmt.selectedFindingsAgentId)
                          : []
                      }
                      onFindingClick={handleFindingClick}
                      onNavigateToFile={(finding) => handleNavigateToFile(finding.file_path)}
                    />
                  </div>
                </div>
              )}
            </div>
          </aside>
        )}

        {/* Main content area */}
        <main className="flex-1 flex flex-col overflow-hidden bg-vsc-bg">
          {/* Flow visualization view */}
          {panels.activeView === 'flow' && (
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
                    value={agentMgmt.selectedAgentId || ''}
                    onChange={(e) => agentMgmt.selectAgent(e.target.value || null)}
                    className="ml-2 px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm"
                  >
                    <option value="">Select agent...</option>
                    {agentMgmt.agents.map((agent) => (
                      <option key={agent.id} value={agent.id}>
                        {agent.name} ({agent.status})
                      </option>
                    ))}
                  </select>
                ) : (
                  <select
                    value={callTree.selectedRouteId || ''}
                    onChange={(e) => callTree.setSelectedRouteId(e.target.value || null)}
                    className="ml-2 px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm min-w-[320px]"
                    disabled={callTree.isCallTreeRoutesLoading}
                    data-testid="calltree-route-select"
                  >
                    <option value="">
                      {callTree.isCallTreeRoutesLoading
                        ? 'Loading routes...'
                        : callTree.callTreeRoutes.length === 0
                          ? 'No FastAPI routes found'
                          : 'Select route...'}
                    </option>
                    {callTree.callTreeRoutes.map((route) => (
                      <option key={route.id} value={route.id}>
                        {(route.label || `${route.method} ${route.path}`)} ({route.handler})
                      </option>
                    ))}
                  </select>
                )}
              </div>
              <div className="flex-1">
                {diagramMode === 'investigation' ? (
                  useSpanBasedFlow ? (
                    // New span-based visualization
                    isReconstructing ? (
                      <div className="flex items-center justify-center h-full text-vsc-fg">
                        Reconstructing investigation flow...
                      </div>
                    ) : (
                      <TreeLayout spans={spans} edges={spanEdges} />
                    )
                  ) : (
                    // Legacy flow visualization
                    <FlowVisualization
                      agentId={agentMgmt.selectedAgentId}
                      flow={agentMgmt.agentFlow}
                      variant="investigation"
                      onQueueInvestigation={
                        canQueueInvestigations
                          ? async (nodeId) => {
                            if (!agentMgmt.selectedAgentId) return;
                            const res = await agentsApi.queueInvestigation(agentMgmt.selectedAgentId, nodeId);
                            if (!res.queued) {
                              throw new Error(res.reason || 'Not queued');
                            }
                            const updated = await agentsApi.getFlow(agentMgmt.selectedAgentId);
                            agentMgmt.setAgentFlow(updated);
                          }
                          : undefined
                      }
                    />
                  )
                ) : (
                  <FlowVisualization
                    agentId={callTree.selectedRouteId}
                    flow={callTree.callTreeFlow}
                    variant="calltree"
                    emptySelectionText="Select a route to view call tree"
                    emptyFlowText={callTree.isCallTreeLoading ? 'Building call tree...' : 'No call tree data'}
                  />
                )}
              </div>
            </div>
          )}

          {/* LLM Interactions view */}
          {panels.activeView === 'llm' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Agent selector for LLM view */}
              <div className="h-10 bg-vsc-sidebar border-b border-vsc-border-subtle flex items-center px-3 gap-2">
                <Brain className="w-4 h-4 text-vsc-text-muted" />
                <span className="text-vsc-sm text-vsc-text-muted">LLM Interactions</span>
                <select
                  value={agentMgmt.selectedAgentId || ''}
                  onChange={(e) => agentMgmt.selectAgent(e.target.value || null)}
                  className="ml-2 px-2 py-1 bg-vsc-input border border-vsc-border rounded text-vsc-sm"
                >
                  <option value="">Select agent...</option>
                  {agentMgmt.agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name} ({agent.status})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex-1 overflow-hidden min-h-0">
                <LLMInteractionPanel
                  agentId={agentMgmt.selectedAgentId}
                  interactions={observability.llmInteractions}
                  toolDetails={observability.toolDetails}
                  isConnected={isConnected}
                />
              </div>
            </div>
          )}

          {/* Tab bar */}
          {panels.activeView !== 'flow' && panels.activeView !== 'llm' && workspace.currentFile && (
            <div className="h-9 bg-vsc-sidebar flex items-end border-b border-vsc-border-subtle">
              <div className="tab active">
                <span className="truncate max-w-[200px]">
                  {workspace.currentFile.path.split('/').pop()}
                </span>
                <button
                  onClick={workspace.clearFile}
                  className="ml-1 p-0.5 rounded hover:bg-vsc-hover"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* Breadcrumb */}
          {panels.activeView !== 'flow' && panels.activeView !== 'llm' && workspace.currentFile && (
            <div className="breadcrumb border-b border-vsc-border-subtle">
              {workspace.currentFile.path.split('/').map((part, idx, arr) => (
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
          {panels.activeView !== 'flow' && panels.activeView !== 'llm' && (
            <div className="flex-1 overflow-hidden">
              <MonacoEditor
                file={workspace.currentFile}
                findings={findingsMgmt.findings.filter((f) => f.file_path === workspace.currentFile?.path)}
              />
            </div>
          )}
        </main>

        {/* Right panel - can show agents or findings in split view */}
        {panels.showPanel && workspace.currentFile && findingsMgmt.findings.filter((f) => f.file_path === workspace.currentFile?.path).length > 0 && (
          <aside className="w-80 bg-vsc-sidebar border-l border-vsc-border-subtle flex flex-col">
            <div className="panel-header">
              <span>FILE FINDINGS</span>
              <button
                onClick={() => panels.setShowPanel(false)}
                className="btn-icon"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-auto">
              <FindingsList
                findings={findingsMgmt.findings.filter((f) => f.file_path === workspace.currentFile?.path)}
                onFindingClick={handleFindingClick}
                onNavigateToFile={(finding) => handleNavigateToFile(finding.file_path)}
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
            {findingsMgmt.findings.length} findings
            {criticalFindings > 0 && (
              <span className="text-sev-critical">({criticalFindings} critical)</span>
            )}
          </span>
        </div>
      </footer>

      {/* Chat Panel (left pop-out) */}
      <ChatPanel
        isOpen={panels.showChat}
        onToggle={panels.toggleChat}
        currentFile={workspace.currentFile}
        findings={findingsMgmt.findings}
        onRequestSettings={() => setShowSettings(true)}
      />

      {/* Settings Modal */}
      <SettingsModal
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
      />

      <ThreatModelModal
        isOpen={showThreatModelModal}
        onClose={() => {
          setShowThreatModelModal(false);
          setThreatModelPresetPreview(null);
        }}
        projectId={currentProject.id}
        presetPreview={threatModelPresetPreview}
        onProfileUpdated={handleThreatModelProfileUpdated}
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
      {sessionMgmt.showResumeDialog && sessionMgmt.snapshotInfo && (
        <ResumeDialog
          snapshotInfo={sessionMgmt.snapshotInfo}
          onRestore={handleRestoreSession}
          onKeepCurrent={handleKeepCurrent}
          onClose={() => sessionMgmt.setShowResumeDialog(false)}
        />
      )}

      {/* Finding Drawer */}
      {findingsMgmt.selectedFindingForDrawer && (
        <FindingDrawer
          finding={findingsMgmt.selectedFindingForDrawer}
          onClose={() => findingsMgmt.setSelectedFindingForDrawer(null)}
          onNavigateToFile={handleNavigateToFile}
        />
      )}
    </div>
  );
}
