'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
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
import { FindingFullView } from '@/components/FindingsPanel/FindingFullView';
import { ChatPanel } from '@/components/ChatPanel/ChatPanel';
import { SettingsModal } from '@/components/SettingsModal/SettingsModal';
import { ProjectSelector } from '@/components/ProjectSelector/ProjectSelector';
import { FlowVisualization } from '@/components/FlowVisualization/FlowVisualization';
import { LLMInteractionPanel } from '@/components/LLMInteractionPanel';
import { ReportModal } from '@/components/ReportPanel';
import { ThreatModelModal } from '@/components/ThreatModel/ThreatModelModal';
import { AuthModal, AuthScreen } from '@/components/Auth';
import { SessionControls } from '@/components/SessionControls';
import { ResumeDialog } from '@/components/ResumeDialog';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useAuth } from '@/hooks/useAuth';
import { useAgentManagement } from '@/hooks/useAgentManagement';
import { useFindingsManagement } from '@/hooks/useFindingsManagement';
import { useProjectWorkspace } from '@/hooks/useProjectWorkspace';
import { usePanelLayout, type ActivityView } from '@/hooks/usePanelLayout';
import { useSessionManagement } from '@/hooks/useSessionManagement';
import { useObservability } from '@/hooks/useObservability';
import { agents as agentsApi, projects as projectsApi, files as filesApi, setAuthFunctions, type Project } from '@/lib/api';
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

  // Chat state (post-scan contextual chat)
  const [chatFlowContextPack, setChatFlowContextPack] = useState<unknown | null>(null);
  const [chatSeedMessage, setChatSeedMessage] = useState<{ id: string; text: string } | null>(null);

  // Auth state
  const { user, isAuthenticated, isLoading: isAuthLoading, logout, getAccessToken, refreshToken } = useAuth();

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

  const projectLoadTokenRef = useRef(0);

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
	      const projectId = currentProject?.id;
	      if (!projectId) return;

	      // Only add finding if it belongs to the current project.
	      // (The backend broadcasts all events to all clients.)
	      findingsMgmt.setFindings((prev) => {
	        if (finding?.repo_id !== projectId) return prev;

	        // Deduplicate by (agent_id, id) to avoid duplicates when we also refresh from the API.
	        const alreadyPresent = prev.some(
	          (f) => f.id === finding.id && f.agent_id === finding.agent_id
	        );
	        if (alreadyPresent) return prev;

	        return [finding, ...prev];
	      });
	    }, [currentProject?.id, findingsMgmt.setFindings]),
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
	      const isKnownAgent = agentMgmt.agents.some((a) => a.id === agentId);
	      if (!isKnownAgent) return;

	      agentMgmt.setAgents((prev) =>
	        prev.map((a) =>
	          a.id === agentId ? { ...a, status: status as any } : a
	        )
	      );
	      if (status === 'completed' || status === 'failed' || status === 'cancelled') {
	        // Ensure findings are fresh even if we missed WS messages during refresh/reconnect.
	        findingsMgmt.refreshFindings();
	      }
	    }, [agentMgmt.agents, agentMgmt.setAgents, findingsMgmt.refreshFindings]),
    // Observability handlers
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onLLMRequest: useCallback((agentId: string, interaction: any) => {
      if (agentId === agentMgmt.selectedAgentId) {
        observability.setLlmInteractions((prev) => [...prev, interaction]);
      }
    }, [agentMgmt.selectedAgentId, observability.setLlmInteractions]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onLLMResponse: useCallback((agentId: string, interaction: any) => {
      if (agentId === agentMgmt.selectedAgentId) {
        observability.setLlmInteractions((prev) => [...prev, interaction]);
      }
    }, [agentMgmt.selectedAgentId, observability.setLlmInteractions]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    onToolDetail: useCallback((agentId: string, detail: any) => {
      if (agentId === agentMgmt.selectedAgentId) {
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
    const loadToken = ++projectLoadTokenRef.current;

    // Load critical UI state first (agents + findings) so refresh doesn't look "empty" if file-tree is slow.
    try {
      const [agents, findings] = await Promise.all([
        agentsApi.list(project.id),
        agentsApi.getAllFindings(project.id),
      ]);
      if (projectLoadTokenRef.current !== loadToken) return;
      agentMgmt.setAgents(agents);
      findingsMgmt.setFindings(findings);
    } catch (err) {
      console.error('Failed to load agents/findings:', err);
    }

    // Load file tree after (don’t block the main UI on it).
    const needsFileTree = project.repo_name || project.is_cloned;
    if (!needsFileTree) {
      if (projectLoadTokenRef.current !== loadToken) return;
      workspace.setFileTree(null);
      return;
    }

    filesApi.getTree(project.id, 1, '', { maxChildren: 200, maxNodes: 5000 })
      .then((tree) => {
        if (projectLoadTokenRef.current !== loadToken) return;
        workspace.setFileTree(tree);
      })
      .catch((err) => {
        console.error('Failed to load file tree:', err);
      });
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
    panels.setActiveView('explorer');
  };

  const handleClearChatFlowContext = useCallback(() => {
    setChatFlowContextPack(null);
  }, []);

  const handleOpenChatFromFlow = useCallback(
    async (payload: { contextPack: unknown; filePath?: string; seedText?: string }) => {
      setChatFlowContextPack(payload.contextPack);

      if (typeof payload.filePath === 'string' && payload.filePath.trim()) {
        try {
          await workspace.selectFile(payload.filePath.trim());
        } catch (err) {
          console.error('Failed to load file for chat context:', err);
        }
      }

      panels.setShowChat(true);
      if (typeof payload.seedText === 'string' && payload.seedText.trim()) {
        setChatSeedMessage({ id: String(Date.now()), text: payload.seedText });
      }
    },
    [panels, workspace]
  );

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
      ['deep_audit', 'custom'].includes(selectedAgent.agent_type)
  );

  // Show loading while checking project status
  // Auth gate: Show loading while checking authentication
  if (isAuthLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-bg-primary">
        <RefreshCw className="w-8 h-8 text-accent animate-spin" />
      </div>
    );
  }

  // Auth gate: Show login screen if not authenticated
  if (!isAuthenticated) {
    return <AuthScreen />;
  }

  if (isProjectLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-bg-primary">
        <RefreshCw className="w-8 h-8 text-accent animate-spin" />
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
    <div className="h-screen flex flex-col bg-bg-primary scanlines">
      {/* Project header bar */}
      <header className="h-9 bg-bg-secondary flex items-center justify-between px-3 border-b border-border-subtle select-none">
        <div className="flex items-center gap-3">
          <span className="text-text-muted text-xs">quick_hack</span>
          <div className="flex items-center gap-2 text-text-primary">
            <FolderGit2 className="w-4 h-4 text-accent" />
            <span className="text-sm font-medium">{currentProject.name}</span>
            {currentProject.repo_name && (
              <span className="text-xs text-text-muted">
                ({currentProject.repo_name})
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted">Threat model</span>
            <select
              value={(currentProject.threat_model || 'AB') as ThreatModel}
              onChange={(e) => openThreatModelModal(e.target.value as ThreatModel)}
              className="px-2 py-1 bg-bg-tertiary border border-border-default rounded text-xs"
              title="Opens the Project Threat Model editor (changes require explicit reset/save)"
            >
              <option value="A">Internet (A)</option>
              <option value="AB">Internet + Auth (A+B)</option>
              <option value="ABC">Internet + Auth + Insider (A+B+C)</option>
            </select>
            {currentProject.profile_review_status === 'unreviewed' && (
              <button
                onClick={() => openThreatModelModal()}
                className="px-2 py-0.5 rounded text-xs bg-yellow-900/40 text-yellow-200 border border-yellow-800 hover:bg-yellow-900/60"
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
        <aside className="w-12 bg-bg-secondary flex flex-col items-center py-1 border-r border-border-subtle">
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
                className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-accent scan-indicator"
              />
            )}
            {runningAgents === 0 && agentMgmt.agents.some(a => a.status === 'paused') && (
              <span
                className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-accent scan-indicator-paused"
              />
            )}
            {runningAgents === 0 && agentMgmt.agents.some(a => a.status === 'completed' && a.findings_count > 0) &&
             !agentMgmt.agents.some(a => a.status === 'running' || a.status === 'paused') && (
              <span
                className={`absolute top-2 right-2 w-1.5 h-1.5 rounded-full ${
                  findingsMgmt.findings.some(f => f.severity === 'critical') ? 'bg-sev-critical' :
                  findingsMgmt.findings.some(f => f.severity === 'high') ? 'bg-sev-high' : 'bg-accent'
                }`}
              />
            )}
          </button>
          <button
            onClick={() => {
              if (panels.activeView === 'findings' && panels.showSidebar) {
                // Already in sidebar mode - switch to full-screen
                panels.setShowSidebar(false);
              } else if (panels.activeView === 'findings' && !panels.showSidebar) {
                // Already in full-screen - switch to sidebar
                panels.setShowSidebar(true);
              } else {
                // Not in findings view - go to full-screen findings
                panels.setActiveView('findings');
                panels.setShowSidebar(false);
              }
            }}
            className={`activity-icon ${panels.activeView === 'findings' ? 'active' : ''}`}
            title="Findings (click again to toggle view)"
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
              <span className="absolute top-1 right-1 w-2 h-2 bg-accent rounded-full" />
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
          <aside className="w-64 bg-bg-secondary flex flex-col border-r border-border-subtle">
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
                  onDirectoryExpand={workspace.expandDirectory}
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
                  <div className="h-10 bg-bg-secondary border-b border-border-subtle flex items-center px-3 gap-2 flex-shrink-0">
                    <Bug className="w-4 h-4 text-text-muted" />
	                    <select
	                      value={findingsMgmt.selectedFindingsAgentId || ''}
	                      onChange={(e) => {
	                        findingsMgmt.setUserSelectedFindingsAgentId(true);
	                        findingsMgmt.setSelectedFindingsAgentId(e.target.value || null);
	                      }}
	                      className="flex-1 px-2 py-1 bg-bg-tertiary border border-border-default rounded text-sm"
	                    >
	                      <option value="">
	                        All agents ({findingsMgmt.findings.length} findings)
	                      </option>
	                      {agentMgmt.agents.map((agent) => (
	                        <option key={agent.id} value={agent.id}>
	                          {agent.name} ({findingsMgmt.findings.filter(f => f.agent_id === agent.id).length} findings)
	                        </option>
	                      ))}
	                    </select>
	                  </div>
	                  <div className="flex-1 overflow-hidden">
	                    <FindingsList
	                      key={findingsMgmt.selectedFindingsAgentId || 'all'}
	                      agentId={findingsMgmt.selectedFindingsAgentId}
	                      findings={
	                        findingsMgmt.selectedFindingsAgentId
	                          ? findingsMgmt.findings.filter(f => f.agent_id === findingsMgmt.selectedFindingsAgentId)
	                          : findingsMgmt.findings
	                      }
	                      onFindingClick={handleFindingClick}
	                      onNavigateToFile={(finding) => handleNavigateToFile(finding.file_path)}
	                      onFindingsUpdated={(triaged) => {
	                        // Replace findings for this agent with triaged results
	                        findingsMgmt.setFindings((prev) => {
	                          const otherFindings = prev.filter(f => f.agent_id !== findingsMgmt.selectedFindingsAgentId);
	                          return [...otherFindings, ...triaged];
	                        });
	                      }}
	                    />
	                  </div>
	                </div>
	              )}
            </div>
          </aside>
        )}

        {/* Main content area */}
        <main className="flex-1 flex flex-col overflow-hidden bg-bg-primary">
	          {/* Flow visualization view */}
	          {panels.activeView === 'flow' && (
	            <div className="flex-1 flex flex-col overflow-hidden">
	              <div className="h-10 bg-bg-secondary border-b border-border-subtle flex items-center px-3 gap-2">
	                <Network className="w-4 h-4 text-text-muted" />
	                <span className="text-sm text-text-muted">Structured Trace</span>
	                <select
	                  value={agentMgmt.selectedAgentId || ''}
	                  onChange={(e) => agentMgmt.selectAgent(e.target.value || null)}
	                  className="ml-2 px-2 py-1 bg-bg-tertiary border border-border-default rounded text-sm"
	                >
	                  <option value="">Select agent...</option>
	                  {agentMgmt.agents.map((agent) => (
	                    <option key={agent.id} value={agent.id}>
	                      {agent.name} ({agent.status})
	                    </option>
	                  ))}
	                </select>
	              </div>
	              <div className="flex-1">
	                <FlowVisualization
	                  agentId={agentMgmt.selectedAgentId}
	                  flow={agentMgmt.agentFlow}
	                  variant="structured"
	                  findings={findingsMgmt.findings}
	                  onOpenChat={handleOpenChatFromFlow}
	                  onOpenFile={handleNavigateToFile}
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
	              </div>
	            </div>
	          )}

          {/* LLM Interactions view */}
          {panels.activeView === 'llm' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Agent selector for LLM view */}
              <div className="h-10 bg-bg-secondary border-b border-border-subtle flex items-center px-3 gap-2">
                <Brain className="w-4 h-4 text-text-muted" />
                <span className="text-sm text-text-muted">LLM Interactions</span>
                <select
                  value={agentMgmt.selectedAgentId || ''}
                  onChange={(e) => agentMgmt.selectAgent(e.target.value || null)}
                  className="ml-2 px-2 py-1 bg-bg-tertiary border border-border-default rounded text-sm"
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

          {/* Full-screen Findings view */}
          {panels.activeView === 'findings' && panels.showSidebar === false && (
            <div className="flex-1 flex overflow-hidden">
              {/* Findings list on left */}
              <div className="w-80 border-r border-border-subtle flex flex-col bg-bg-secondary">
                <div className="h-10 bg-bg-secondary border-b border-border-subtle flex items-center px-3 gap-2">
                  <Shield className="w-4 h-4 text-text-muted" />
                  <span className="text-sm text-text-muted">Findings</span>
                  <select
                    value={findingsMgmt.selectedFindingsAgentId || ''}
                    onChange={(e) => {
                      findingsMgmt.setUserSelectedFindingsAgentId(true);
                      findingsMgmt.setSelectedFindingsAgentId(e.target.value || null);
                    }}
                    className="ml-auto px-2 py-1 bg-bg-tertiary border border-border-default rounded text-xs"
                  >
                    <option value="">All agents ({findingsMgmt.findings.length})</option>
                    {agentMgmt.agents.map((agent) => (
                      <option key={agent.id} value={agent.id}>
                        {agent.name} ({findingsMgmt.findings.filter(f => f.agent_id === agent.id).length})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex-1 overflow-auto">
                  <FindingsList
                    key={findingsMgmt.selectedFindingsAgentId || 'all'}
                    agentId={findingsMgmt.selectedFindingsAgentId}
                    findings={
                      findingsMgmt.selectedFindingsAgentId
                        ? findingsMgmt.findings.filter(f => f.agent_id === findingsMgmt.selectedFindingsAgentId)
                        : findingsMgmt.findings
                    }
                    onFindingClick={(finding) => findingsMgmt.setSelectedFindingForDrawer(finding)}
                    onNavigateToFile={(finding) => handleNavigateToFile(finding.file_path)}
                    onFindingsUpdated={(triaged) => {
                      findingsMgmt.setFindings((prev) => {
                        const otherFindings = prev.filter(f => f.agent_id !== findingsMgmt.selectedFindingsAgentId);
                        return [...otherFindings, ...triaged];
                      });
                    }}
                  />
                </div>
              </div>
              {/* Finding details on right */}
              <div className="flex-1 bg-bg-primary overflow-auto">
                {findingsMgmt.selectedFindingForDrawer ? (
                  <div className="p-6 max-w-4xl mx-auto">
                    <FindingFullView
                      finding={findingsMgmt.selectedFindingForDrawer}
                      onNavigateToFile={handleNavigateToFile}
                    />
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-full text-text-muted">
                    <div className="text-center">
                      <Shield className="w-12 h-12 mx-auto mb-4 opacity-30" />
                      <p>Select a finding to view details</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab bar */}
          {panels.activeView !== 'flow' && panels.activeView !== 'llm' && (panels.activeView !== 'findings' || panels.showSidebar) && workspace.currentFile && (
            <div className="h-9 bg-bg-secondary flex items-end border-b border-border-subtle">
              <div className="tab active">
                <span className="truncate max-w-[200px]">
                  {workspace.currentFile.path.split('/').pop()}
                </span>
                <button
                  onClick={workspace.clearFile}
                  className="ml-1 p-0.5 rounded hover:bg-bg-tertiary"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* Breadcrumb */}
          {panels.activeView !== 'flow' && panels.activeView !== 'llm' && (panels.activeView !== 'findings' || panels.showSidebar) && workspace.currentFile && (
            <div className="breadcrumb border-b border-border-subtle">
              {workspace.currentFile.path.split('/').map((part, idx, arr) => (
                <span key={idx} className="flex items-center">
                  {idx > 0 && <ChevronRight className="breadcrumb-separator w-3 h-3" />}
                  <span className={idx === arr.length - 1 ? 'text-text-primary' : 'breadcrumb-item'}>
                    {part}
                  </span>
                </span>
              ))}
            </div>
          )}

          {/* Editor */}
          {panels.activeView !== 'flow' && panels.activeView !== 'llm' && (panels.activeView !== 'findings' || panels.showSidebar) && (
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
          <aside className="w-80 bg-bg-secondary border-l border-border-subtle flex flex-col">
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
      <footer className="h-6 bg-bg-primary border-t border-border-default flex items-center px-3 text-xs text-text-secondary select-none">
        <div className="flex items-center gap-3">
          {/* Connection status */}
          <span className="flex items-center gap-1" data-testid="ws-connection-status">
            <Circle className={`w-2 h-2 ${isConnected ? 'fill-status-confirmed text-status-confirmed' : 'fill-sev-critical text-sev-critical'}`} />
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
        provider={selectedAgent?.provider_config?.provider}
        model={selectedAgent?.provider_config?.model}
        flowContextPack={chatFlowContextPack}
        seedMessage={chatSeedMessage}
        onClearFlowContext={handleClearChatFlowContext}
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
