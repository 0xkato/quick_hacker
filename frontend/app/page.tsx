'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import {
  Files,
  Crosshair,
  Rocket,
  BarChart3,
  AlertTriangle,
  Shield,
  Network,
  Compass,
  GitBranch,
  Settings,
  MessageSquare,
  X,
  ChevronRight,
  RefreshCw,
  Circle,
  FolderGit2,
  LogOut,
} from 'lucide-react';

// Auth
import { useAuth } from '@/hooks/useAuth';
import { AuthScreen } from '@/components/Auth';

// Layout / shell
import { usePanelLayout, type ActivityView } from '@/hooks/usePanelLayout';
import { ProjectSelector } from '@/components/ProjectSelector/ProjectSelector';
import { SettingsModal } from '@/components/SettingsModal/SettingsModal';
import { MonacoEditor } from '@/components/Editor/MonacoEditor';
import { FileTree } from '@/components/FileExplorer/FileTree';
import { ChatPanel } from '@/components/ChatPanel/ChatPanel';
import { SessionControls } from '@/components/SessionControls';
import { ResumeDialog } from '@/components/ResumeDialog';

// Campaign components
import { CampaignManager } from '@/components/Campaigns';
import { TargetList } from '@/components/Targets';
import { CoveragePanel } from '@/components/Coverage';
import { FailuresPanel } from '@/components/Failures';
import { IssuesList } from '@/components/Findings';
import { CampaignGraph } from '@/components/Graph';
import { SteeringPanel } from '@/components/Steering';
import { BehaviorTree, BTNodeDetail } from '@/components/BehaviorTree';

// Campaign hooks
import { useCampaignManagement } from '@/hooks/useCampaignManagement';
import { useTargets } from '@/hooks/useTargets';
import { useLanes } from '@/hooks/useLanes';
import { useCoverage } from '@/hooks/useCoverage';
import { useArtifacts } from '@/hooks/useArtifacts';
import { useIssues } from '@/hooks/useIssues';
import { useSteering } from '@/hooks/useSteering';

// Existing hooks
import { useProjectWorkspace } from '@/hooks/useProjectWorkspace';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useSessionManagement } from '@/hooks/useSessionManagement';
import { useBehaviorTree } from '@/hooks/useBehaviorTree';

import { projects as projectsApi, files as filesApi, setAuthFunctions, type Project } from '@/lib/api';

// ---------------------------------------------------------------------------
// Sidebar title map
// ---------------------------------------------------------------------------
const SIDEBAR_TITLES: Partial<Record<ActivityView, string>> = {
  explorer: 'EXPLORER',
  targets: 'TARGETS',
  campaigns: 'CAMPAIGNS',
  coverage: 'COVERAGE',
  failures: 'FAILURES',
  findings: 'ISSUES',
  steering: 'STEERING',
};

// Views that hide the sidebar and take over the main content area
const FULL_WIDTH_VIEWS: ActivityView[] = ['graph', 'behavior'];

// Views that show content in the sidebar
const SIDEBAR_VIEWS: ActivityView[] = [
  'explorer', 'targets', 'campaigns', 'coverage', 'failures', 'findings', 'steering',
];

export default function Home() {
  // ---- project state ----
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [isProjectLoading, setIsProjectLoading] = useState(true);

  // ---- modals ----
  const [showSettings, setShowSettings] = useState(false);

  // ---- auth ----
  const { user, isAuthenticated, isLoading: isAuthLoading, logout, getAccessToken, refreshToken } = useAuth();

  // ---- layout ----
  const panels = usePanelLayout();
  const workspace = useProjectWorkspace({ currentProject });

  // ---- campaign state ----
  const campaignMgmt = useCampaignManagement({ projectId: currentProject?.id ?? null, isAuthenticated });
  const targetData = useTargets(campaignMgmt.selectedCampaignId);
  const laneData = useLanes(campaignMgmt.selectedCampaignId);
  const coverageData = useCoverage(campaignMgmt.selectedCampaignId);
  const artifactData = useArtifacts(campaignMgmt.selectedCampaignId);
  const issueData = useIssues(campaignMgmt.selectedCampaignId);
  const steeringData = useSteering(campaignMgmt.selectedCampaignId);
  const behaviorTree = useBehaviorTree({
    selectedAgentId: campaignMgmt.selectedCampaignId,
    isAuthenticated,
  });

  // ---- session ----
  const sessionMgmt = useSessionManagement({
    currentProjectId: currentProject?.id ?? null,
    isAuthenticated,
  });

  // ---- websocket ----
  const { isConnected } = useWebSocket({
    enabled: isAuthenticated,
    onBTNodeAdd: useCallback((agentId: string, node: any) => {
      if (agentId !== campaignMgmt.selectedCampaignId) return;
      behaviorTree.addNode(node);
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [campaignMgmt.selectedCampaignId, behaviorTree.addNode]),
    onBTNodeUpdate: useCallback((agentId: string, update: any) => {
      if (agentId !== campaignMgmt.selectedCampaignId) return;
      behaviorTree.updateNode(update);
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [campaignMgmt.selectedCampaignId, behaviorTree.updateNode]),
    onBTNodeBatch: useCallback((agentId: string, nodes: any[]) => {
      if (agentId !== campaignMgmt.selectedCampaignId) return;
      behaviorTree.addNodes(nodes);
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [campaignMgmt.selectedCampaignId, behaviorTree.addNodes]),
  });

  const projectLoadTokenRef = useRef(0);

  // ---- set up API auth ----
  useEffect(() => {
    setAuthFunctions(getAccessToken, refreshToken);
  }, [getAccessToken, refreshToken]);

  // ---- initialise project on mount ----
  useEffect(() => {
    if (isAuthLoading || !isAuthenticated) return;
    setIsProjectLoading(true);
    let cancelled = false;
    const init = async () => {
      try {
        const status = await projectsApi.getStatus();
        if (cancelled) return;
        if (status.current_project) {
          setCurrentProject(status.current_project);
          await loadProjectData(status.current_project);
        }
      } catch (err) {
        console.error('Failed to initialise:', err);
      } finally {
        if (!cancelled) setIsProjectLoading(false);
      }
    };
    init();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthLoading, isAuthenticated]);

  // ---- load project data ----
  const loadProjectData = async (project: Project) => {
    const loadToken = ++projectLoadTokenRef.current;
    // Load file tree (non-blocking).
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
      .catch((err) => console.error('Failed to load file tree:', err));
  };

  // ---- project enter / exit ----
  const handleProjectEnter = async (project: Project) => {
    setCurrentProject(project);
    workspace.clearFile();
    workspace.setFileTree(null);
    await loadProjectData(project);
  };

  const handleProjectExit = async () => {
    try { await projectsApi.exit(); } catch (err) { console.error('Failed to exit project:', err); }
    setCurrentProject(null);
    workspace.clearFile();
    workspace.setFileTree(null);
  };

  // ---- file selection ----
  const handleFileSelect = async (path: string) => {
    await workspace.selectFile(path);
  };

  // ---- session restore ----
  const handleRestoreSession = useCallback(async () => {
    await sessionMgmt.restoreSession({
      onFindingsRestore: () => { /* no-op: campaign model doesn't use findings array */ },
      onActiveViewRestore: (view: any) => panels.setActiveView(view),
      onSelectedFileRestore: (path: string) => workspace.setSelectedPath(path),
      onSelectedAgentRestore: (id: string) => campaignMgmt.setSelectedCampaignId(id),
    });
  }, [sessionMgmt, panels, workspace, campaignMgmt]);

  useEffect(() => {
    if (!sessionMgmt.snapshotInfo) return;
    handleRestoreSession();
  }, [sessionMgmt.snapshotInfo, handleRestoreSession]);

  const handleKeepCurrent = useCallback(async () => {
    await sessionMgmt.keepCurrentSession();
  }, [sessionMgmt]);

  // ---- derived ----
  const isFullWidthView = FULL_WIDTH_VIEWS.includes(panels.activeView);
  const showEditorArea = !isFullWidthView;

  // ---- loading / auth gates ----
  if (isAuthLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-bg-primary">
        <RefreshCw className="w-8 h-8 text-accent animate-spin" />
      </div>
    );
  }

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

  if (!currentProject) {
    return (
      <ProjectSelector
        onProjectEnter={handleProjectEnter}
        onProjectExit={handleProjectExit}
      />
    );
  }

  // =========================================================================
  // MAIN IDE LAYOUT
  // =========================================================================
  return (
    <div className="h-screen flex flex-col bg-bg-primary scanlines">
      {/* ---- HEADER ---- */}
      <header className="h-9 bg-bg-secondary flex items-center justify-between px-3 border-b border-border-subtle select-none">
        <div className="flex items-center gap-3">
          <span className="text-text-muted text-xs">quick_hack</span>
          <div className="flex items-center gap-2 text-text-primary">
            <FolderGit2 className="w-4 h-4 text-accent" />
            <span className="text-sm font-medium">{currentProject.name}</span>
            {currentProject.repo_name && (
              <span className="text-xs text-text-muted">({currentProject.repo_name})</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {isAuthenticated ? (
            <div className="flex items-center gap-4">
              <span className="text-gray-400">{user?.username}</span>
              <button onClick={logout} className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded">
                Logout
              </button>
            </div>
          ) : null}

          <SessionControls
            sessionStatus={sessionMgmt.sessionStatus}
            onStatusChange={sessionMgmt.setSessionStatus}
            hasRunningAgents={false}
            activeView={panels.activeView}
            selectedFile={workspace.selectedPath}
            openPanels={[
              panels.showSidebar ? 'sidebar' : '',
              panels.showPanel ? 'panel' : '',
              panels.showChat ? 'chat' : '',
            ].filter(Boolean)}
            selectedAgentId={campaignMgmt.selectedCampaignId}
            onPaused={() => console.log('Session paused')}
            onError={(err: string) => console.error('Session error:', err)}
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

      {/* ---- BODY ---- */}
      <div className="flex-1 flex overflow-hidden">
        {/* ==== ACTIVITY BAR ==== */}
        <aside className="w-12 bg-bg-secondary flex flex-col items-center py-1 border-r border-border-subtle">
          {/* Explorer */}
          <button
            onClick={() => { panels.setActiveView('explorer'); panels.setShowSidebar(true); }}
            className={`activity-icon ${panels.activeView === 'explorer' && panels.showSidebar ? 'active' : ''}`}
            title="Explorer"
          >
            <Files className="w-6 h-6" />
          </button>

          {/* Targets */}
          <button
            onClick={() => { panels.setActiveView('targets'); panels.setShowSidebar(true); }}
            className={`activity-icon ${panels.activeView === 'targets' && panels.showSidebar ? 'active' : ''}`}
            title="Targets"
          >
            <Crosshair className="w-6 h-6" />
            {targetData.targets.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-accent rounded-full" />
            )}
          </button>

          {/* Campaigns */}
          <button
            onClick={() => { panels.setActiveView('campaigns'); panels.setShowSidebar(true); }}
            className={`activity-icon ${panels.activeView === 'campaigns' && panels.showSidebar ? 'active' : ''}`}
            title="Campaigns"
          >
            <Rocket className="w-6 h-6" />
            {campaignMgmt.campaigns.some(c => c.status === 'running') && (
              <span className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-accent scan-indicator" />
            )}
          </button>

          {/* Coverage */}
          <button
            onClick={() => { panels.setActiveView('coverage'); panels.setShowSidebar(true); }}
            className={`activity-icon ${panels.activeView === 'coverage' && panels.showSidebar ? 'active' : ''}`}
            title="Coverage"
          >
            <BarChart3 className="w-6 h-6" />
          </button>

          {/* Failures */}
          <button
            onClick={() => { panels.setActiveView('failures'); panels.setShowSidebar(true); }}
            className={`activity-icon ${panels.activeView === 'failures' && panels.showSidebar ? 'active' : ''}`}
            title="Failures"
          >
            <AlertTriangle className="w-6 h-6" />
            {artifactData.artifacts.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-sev-critical rounded-full" />
            )}
          </button>

          {/* Issues (Findings) */}
          <button
            onClick={() => { panels.setActiveView('findings'); panels.setShowSidebar(true); }}
            className={`activity-icon ${panels.activeView === 'findings' ? 'active' : ''}`}
            title="Issues"
          >
            <Shield className="w-6 h-6" />
            {issueData.issues.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-sev-critical rounded-full" />
            )}
          </button>

          {/* Campaign Graph */}
          <button
            onClick={() => { panels.setActiveView('graph'); panels.setShowSidebar(false); }}
            className={`activity-icon ${panels.activeView === 'graph' ? 'active' : ''}`}
            title="Campaign Graph"
          >
            <Network className="w-6 h-6" />
          </button>

          {/* Steering */}
          <button
            onClick={() => { panels.setActiveView('steering'); panels.setShowSidebar(true); }}
            className={`activity-icon ${panels.activeView === 'steering' && panels.showSidebar ? 'active' : ''}`}
            title="Steering"
          >
            <Compass className="w-6 h-6" />
            {steeringData.decisions.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-accent rounded-full" />
            )}
          </button>

          {/* Behavior Tree */}
          <button
            onClick={() => { panels.setActiveView('behavior'); panels.setShowSidebar(false); }}
            className={`activity-icon ${panels.activeView === 'behavior' ? 'active' : ''}`}
            title="Behavior Tree"
          >
            <GitBranch className="w-6 h-6" />
            {behaviorTree.nodes.size > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-accent rounded-full" />
            )}
          </button>

          <div className="flex-1" />

          {/* Chat toggle */}
          <button
            onClick={panels.toggleChat}
            className={`activity-icon ${panels.showChat ? 'active' : ''}`}
            title="AI Chat"
          >
            <MessageSquare className="w-5 h-5" />
          </button>

          {/* Settings */}
          <button
            onClick={() => setShowSettings(true)}
            className="activity-icon"
            title="Settings"
          >
            <Settings className="w-5 h-5" />
          </button>
        </aside>

        {/* ==== SIDEBAR ==== */}
        {panels.showSidebar && SIDEBAR_VIEWS.includes(panels.activeView) && (
          <aside className="w-64 bg-bg-secondary flex flex-col border-r border-border-subtle">
            {/* Sidebar header */}
            <div className="panel-header">
              <span>{SIDEBAR_TITLES[panels.activeView] ?? panels.activeView.toUpperCase()}</span>
              <button onClick={() => panels.setShowSidebar(false)} className="btn-icon">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Sidebar content */}
            <div className="flex-1 overflow-hidden">
              {panels.activeView === 'explorer' && (
                <FileTree
                  tree={workspace.fileTree}
                  selectedPath={workspace.selectedPath}
                  onFileSelect={handleFileSelect}
                  onDirectoryExpand={workspace.expandDirectory}
                />
              )}

              {panels.activeView === 'targets' && (
                <TargetList targets={targetData.targets} isLoading={targetData.isLoading} />
              )}

              {panels.activeView === 'campaigns' && (
                <CampaignManager
                  campaigns={campaignMgmt.campaigns}
                  selectedCampaignId={campaignMgmt.selectedCampaignId}
                  onSelectCampaign={campaignMgmt.setSelectedCampaignId}
                  onCreateCampaign={campaignMgmt.createCampaign as any}
                  onStartCampaign={campaignMgmt.startCampaign as any}
                  onPauseCampaign={campaignMgmt.pauseCampaign as any}
                  onResumeCampaign={campaignMgmt.resumeCampaign as any}
                  onCancelCampaign={campaignMgmt.cancelCampaign as any}
                  repoId={currentProject.id}
                  lanes={laneData.lanes}
                />
              )}

              {panels.activeView === 'coverage' && (
                <CoveragePanel coverage={coverageData.coverage} isLoading={coverageData.isLoading} />
              )}

              {panels.activeView === 'failures' && (
                <FailuresPanel artifacts={artifactData.artifacts} buckets={artifactData.buckets} isLoading={artifactData.isLoading} />
              )}

              {panels.activeView === 'findings' && (
                <IssuesList issues={issueData.issues} isLoading={issueData.isLoading} />
              )}

              {panels.activeView === 'steering' && (
                <SteeringPanel decisions={steeringData.decisions} isLoading={steeringData.isLoading} />
              )}
            </div>
          </aside>
        )}

        {/* ==== MAIN CONTENT ==== */}
        <main className="flex-1 flex flex-col overflow-hidden bg-bg-primary">
          {/* ---- Campaign Graph (full width) ---- */}
          {panels.activeView === 'graph' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="h-10 bg-bg-secondary border-b border-border-subtle flex items-center px-3 gap-2">
                <Network className="w-4 h-4 text-text-muted" />
                <span className="text-sm text-text-muted">Campaign Graph</span>
                <select
                  value={campaignMgmt.selectedCampaignId || ''}
                  onChange={(e) => campaignMgmt.setSelectedCampaignId(e.target.value || null)}
                  className="ml-2 px-2 py-1 bg-bg-tertiary border border-border-default rounded text-sm"
                >
                  <option value="">Select campaign...</option>
                  {campaignMgmt.campaigns.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.preset} campaign ({c.status})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex-1">
                <CampaignGraph campaignId={campaignMgmt.selectedCampaignId} />
              </div>
            </div>
          )}

          {/* ---- Behavior Tree (full width) ---- */}
          {panels.activeView === 'behavior' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="h-10 bg-bg-secondary border-b border-border-subtle flex items-center px-3 gap-2">
                <GitBranch className="w-4 h-4 text-text-muted" />
                <span className="text-sm text-text-muted">Behavior Tree</span>
                <select
                  value={campaignMgmt.selectedCampaignId || ''}
                  onChange={(e) => campaignMgmt.setSelectedCampaignId(e.target.value || null)}
                  className="ml-2 px-2 py-1 bg-bg-tertiary border border-border-default rounded text-sm"
                >
                  <option value="">Select campaign...</option>
                  {campaignMgmt.campaigns.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.preset} campaign ({c.status})
                    </option>
                  ))}
                </select>
                <div className="ml-auto flex items-center gap-1">
                  <button
                    onClick={behaviorTree.expandAll}
                    className="px-2 py-0.5 text-xs bg-bg-tertiary border border-border-subtle rounded hover:bg-bg-primary text-text-muted"
                  >
                    Expand All
                  </button>
                  <button
                    onClick={behaviorTree.collapseAll}
                    className="px-2 py-0.5 text-xs bg-bg-tertiary border border-border-subtle rounded hover:bg-bg-primary text-text-muted"
                  >
                    Collapse All
                  </button>
                  <span className="text-[10px] text-text-muted ml-2">
                    {behaviorTree.nodes.size} nodes
                  </span>
                </div>
              </div>
              <div className="flex-1 flex overflow-hidden min-h-0">
                <BehaviorTree
                  nodes={behaviorTree.nodes}
                  childIndex={behaviorTree.childIndex}
                  rootId={behaviorTree.rootId}
                  expandedNodes={behaviorTree.expandedNodes}
                  selectedNodeId={behaviorTree.selectedNodeId}
                  isLoading={behaviorTree.isLoading}
                  onToggleExpand={behaviorTree.toggleExpand}
                  onSelectNode={behaviorTree.selectNode}
                  getChildren={behaviorTree.getChildren}
                />
                {behaviorTree.selectedNodeId && behaviorTree.nodes.get(behaviorTree.selectedNodeId) && (
                  <BTNodeDetail
                    node={behaviorTree.nodes.get(behaviorTree.selectedNodeId)!}
                    onClose={() => behaviorTree.selectNode(null)}
                  />
                )}
              </div>
            </div>
          )}

          {/* ---- Tab bar + Breadcrumb + Editor (when not in a full-width view) ---- */}
          {showEditorArea && workspace.currentFile && (
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

          {showEditorArea && workspace.currentFile && (
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

          {showEditorArea && (
            <div className="flex-1 overflow-hidden">
              <MonacoEditor
                file={workspace.currentFile}
                findings={[]}
              />
            </div>
          )}
        </main>
      </div>

      {/* ---- STATUS BAR ---- */}
      <footer className="h-6 bg-bg-primary border-t border-border-default flex items-center px-3 text-xs text-text-secondary select-none">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1" data-testid="ws-connection-status">
            <Circle className={`w-2 h-2 ${isConnected ? 'fill-status-confirmed text-status-confirmed' : 'fill-sev-critical text-sev-critical'}`} />
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
          {currentProject.repo_branch && (
            <span className="flex items-center gap-1">
              <GitBranch className="w-3 h-3" />
              {currentProject.repo_branch}
            </span>
          )}
        </div>

        <div className="flex-1" />

        <div className="flex items-center gap-3">
          {currentProject.file_count > 0 && (
            <span>{currentProject.file_count} files</span>
          )}
          {campaignMgmt.campaigns.filter(c => c.status === 'running').length > 0 && (
            <span className="flex items-center gap-1">
              <RefreshCw className="w-3 h-3 animate-spin" />
              {campaignMgmt.campaigns.filter(c => c.status === 'running').length} running
            </span>
          )}
          <span className="flex items-center gap-1">
            {issueData.issues.length} issues
          </span>
        </div>
      </footer>

      {/* ---- CHAT PANEL ---- */}
      <ChatPanel
        isOpen={panels.showChat}
        onToggle={panels.toggleChat}
        currentFile={workspace.currentFile}
        findings={[]}
        onRequestSettings={() => setShowSettings(true)}
      />

      {/* ---- SETTINGS MODAL ---- */}
      <SettingsModal
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
      />

      {/* ---- RESUME DIALOG ---- */}
      {sessionMgmt.showResumeDialog && sessionMgmt.snapshotInfo && (
        <ResumeDialog
          snapshotInfo={sessionMgmt.snapshotInfo}
          onRestore={handleRestoreSession}
          onKeepCurrent={handleKeepCurrent}
          onClose={() => sessionMgmt.setShowResumeDialog(false)}
        />
      )}
    </div>
  );
}
