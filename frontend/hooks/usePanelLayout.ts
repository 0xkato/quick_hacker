'use client';

import { useState, useCallback } from 'react';

export type ActivityView = 'explorer' | 'search' | 'agents' | 'findings' | 'flow' | 'llm';

export interface UsePanelLayoutResult {
  activeView: ActivityView;
  showSidebar: boolean;
  showPanel: boolean;
  showChat: boolean;
  setActiveView: (view: ActivityView) => void;
  setShowSidebar: (show: boolean) => void;
  setShowPanel: (show: boolean) => void;
  setShowChat: (show: boolean) => void;
  toggleChat: () => void;
}

export function usePanelLayout(): UsePanelLayoutResult {
  const [activeView, setActiveView] = useState<ActivityView>('explorer');
  const [showSidebar, setShowSidebar] = useState(true);
  const [showPanel, setShowPanel] = useState(true);
  const [showChat, setShowChat] = useState(false);

  const toggleChat = useCallback(() => {
    setShowChat(prev => !prev);
  }, []);

  return {
    activeView,
    showSidebar,
    showPanel,
    showChat,
    setActiveView,
    setShowSidebar,
    setShowPanel,
    setShowChat,
    toggleChat,
  };
}
