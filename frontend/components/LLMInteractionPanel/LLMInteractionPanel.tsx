'use client';

import { useState, useEffect, useRef, useMemo, useCallback, memo } from 'react';
import type { LLMInteraction, ToolDetail } from '@/types';
import styles from './LLMInteractionPanel.module.css';

interface LLMInteractionPanelProps {
  agentId: string | null;
  interactions: LLMInteraction[];
  toolDetails: ToolDetail[];
  isConnected: boolean;
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatTokens(tokens: number | undefined): string {
  if (!tokens) return '-';
  if (tokens > 1000) return `${(tokens / 1000).toFixed(1)}k`;
  return String(tokens);
}

const InteractionEntry = memo(function InteractionEntry({
  interaction,
  isExpanded,
  onToggle,
}: {
  interaction: LLMInteraction;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const isRequest = interaction.interaction_type === 'request';
  const hasToolCalls = interaction.tool_calls && interaction.tool_calls.length > 0;

  return (
    <div className={`${styles.entry} ${isRequest ? styles.request : styles.response}`}>
      <div className={styles.entryHeader} onClick={onToggle}>
        <div className={styles.entryMeta}>
          <span className={`${styles.badge} ${isRequest ? styles.badgeRequest : styles.badgeResponse}`}>
            {isRequest ? 'REQ' : 'RES'}
          </span>
          {interaction.subagent && (
            <span className={styles.subagentBadge}>{interaction.subagent}</span>
          )}
          <span className={styles.timestamp}>{formatTimestamp(interaction.timestamp)}</span>
          {interaction.duration_ms && (
            <span className={styles.duration}>{interaction.duration_ms}ms</span>
          )}
          {interaction.total_tokens && (
            <span className={styles.tokens}>
              {formatTokens(interaction.total_tokens)} tokens
            </span>
          )}
          {hasToolCalls && (
            <span className={styles.toolBadge}>
              {interaction.tool_calls?.length} tool{interaction.tool_calls?.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        <span className={styles.expandIcon}>{isExpanded ? '[-]' : '[+]'}</span>
      </div>

      <div className={styles.summary}>{interaction.summary}</div>

      {isExpanded && (
        <div className={styles.expandedContent}>
          {interaction.model && (
            <div className={styles.modelInfo}>
              Model: {interaction.model} ({interaction.provider})
            </div>
          )}

          {interaction.prompt_tokens && (
            <div className={styles.tokenBreakdown}>
              Prompt: {formatTokens(interaction.prompt_tokens)} |
              Completion: {formatTokens(interaction.completion_tokens)} |
              Total: {formatTokens(interaction.total_tokens)}
            </div>
          )}

          {hasToolCalls && (
            <div className={styles.toolCalls}>
              <div className={styles.sectionTitle}>Tool Calls:</div>
              {interaction.tool_calls?.map((tc, i) => (
                <div key={i} className={styles.toolCall}>
                  <span className={styles.toolName}>
                    {(tc as any).function?.name || (tc as any).name || 'unknown'}
                  </span>
                </div>
              ))}
            </div>
          )}

          <div className={styles.fullContent}>
            <div className={styles.sectionTitle}>Full Content:</div>
            <pre className={styles.codeBlock}>{interaction.full_content}</pre>
          </div>
        </div>
      )}
    </div>
  );
});

const ToolDetailEntry = memo(function ToolDetailEntry({
  detail,
  isExpanded,
  onToggle,
}: {
  detail: ToolDetail;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className={`${styles.entry} ${styles.tool} ${detail.success ? '' : styles.toolError}`}>
      <div className={styles.entryHeader} onClick={onToggle}>
        <div className={styles.entryMeta}>
          <span className={`${styles.badge} ${styles.badgeTool}`}>TOOL</span>
          {detail.subagent && (
            <span className={styles.subagentBadge}>{detail.subagent}</span>
          )}
          <span className={styles.toolNameBadge}>{detail.tool_name}</span>
          <span className={styles.timestamp}>{formatTimestamp(detail.timestamp)}</span>
          <span className={styles.duration}>{detail.duration_ms}ms</span>
          {!detail.success && <span className={styles.errorBadge}>ERROR</span>}
        </div>
        <span className={styles.expandIcon}>{isExpanded ? '[-]' : '[+]'}</span>
      </div>

      <div className={styles.summary}>{detail.arguments_summary}</div>

      {isExpanded && (
        <div className={styles.expandedContent}>
          <div className={styles.section}>
            <div className={styles.sectionTitle}>Arguments:</div>
            <pre className={styles.codeBlock}>
              {JSON.stringify(detail.arguments, null, 2)}
            </pre>
          </div>

          <div className={styles.section}>
            <div className={styles.sectionTitle}>Result:</div>
            {detail.success ? (
              <pre className={styles.codeBlock}>
                {typeof detail.result === 'string'
                  ? detail.result
                  : JSON.stringify(detail.result, null, 2)}
              </pre>
            ) : (
              <div className={styles.errorMessage}>{detail.error_message}</div>
            )}
          </div>

          {detail.code_context && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>
                Code Context ({detail.code_context.file_path}):
              </div>
              <pre className={styles.codeBlock}>{detail.code_context.content}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
});

type EntryType =
  | { type: 'interaction'; data: LLMInteraction }
  | { type: 'tool'; data: ToolDetail };

function LLMInteractionPanelComponent({
  agentId,
  interactions,
  toolDetails,
  isConnected,
}: LLMInteractionPanelProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<'all' | 'llm' | 'tools'>('all');
  const [subagentFilter, setSubagentFilter] = useState<string | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  // Virtualization constants
  const ITEM_HEIGHT = 60; // Approximate height of each entry when collapsed
  const OVERSCAN = 5; // Number of items to render outside the visible area
  const VIRTUALIZATION_THRESHOLD = 100; // Only virtualize when there are this many entries

  // Memoize unique subagents from tool details and LLM interactions
  const subagents = useMemo(() => {
    const toolSubagents = toolDetails.map(t => t.subagent).filter(Boolean) as string[];
    const interactionSubagents = interactions.map(i => i.subagent).filter(Boolean) as string[];
    return Array.from(new Set([...toolSubagents, ...interactionSubagents]));
  }, [toolDetails, interactions]);
  const hasSubagents = subagents.length > 0;

  // Memoize combined and sorted entries by timestamp
  const allEntries = useMemo<EntryType[]>(() => {
    const entries: EntryType[] = [
      ...interactions.map(i => ({ type: 'interaction' as const, data: i })),
      ...toolDetails.map(t => ({ type: 'tool' as const, data: t })),
    ];
    // Sort by timestamp
    return entries.sort((a, b) =>
      new Date(a.data.timestamp).getTime() - new Date(b.data.timestamp).getTime()
    );
  }, [interactions, toolDetails]);

  // Memoize filtered entries
  const filteredEntries = useMemo(() => {
    return allEntries.filter(entry => {
      // Type filter
      if (filter === 'llm' && entry.type !== 'interaction') return false;
      if (filter === 'tools' && entry.type !== 'tool') return false;

      // Subagent filter (applies to both tools and LLM interactions)
      if (subagentFilter) {
        const entrySubagent = entry.data.subagent;
        if (entrySubagent !== subagentFilter) return false;
      }

      return true;
    });
  }, [allEntries, filter, subagentFilter]);

  // Auto-scroll to bottom when new entries arrive
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [filteredEntries.length, autoScroll]);

  // Track scroll position for virtualization
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, []);

  // Calculate virtualized items to render
  const virtualizedData = useMemo(() => {
    const shouldVirtualize = filteredEntries.length >= VIRTUALIZATION_THRESHOLD;

    if (!shouldVirtualize) {
      return {
        items: filteredEntries,
        startIndex: 0,
        paddingTop: 0,
        paddingBottom: 0,
        totalHeight: 0,
      };
    }

    const containerHeight = containerRef.current?.clientHeight || 600;
    const startIndex = Math.max(0, Math.floor(scrollTop / ITEM_HEIGHT) - OVERSCAN);
    const endIndex = Math.min(
      filteredEntries.length,
      Math.ceil((scrollTop + containerHeight) / ITEM_HEIGHT) + OVERSCAN
    );

    const items = filteredEntries.slice(startIndex, endIndex);
    const paddingTop = startIndex * ITEM_HEIGHT;
    const paddingBottom = (filteredEntries.length - endIndex) * ITEM_HEIGHT;
    const totalHeight = filteredEntries.length * ITEM_HEIGHT;

    return { items, startIndex, paddingTop, paddingBottom, totalHeight };
  }, [filteredEntries, scrollTop]);

  const toggleExpanded = useCallback((id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  // Memoize stats calculations
  const { totalTokens, llmCalls, toolCalls } = useMemo(() => {
    const totalTokens = interactions.reduce(
      (sum, i) => sum + (i.total_tokens || 0),
      0
    );
    const llmCalls = interactions.filter(i => i.interaction_type === 'response').length;
    const toolCalls = toolDetails.length;
    return { totalTokens, llmCalls, toolCalls };
  }, [interactions, toolDetails]);

  if (!agentId) {
    return (
      <div className={styles.panel}>
        <div className={styles.header}>
          <h3>LLM Interactions</h3>
        </div>
        <div className={styles.empty}>Select an agent to view interactions</div>
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <h3>LLM Interactions</h3>
        <div className={styles.stats}>
          <span className={styles.stat}>
            <span className={styles.statValue}>{llmCalls}</span> LLM calls
          </span>
          <span className={styles.stat}>
            <span className={styles.statValue}>{toolCalls}</span> tools
          </span>
          <span className={styles.stat}>
            <span className={styles.statValue}>{formatTokens(totalTokens)}</span> tokens
          </span>
          <span className={`${styles.connectionStatus} ${isConnected ? styles.connected : ''}`}>
            {isConnected ? 'Live' : 'Disconnected'}
          </span>
        </div>
      </div>

      <div className={styles.toolbar}>
        <div className={styles.filterGroup}>
          <button
            className={`${styles.filterBtn} ${filter === 'all' ? styles.active : ''}`}
            onClick={() => setFilter('all')}
          >
            All
          </button>
          <button
            className={`${styles.filterBtn} ${filter === 'llm' ? styles.active : ''}`}
            onClick={() => setFilter('llm')}
          >
            LLM
          </button>
          <button
            className={`${styles.filterBtn} ${filter === 'tools' ? styles.active : ''}`}
            onClick={() => setFilter('tools')}
          >
            Tools
          </button>
        </div>
        {hasSubagents && (
          <div className={styles.filterGroup}>
            <button
              className={`${styles.filterBtn} ${subagentFilter === null ? styles.active : ''}`}
              onClick={() => setSubagentFilter(null)}
            >
              All Agents
            </button>
            {subagents.map(sa => (
              <button
                key={sa}
                className={`${styles.filterBtn} ${subagentFilter === sa ? styles.active : ''}`}
                onClick={() => setSubagentFilter(sa)}
              >
                {sa}
              </button>
            ))}
          </div>
        )}
        <label className={styles.autoScrollLabel}>
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
          />
          Auto-scroll
        </label>
      </div>

      <div className={styles.entries} ref={containerRef} onScroll={handleScroll}>
        {filteredEntries.length === 0 ? (
          <div className={styles.empty}>
            {filter === 'all'
              ? 'No interactions yet. Start an agent to see LLM activity.'
              : `No ${filter === 'llm' ? 'LLM' : 'tool'} entries.`}
          </div>
        ) : (
          <>
            {/* Virtualization spacer - top */}
            {virtualizedData.paddingTop > 0 && (
              <div style={{ height: virtualizedData.paddingTop }} />
            )}
            {virtualizedData.items.map((entry) => {
              if (entry.type === 'interaction') {
                return (
                  <InteractionEntry
                    key={entry.data.id}
                    interaction={entry.data}
                    isExpanded={expandedIds.has(entry.data.id)}
                    onToggle={() => toggleExpanded(entry.data.id)}
                  />
                );
              } else {
                return (
                  <ToolDetailEntry
                    key={entry.data.id}
                    detail={entry.data}
                    isExpanded={expandedIds.has(entry.data.id)}
                    onToggle={() => toggleExpanded(entry.data.id)}
                  />
                );
              }
            })}
            {/* Virtualization spacer - bottom */}
            {virtualizedData.paddingBottom > 0 && (
              <div style={{ height: virtualizedData.paddingBottom }} />
            )}
          </>
        )}
      </div>
    </div>
  );
}

// Wrap the component with React.memo for performance optimization
const LLMInteractionPanel = memo(LLMInteractionPanelComponent);
LLMInteractionPanel.displayName = 'LLMInteractionPanel';

export default LLMInteractionPanel;
