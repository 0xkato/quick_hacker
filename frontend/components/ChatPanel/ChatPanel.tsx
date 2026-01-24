'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import {
  MessageSquare,
  Send,
  X,
  Bot,
  User,
  Loader2,
  Code,
  FileCode,
  AlertTriangle,
  Trash2,
  Settings2,
  Network,
} from 'lucide-react';
import { chat, type ChatMessage, type ChatContext } from '@/lib/api';
import type { FileContent, Finding } from '@/types';

interface ChatPanelProps {
  isOpen: boolean;
  onToggle: () => void;
  currentFile: FileContent | null;
  findings: Finding[];
  onRequestSettings: () => void;
  provider?: string;
  model?: string;
  flowContextPack?: unknown;
  seedMessage?: { id: string; text: string } | null;
  onClearFlowContext?: () => void;
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export function ChatPanel({
  isOpen,
  onToggle,
  currentFile,
  findings,
  onRequestSettings,
  provider,
  model,
  flowContextPack,
  seedMessage,
  onClearFlowContext,
}: ChatPanelProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [selectedText, setSelectedText] = useState<string | null>(null);
  const [width, setWidth] = useState(400);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const resizeRef = useRef<HTMLDivElement>(null);
  const lastSeedIdRef = useRef<string | null>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      inputRef.current?.focus();
    }
  }, [isOpen]);

  // Apply externally-seeded input (best-effort)
  useEffect(() => {
    if (!seedMessage) return;
    if (typeof seedMessage.id !== 'string' || !seedMessage.id) return;
    if (lastSeedIdRef.current === seedMessage.id) return;
    if (typeof seedMessage.text !== 'string' || !seedMessage.text.trim()) return;
    setInput(seedMessage.text);
    lastSeedIdRef.current = seedMessage.id;
    inputRef.current?.focus();
  }, [seedMessage]);

  // Resizable panel
  useEffect(() => {
    const resizeHandle = resizeRef.current;
    if (!resizeHandle) return;

    let startX: number;
    let startWidth: number;

    const onMouseDown = (e: MouseEvent) => {
      startX = e.clientX;
      startWidth = width;
      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
      document.body.style.cursor = 'ew-resize';
      document.body.style.userSelect = 'none';
    };

    const onMouseMove = (e: MouseEvent) => {
      const diff = e.clientX - startX;
      const newWidth = Math.min(Math.max(startWidth + diff, 300), 800);
      setWidth(newWidth);
    };

    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    resizeHandle.addEventListener('mousedown', onMouseDown);
    return () => resizeHandle.removeEventListener('mousedown', onMouseDown);
  }, [width]);

  // Build context for chat
  const buildContext = useCallback((): ChatContext => {
    const ctx: ChatContext = {};

    if (currentFile) {
      ctx.current_file = currentFile.path;
      ctx.file_content = currentFile.content;
    }

    if (findings.length > 0) {
      ctx.findings = currentFile
        ? findings.filter((f) => f.file_path === currentFile.path)
        : findings.slice(0, 10);
    }

    if (selectedText) {
      ctx.selected_text = selectedText;
    }

    if (flowContextPack) {
      ctx.flow_context_pack = flowContextPack;
    }

    return ctx;
  }, [currentFile, findings, selectedText, flowContextPack]);

  // Send message
  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    // Prepare chat messages for API
    const chatMessages: ChatMessage[] = messages.map((m) => ({
      role: m.role,
      content: m.content,
    }));
    chatMessages.push({ role: 'user', content: userMessage.content });

    const assistantMessage: Message = {
      id: (Date.now() + 1).toString(),
      role: 'assistant',
      content: '',
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, assistantMessage]);

    try {
      const context = buildContext();

      // Stream response
      for await (const chunk of chat.stream(chatMessages, context, provider, model)) {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMessage.id
              ? { ...m, content: m.content + chunk }
              : m
          )
        );
      }
    } catch (error) {
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantMessage.id
            ? { ...m, content: `Error: ${error instanceof Error ? error.message : 'Failed to get response'}` }
            : m
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Quick prompts
  const quickPrompts = [
    { icon: Code, label: 'Explain code', prompt: 'Explain what this code does' },
    { icon: AlertTriangle, label: 'Find vulns', prompt: 'Analyze this code for security vulnerabilities' },
    { icon: FileCode, label: 'Review', prompt: 'Review this code for best practices and potential issues' },
  ];

  const handleQuickPrompt = (prompt: string) => {
    setInput(prompt);
    inputRef.current?.focus();
  };

  const clearChat = () => {
    setMessages([]);
  };

  return (
    <>
      {/* Toggle button when closed */}
      {!isOpen && (
        <button
          onClick={onToggle}
          className="fixed left-0 top-1/2 -translate-y-1/2 z-50 bg-vsc-sidebar border border-vsc-border-subtle border-l-0 rounded-r-lg p-2 hover:bg-vsc-hover transition-colors"
          title="Open Chat"
        >
          <MessageSquare className="w-5 h-5 text-vsc-text" />
        </button>
      )}

      {/* Chat panel */}
      <div
        className={`fixed left-0 top-8 bottom-6 z-40 bg-vsc-sidebar border-r border-vsc-border-subtle flex flex-col transition-transform duration-200 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        style={{ width: `${width}px` }}
      >
        {/* Resize handle */}
        <div
          ref={resizeRef}
          className="absolute right-0 top-0 bottom-0 w-1 cursor-ew-resize hover:bg-vsc-focus z-10"
        />

        {/* Header */}
        <div className="panel-header flex-shrink-0">
          <div className="flex items-center gap-2">
            <Bot className="w-4 h-4" />
            <span>AI Assistant</span>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={clearChat}
              className="btn-icon"
              title="Clear chat"
            >
              <Trash2 className="w-4 h-4" />
            </button>
            <button
              onClick={onRequestSettings}
              className="btn-icon"
              title="Settings"
            >
              <Settings2 className="w-4 h-4" />
            </button>
            <button onClick={onToggle} className="btn-icon" title="Close">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Context indicator */}
        {currentFile && (
          <div className="px-3 py-1.5 bg-vsc-bg border-b border-vsc-border-subtle text-vsc-xs text-vsc-text-muted flex items-center gap-2">
            <FileCode className="w-3 h-3" />
            <span className="truncate">{currentFile.path}</span>
            {findings.filter((f) => f.file_path === currentFile.path).length > 0 && (
              <span className="text-sev-medium">
                ({findings.filter((f) => f.file_path === currentFile.path).length} findings)
              </span>
            )}
          </div>
        )}

        {/* Flow context indicator */}
        {flowContextPack != null && (
          <div className="px-3 py-1.5 bg-vsc-bg border-b border-vsc-border-subtle text-vsc-xs text-vsc-text-muted flex items-center gap-2">
            <Network className="w-3 h-3" />
            <span className="truncate">
              Flow context:{' '}
              {typeof (flowContextPack as any)?.selected_node?.label === 'string'
                ? (flowContextPack as any).selected_node.label
                : 'selected node'}
            </span>
            {onClearFlowContext && (
              <button
                type="button"
                onClick={onClearFlowContext}
                className="ml-auto px-2 py-0.5 rounded bg-vsc-border/40 hover:bg-vsc-border/60 text-vsc-text-muted hover:text-vsc-text"
                title="Clear flow context"
              >
                Clear
              </button>
            )}
          </div>
        )}

        {/* Messages */}
        <div className="flex-1 overflow-auto p-3 space-y-4">
          {messages.length === 0 ? (
            <div className="text-center text-vsc-text-muted py-8">
              <Bot className="w-12 h-12 mx-auto mb-3 opacity-50" />
              {currentFile ? (
                <>
                  <p className="mb-4">Analyze the current file for security issues.</p>
                  <div className="flex flex-wrap gap-2 justify-center">
                    {quickPrompts.map(({ icon: Icon, label, prompt }) => (
                      <button
                        key={label}
                        onClick={() => handleQuickPrompt(prompt)}
                        className="btn btn-secondary btn-sm flex items-center gap-1"
                      >
                        <Icon className="w-3 h-3" />
                        {label}
                      </button>
                    ))}
                  </div>
                </>
              ) : (
                <>
                  <p className="mb-2">Select a file from the explorer to analyze.</p>
                  <p className="text-vsc-xs">Or ask general security questions.</p>
                </>
              )}
            </div>
          ) : (
            messages.map((message) => (
              <div
                key={message.id}
                className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : ''}`}
              >
                {message.role === 'assistant' && (
                  <div className="w-7 h-7 rounded-full bg-vsc-focus flex items-center justify-center flex-shrink-0">
                    <Bot className="w-4 h-4" />
                  </div>
                )}
                <div
                  className={`max-w-[85%] rounded-lg px-3 py-2 ${
                    message.role === 'user'
                      ? 'bg-vsc-focus text-vsc-text'
                      : 'bg-vsc-bg text-vsc-text'
                  }`}
                >
                  <div className="prose prose-invert prose-sm max-w-none">
                    {message.content.split('\n').map((line, i) => (
                      <p key={i} className="mb-1 last:mb-0">
                        {line || '\u00A0'}
                      </p>
                    ))}
                    {message.role === 'assistant' && isLoading && message.id === messages[messages.length - 1]?.id && (
                      <span className="inline-block w-2 h-4 bg-vsc-text animate-pulse ml-1" />
                    )}
                  </div>
                </div>
                {message.role === 'user' && (
                  <div className="w-7 h-7 rounded-full bg-vsc-success/20 flex items-center justify-center flex-shrink-0">
                    <User className="w-4 h-4 text-vsc-success" />
                  </div>
                )}
              </div>
            ))
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-3 border-t border-vsc-border-subtle">
          <div className="flex gap-2">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              placeholder="Ask about security, code review..."
              className="input flex-1 resize-none min-h-[60px] max-h-[120px]"
              rows={2}
              disabled={isLoading}
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || isLoading}
              className="btn btn-primary self-end"
            >
              {isLoading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
