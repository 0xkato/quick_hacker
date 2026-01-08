'use client';

import { useRef, useEffect } from 'react';
import Editor, { OnMount } from '@monaco-editor/react';
import type { editor } from 'monaco-editor';
import { FileCode } from 'lucide-react';
import type { FileContent, Finding } from '@/types';

interface MonacoEditorProps {
  file: FileContent | null;
  findings?: Finding[];
  onLineClick?: (lineNumber: number) => void;
}

export function MonacoEditor({ file, findings = [], onLineClick }: MonacoEditorProps) {
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);
  const decorationsRef = useRef<string[]>([]);

  const handleEditorMount: OnMount = (editor, monaco) => {
    editorRef.current = editor;

    // Configure editor with VSCode-like settings
    editor.updateOptions({
      readOnly: true,
      minimap: { enabled: true, scale: 1 },
      scrollBeyondLastLine: false,
      fontSize: 13,
      fontFamily: 'Menlo, Monaco, Consolas, monospace',
      lineNumbers: 'on',
      renderLineHighlight: 'line',
      wordWrap: 'on',
      smoothScrolling: true,
      cursorBlinking: 'smooth',
      cursorSmoothCaretAnimation: 'on',
      padding: { top: 8 },
      scrollbar: {
        verticalScrollbarSize: 14,
        horizontalScrollbarSize: 14,
        useShadows: false,
      },
    });

    // Line click handler
    editor.onMouseDown((e) => {
      if (e.target.position && onLineClick) {
        onLineClick(e.target.position.lineNumber);
      }
    });

    // Define VSCode Dark+ compatible theme
    monaco.editor.defineTheme('vscode-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'comment', foreground: '6A9955' },
        { token: 'keyword', foreground: '569CD6' },
        { token: 'string', foreground: 'CE9178' },
        { token: 'number', foreground: 'B5CEA8' },
        { token: 'type', foreground: '4EC9B0' },
        { token: 'function', foreground: 'DCDCAA' },
        { token: 'variable', foreground: '9CDCFE' },
        { token: 'constant', foreground: '4FC1FF' },
      ],
      colors: {
        'editor.background': '#1e1e1e',
        'editor.foreground': '#d4d4d4',
        'editor.lineHighlightBackground': '#2a2d2e',
        'editor.selectionBackground': '#264f78',
        'editorLineNumber.foreground': '#858585',
        'editorLineNumber.activeForeground': '#c6c6c6',
        'editorGutter.background': '#1e1e1e',
        'editorCursor.foreground': '#aeafad',
        'editor.inactiveSelectionBackground': '#3a3d41',
        'editorIndentGuide.background': '#404040',
        'editorIndentGuide.activeBackground': '#707070',
        'editorWhitespace.foreground': '#3b3b3b',
        'scrollbar.shadow': '#000000',
        'scrollbarSlider.background': 'rgba(121, 121, 121, 0.4)',
        'scrollbarSlider.hoverBackground': 'rgba(100, 100, 100, 0.7)',
        'scrollbarSlider.activeBackground': 'rgba(191, 191, 191, 0.4)',
        'minimap.background': '#1e1e1e',
      },
    });

    monaco.editor.setTheme('vscode-dark');
  };

  // Update decorations when findings change
  useEffect(() => {
    if (!editorRef.current || !file) return;

    const monaco = (window as unknown as { monaco: typeof import('monaco-editor') }).monaco;
    if (!monaco) return;

    // Filter findings for current file
    const fileFindings = findings.filter((f) => f.file_path === file.path);

    // Create decorations for findings
    const decorations: editor.IModelDeltaDecoration[] = fileFindings.map((finding) => {
      const severityColors: Record<string, string> = {
        critical: 'rgba(241, 76, 76, 0.25)',
        high: 'rgba(204, 167, 0, 0.25)',
        medium: 'rgba(233, 167, 0, 0.2)',
        low: 'rgba(55, 148, 255, 0.15)',
        info: 'rgba(117, 190, 255, 0.1)',
      };

      const glyphColors: Record<string, string> = {
        critical: '#f14c4c',
        high: '#cca700',
        medium: '#e9a700',
        low: '#3794ff',
        info: '#75beff',
      };

      return {
        range: new monaco.Range(
          finding.line_start,
          1,
          finding.line_end || finding.line_start,
          1
        ),
        options: {
          isWholeLine: true,
          className: `finding-decoration-${finding.severity}`,
          linesDecorationsClassName: `finding-glyph-${finding.severity}`,
          hoverMessage: {
            value: `**${finding.severity.toUpperCase()}**: ${finding.title}\n\n${finding.description}`,
          },
          overviewRuler: {
            color: glyphColors[finding.severity] || '#858585',
            position: monaco.editor.OverviewRulerLane.Right,
          },
          minimap: {
            color: severityColors[finding.severity] || '#858585',
            position: monaco.editor.MinimapPosition.Inline,
          },
        },
      };
    });

    // Apply decorations
    decorationsRef.current = editorRef.current.deltaDecorations(
      decorationsRef.current,
      decorations
    );
  }, [file, findings]);

  if (!file) {
    return (
      <div className="flex items-center justify-center h-full bg-vsc-bg">
        <div className="empty-state">
          <FileCode className="empty-state-icon" />
          <p className="text-vsc-base text-vsc-text-muted">No file selected</p>
          <p className="text-vsc-sm text-vsc-text-muted mt-1">
            Select a file from the explorer to view its contents
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-vsc-bg">
      <Editor
        height="100%"
        language={file.language || 'plaintext'}
        value={file.content}
        theme="vs-dark"
        onMount={handleEditorMount}
        loading={
          <div className="flex items-center justify-center h-full bg-vsc-bg">
            <span className="text-vsc-text-muted text-vsc-sm">Loading editor...</span>
          </div>
        }
        options={{
          readOnly: true,
          minimap: { enabled: true },
          scrollBeyondLastLine: false,
          fontSize: 13,
          fontFamily: 'Menlo, Monaco, Consolas, monospace',
        }}
      />
    </div>
  );
}
