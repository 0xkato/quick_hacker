# UI Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform the security tool UI from VSCode-inspired to a futuristic-retro terminal aesthetic with improved severity visibility.

**Architecture:** Update Tailwind config and globals.css to establish new design tokens, then update components incrementally. Font loaded via Google Fonts. Styling changes only - no logic changes.

**Tech Stack:** Next.js, React, Tailwind CSS, Google Fonts (JetBrains Mono)

---

### Task 1: Add JetBrains Mono Font

**Files:**
- Modify: `frontend/app/layout.tsx`

**Step 1: Update layout.tsx to import JetBrains Mono from Google Fonts**

```tsx
import type { Metadata } from 'next';
import { JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { AuthProvider } from '../contexts/AuthContext';

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'quick_hack - Security Auditing IDE',
  description: 'AI-powered security code auditing in your browser',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={jetbrainsMono.variable}>
      <body className="antialiased font-mono">
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

**Step 2: Verify build succeeds**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes without errors

**Step 3: Commit**

```bash
git add frontend/app/layout.tsx
git commit -m "feat(ui): add JetBrains Mono font via Google Fonts"
```

---

### Task 2: Update Tailwind Config with New Color Palette

**Files:**
- Modify: `frontend/tailwind.config.ts`

**Step 1: Replace entire tailwind.config.ts with new design system**

```typescript
import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // New futuristic dark theme
        'bg-primary': '#0a0c10',
        'bg-secondary': '#12151c',
        'bg-tertiary': '#1a1e28',
        'bg-elevated': '#222833',

        // Borders
        'border-default': '#2a3040',
        'border-subtle': '#1e2430',
        'border-accent': '#3a4560',

        // Text
        'text-primary': '#e4e6eb',
        'text-secondary': '#8892a0',
        'text-muted': '#5a6270',
        'text-disabled': '#4a5568',

        // Accent (interactive)
        'accent': '#60a5fa',
        'accent-hover': '#7db8fc',

        // Severity colors (5 levels)
        'sev-critical': '#ff5f5f',
        'sev-high': '#f0b429',
        'sev-medium': '#f59e0b',
        'sev-low': '#60a5fa',
        'sev-info': '#94a3b8',

        // Validation status (4 states)
        'status-confirmed': '#4ade80',
        'status-needs-review': '#fbbf24',
        'status-rejected': '#f87171',
        'status-unprocessed': '#e4e6eb',

        // Diagram node colors
        'node-finding': '#ff5f5f',
        'node-sink': '#fbbf24',
        'node-touched': '#60a5fa',
        'node-normal': '#4ade80',

        // Legacy mappings (for compatibility during migration)
        'vsc-bg': '#0a0c10',
        'vsc-sidebar': '#12151c',
        'vsc-activitybar': '#0d0f14',
        'vsc-panel': '#12151c',
        'vsc-input': '#1a1e28',
        'vsc-dropdown': '#1a1e28',
        'vsc-border': '#2a3040',
        'vsc-border-subtle': '#1e2430',
        'vsc-text': '#e4e6eb',
        'vsc-text-muted': '#8892a0',
        'vsc-text-link': '#60a5fa',
        'vsc-accent': '#60a5fa',
        'vsc-accent-hover': '#7db8fc',
        'vsc-selection': '#2a3a50',
        'vsc-hover': '#1a2030',
        'vsc-active': '#222833',
        'vsc-focus': '#60a5fa',
        'vsc-tab-active': '#0a0c10',
        'vsc-tab-inactive': '#12151c',
        'vsc-tab-border': '#0a0c10',
        'vsc-statusbar': '#0d1117',
        'vsc-statusbar-debug': '#cc6633',
        'vsc-git-added': '#4ade80',
        'vsc-git-modified': '#fbbf24',
        'vsc-git-deleted': '#ff5f5f',
        'vsc-error': '#ff5f5f',
        'vsc-warning': '#f0b429',
        'vsc-success': '#4ade80',
      },
      fontFamily: {
        mono: ['var(--font-mono)', 'JetBrains Mono', 'Fira Code', 'SF Mono', 'Consolas', 'monospace'],
      },
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1rem' }],
        'sm': ['0.8125rem', { lineHeight: '1.25rem' }],
        'base': ['0.875rem', { lineHeight: '1.5rem' }],
        'lg': ['1rem', { lineHeight: '1.75rem' }],
        'xl': ['1.25rem', { lineHeight: '1.75rem' }],
        '2xl': ['1.5rem', { lineHeight: '2rem' }],
      },
      spacing: {
        'activity': '48px',
        'sidebar': '250px',
        'panel': '320px',
      },
      boxShadow: {
        'glow-critical': '0 0 12px rgba(255, 95, 95, 0.4)',
        'glow-high': '0 0 12px rgba(240, 180, 41, 0.4)',
        'glow-success': '0 0 10px rgba(74, 222, 128, 0.3)',
        'glow-accent': '0 0 10px rgba(96, 165, 250, 0.3)',
        'dropdown': '0 4px 12px rgba(0, 0, 0, 0.5)',
        'elevated': '0 8px 24px rgba(0, 0, 0, 0.4)',
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite',
      },
      keyframes: {
        glow: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.7' },
        },
      },
      borderRadius: {
        'sm': '4px',
        'md': '6px',
        'lg': '8px',
      },
    },
  },
  plugins: [],
};

export default config;
```

**Step 2: Verify build succeeds**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes (may have warnings about unused classes - that's fine)

**Step 3: Commit**

```bash
git add frontend/tailwind.config.ts
git commit -m "feat(ui): update Tailwind config with futuristic dark theme colors"
```

---

### Task 3: Update Global CSS with New Design Tokens and Typography

**Files:**
- Modify: `frontend/app/globals.css`

**Step 1: Replace globals.css with new design system**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Futuristic Dark Theme Variables */
:root {
  /* Base colors */
  --bg-primary: #0a0c10;
  --bg-secondary: #12151c;
  --bg-tertiary: #1a1e28;
  --bg-elevated: #222833;

  /* Borders */
  --border-default: #2a3040;
  --border-subtle: #1e2430;
  --border-accent: #3a4560;

  /* Text */
  --text-primary: #e4e6eb;
  --text-secondary: #8892a0;
  --text-muted: #5a6270;

  /* Accent */
  --accent: #60a5fa;
  --accent-hover: #7db8fc;

  /* Severity */
  --sev-critical: #ff5f5f;
  --sev-high: #f0b429;
  --sev-medium: #f59e0b;
  --sev-low: #60a5fa;
  --sev-info: #94a3b8;

  /* Validation Status */
  --status-confirmed: #4ade80;
  --status-needs-review: #fbbf24;
  --status-rejected: #f87171;
  --status-unprocessed: #e4e6eb;

  /* Node colors */
  --node-finding: #ff5f5f;
  --node-sink: #fbbf24;
  --node-touched: #60a5fa;
  --node-normal: #4ade80;

  /* Legacy compatibility */
  --vsc-bg: #0a0c10;
  --vsc-sidebar: #12151c;
  --vsc-activitybar: #0d0f14;
  --vsc-input: #1a1e28;
  --vsc-border: #2a3040;
  --vsc-border-subtle: #1e2430;
  --vsc-text: #e4e6eb;
  --vsc-text-muted: #8892a0;
  --vsc-accent: #60a5fa;
  --vsc-hover: #1a2030;
  --vsc-selection: #2a3a50;
  --vsc-statusbar: #0d1117;

  /* Design tokens */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;

  --shadow-card: inset 0 1px 0 rgba(255, 255, 255, 0.02);
  --shadow-elevated: 0 8px 24px rgba(0, 0, 0, 0.4);

  --transition-default: all 150ms ease-out;

  --bg-card: #12151c;
  --bg-hover-soft: rgba(42, 48, 64, 0.6);
}

/* Terminal scanlines overlay (subtle) */
.scanlines::after {
  content: '';
  position: fixed;
  inset: 0;
  pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.015) 2px,
    rgba(0, 0, 0, 0.015) 4px
  );
  z-index: 9999;
}

/* Scan indicator animation */
@keyframes scan-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}

.scan-indicator {
  animation: scan-pulse 2s ease-in-out infinite;
}

.scan-indicator-paused {
  opacity: 0.7;
}

/* Base typography */
html {
  font-size: 14px;
}

body {
  background-color: var(--bg-primary);
  color: var(--text-primary);
  font-family: var(--font-mono), 'JetBrains Mono', 'Fira Code', monospace;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  letter-spacing: 0.01em;
}

/* Terminal-style scrollbar */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: var(--bg-primary);
}

::-webkit-scrollbar-thumb {
  background: var(--border-default);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: var(--border-accent);
}

::-webkit-scrollbar-corner {
  background: transparent;
}

/* Selection */
::selection {
  background: var(--vsc-selection);
}

/* Terminal-style labels */
.terminal-label {
  @apply text-xs font-medium uppercase tracking-widest text-text-secondary;
}

/* File tree styles */
.file-tree-item {
  @apply flex items-center gap-1.5 py-1 cursor-pointer text-sm font-mono;
  padding-left: 12px;
  padding-right: 12px;
  margin: 2px 4px;
  border-radius: var(--radius-sm);
  transition: var(--transition-default);
  color: var(--text-secondary);
}

.file-tree-item:hover {
  background: var(--bg-hover-soft);
  color: var(--text-primary);
}

.file-tree-item.selected {
  background: var(--vsc-selection);
  border-left: 3px solid var(--accent);
  padding-left: 9px;
  color: var(--text-primary);
}

/* Severity badges - bold, glowing */
.severity-badge {
  @apply inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide;
}

.severity-badge.critical {
  background: var(--sev-critical);
  color: #0a0c10;
  box-shadow: 0 0 12px rgba(255, 95, 95, 0.4);
}

.severity-badge.high {
  background: var(--sev-high);
  color: #0a0c10;
  box-shadow: 0 0 12px rgba(240, 180, 41, 0.4);
}

.severity-badge.medium {
  background: var(--sev-medium);
  color: #0a0c10;
  box-shadow: 0 0 10px rgba(245, 158, 11, 0.3);
}

.severity-badge.low {
  background: rgba(96, 165, 250, 0.2);
  color: var(--sev-low);
  border: 1px solid var(--sev-low);
}

.severity-badge.info {
  background: rgba(148, 163, 184, 0.15);
  color: var(--sev-info);
  border: 1px solid var(--sev-info);
}

/* Critical/High pulse on hover */
.severity-badge.critical:hover,
.severity-badge.high:hover {
  animation: glow 1.5s ease-in-out infinite;
}

@keyframes glow {
  0%, 100% { filter: brightness(1); }
  50% { filter: brightness(1.1); }
}

/* Validation status badges */
.validation-status {
  @apply inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium;
}

.validation-status.confirmed {
  color: var(--status-confirmed);
}

.validation-status.needs-review {
  color: var(--status-needs-review);
}

.validation-status.rejected {
  color: var(--status-rejected);
}

.validation-status.unprocessed {
  color: var(--status-unprocessed);
  border: 1px solid var(--border-default);
}

/* Agent status badges */
.agent-status {
  @apply inline-flex items-center px-2 py-0.5 rounded text-xs font-medium;
}

.agent-status.running {
  @apply bg-status-confirmed/20 text-status-confirmed;
}

.agent-status.pending {
  @apply bg-status-needs-review/20 text-status-needs-review;
}

.agent-status.paused {
  @apply bg-accent/20 text-accent;
}

.agent-status.completed {
  @apply bg-text-muted/20 text-text-secondary;
}

.agent-status.failed {
  @apply bg-status-rejected/20 text-status-rejected;
}

.agent-status.cancelled {
  @apply bg-border-default/40 text-text-muted;
}

/* Buttons */
.btn {
  @apply inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded text-sm font-medium transition-all;
  @apply disabled:opacity-50 disabled:cursor-not-allowed;
  font-family: inherit;
}

.btn-primary {
  @apply bg-accent hover:bg-accent-hover text-bg-primary;
}

.btn-secondary {
  @apply bg-bg-tertiary hover:bg-bg-elevated text-text-primary border border-border-default;
}

.btn-ghost {
  @apply bg-transparent hover:bg-bg-tertiary text-text-secondary hover:text-text-primary;
}

.btn-danger {
  @apply bg-sev-critical hover:bg-sev-critical/80 text-bg-primary;
}

.btn-sm {
  @apply px-2 py-1 text-xs;
}

.btn-icon {
  @apply p-1.5 text-text-muted hover:text-text-primary;
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius-md);
  background: transparent;
  transition: var(--transition-default);
}

.btn-icon:hover {
  background: var(--bg-tertiary);
}

.btn-icon:active {
  transform: scale(0.97);
}

/* Soft card container with left border */
.soft-card {
  background: var(--bg-card);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-card);
  padding: 12px;
  transition: var(--transition-default);
  border-left: 4px solid transparent;
}

.soft-card:hover {
  background: var(--bg-tertiary);
}

.soft-card.severity-critical {
  border-left-color: var(--sev-critical);
}

.soft-card.severity-high {
  border-left-color: var(--sev-high);
}

.soft-card.severity-medium {
  border-left-color: var(--sev-medium);
}

.soft-card.severity-low {
  border-left-color: var(--sev-low);
}

.soft-card.severity-info {
  border-left-color: var(--sev-info);
}

/* Inputs */
.input {
  @apply w-full px-3 py-2 bg-bg-tertiary border border-border-default rounded text-sm text-text-primary font-mono;
  @apply focus:outline-none focus:border-accent placeholder:text-text-muted;
}

.input:focus {
  box-shadow: 0 0 0 1px var(--accent);
}

.select {
  @apply w-full px-3 py-2 bg-bg-tertiary border border-border-default rounded text-sm text-text-primary font-mono;
  @apply focus:outline-none focus:border-accent;
}

.select:focus {
  box-shadow: 0 0 0 1px var(--accent);
}

/* Panel styles */
.panel {
  @apply bg-bg-secondary;
}

.panel-header {
  @apply flex items-center justify-between px-3 py-2 border-b border-border-subtle;
  @apply text-xs font-semibold uppercase tracking-widest text-text-muted;
}

.panel-header::before {
  content: '>';
  @apply mr-2 text-accent;
}

.panel-content {
  @apply p-2;
}

/* Code snippet */
.code-snippet {
  @apply font-mono text-sm bg-bg-primary p-3 rounded border border-border-subtle overflow-x-auto;
  line-height: 1.5;
}

/* Activity bar icon button */
.activity-icon {
  @apply flex items-center justify-center w-12 h-12 text-text-muted hover:text-text-primary cursor-pointer;
  @apply relative transition-all;
}

.activity-icon:hover {
  text-shadow: 0 0 8px rgba(96, 165, 250, 0.3);
}

.activity-icon.active {
  @apply text-text-primary;
}

.activity-icon.active::before {
  content: '';
  @apply absolute left-0 top-0 bottom-0 w-0.5 bg-accent;
  box-shadow: 0 0 8px rgba(96, 165, 250, 0.5);
}

/* Tab bar styles */
.tab {
  @apply flex items-center gap-1.5 px-3 py-1.5 text-sm text-text-muted cursor-pointer font-mono;
  @apply border-t-2 border-transparent;
  background: var(--bg-secondary);
}

.tab:hover {
  @apply text-text-primary;
}

.tab.active {
  @apply text-text-primary bg-bg-primary;
  border-top-color: var(--accent);
}

/* Breadcrumb */
.breadcrumb {
  @apply flex items-center gap-1 px-3 py-1.5 text-sm text-text-muted bg-bg-primary font-mono;
}

.breadcrumb-item {
  @apply hover:text-text-primary cursor-pointer;
}

.breadcrumb-separator {
  @apply text-border-default mx-0.5;
}

/* Modal overlay */
.modal-overlay {
  @apply fixed inset-0 bg-black/70 flex items-center justify-center z-50;
  backdrop-filter: blur(2px);
}

.modal-content {
  @apply bg-bg-secondary border border-border-default rounded-lg shadow-elevated max-w-2xl w-full mx-4;
}

.modal-header {
  @apply flex items-center justify-between px-4 py-3 border-b border-border-subtle;
}

.modal-body {
  @apply p-4;
}

.modal-footer {
  @apply flex justify-end gap-2 px-4 py-3 border-t border-border-subtle;
}

/* Progress bar */
.progress-bar {
  @apply h-1.5 bg-border-default overflow-hidden;
  border-radius: var(--radius-sm);
}

.progress-bar-fill {
  @apply h-full bg-accent;
  border-radius: var(--radius-sm);
  transition: width 300ms ease-out;
}

/* List item */
.list-item {
  @apply flex items-center gap-2 px-2 py-1.5 text-sm cursor-pointer font-mono;
  @apply hover:bg-bg-tertiary rounded;
}

.list-item.selected {
  @apply bg-vsc-selection;
}

/* Tooltip */
.tooltip {
  @apply absolute z-50 px-2 py-1 text-xs bg-bg-elevated border border-border-default rounded shadow-dropdown;
  @apply text-text-primary whitespace-nowrap font-mono;
}

/* Notification toast */
.toast {
  @apply fixed bottom-4 right-4 px-4 py-2 rounded shadow-dropdown;
  @apply flex items-center gap-2 text-sm font-mono;
}

.toast-error {
  @apply bg-sev-critical text-bg-primary;
}

.toast-success {
  @apply bg-status-confirmed text-bg-primary;
}

.toast-warning {
  @apply bg-sev-high text-bg-primary;
}

/* Divider */
.divider {
  @apply border-t border-border-subtle my-2;
}

/* Empty state */
.empty-state {
  @apply flex flex-col items-center justify-center py-8 text-text-muted;
}

.empty-state-icon {
  @apply w-12 h-12 mb-3 opacity-40;
}

.empty-state-text {
  @apply text-sm text-center font-mono;
}

/* CRT glow effects */
.glow-critical {
  text-shadow: 0 0 10px rgba(255, 95, 95, 0.4);
}

.glow-high {
  text-shadow: 0 0 10px rgba(240, 180, 41, 0.4);
}

.glow-success {
  text-shadow: 0 0 10px rgba(74, 222, 128, 0.3);
}

.glow-accent {
  text-shadow: 0 0 10px rgba(96, 165, 250, 0.3);
}
```

**Step 2: Verify build succeeds**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes without errors

**Step 3: Commit**

```bash
git add frontend/app/globals.css
git commit -m "feat(ui): update globals.css with futuristic terminal aesthetic"
```

---

### Task 4: Update FindingsList Component with New Card Structure

**Files:**
- Modify: `frontend/components/FindingsPanel/FindingsList.tsx`

**Step 1: Update FindingCard component to use new structure (title first, severity borders)**

The key changes:
1. Add severity class to soft-card for left border
2. Reorder: Title first, then badges, then location, then truncated description
3. Use new severity badge classes
4. Add validation status display

```tsx
function FindingCard({ finding, onClick, onNavigateToFile }: FindingCardProps) {
  // Determine validation status
  const validationStatus = finding.validation_result?.is_valid === true ? 'confirmed'
    : finding.validation_result?.is_valid === false ? 'rejected'
    : finding.disposition && !REPORTABLE_DISPOSITIONS.has(finding.disposition) ? 'needs-review'
    : 'unprocessed';

  return (
    <div
      className={clsx(
        'soft-card',
        finding.severity && `severity-${finding.severity}`
      )}
      style={{ padding: 0, overflow: 'hidden' }}
    >
      <div
        className="p-3 cursor-pointer hover:bg-bg-tertiary"
        onClick={onClick}
        style={{ transition: 'var(--transition-default)' }}
      >
        {/* Title first */}
        <div className="text-sm font-medium text-text-primary mb-2 line-clamp-2">
          {finding.title}
        </div>

        {/* Badges row */}
        <div className="flex items-center gap-2 mb-2 flex-wrap">
          {/* Severity badge */}
          {finding.severity && (
            <span className={clsx('severity-badge', finding.severity)}>
              {finding.severity}
            </span>
          )}

          {/* Validation status */}
          <span className={clsx('validation-status', validationStatus)}>
            {validationStatus === 'confirmed' && '● CONFIRMED'}
            {validationStatus === 'rejected' && '● REJECTED'}
            {validationStatus === 'needs-review' && '● NEEDS REVIEW'}
            {validationStatus === 'unprocessed' && '○ UNPROCESSED'}
          </span>

          {/* Disposition badge */}
          {finding.disposition && (
            <span
              className="text-xs px-2 py-0.5 font-medium rounded"
              style={{
                background: DISPOSITION_COLORS[finding.disposition],
                color: '#0a0c10',
              }}
            >
              {DISPOSITION_LABELS[finding.disposition]}
            </span>
          )}
        </div>

        {/* Location */}
        <div className="flex items-center gap-2 text-xs text-text-secondary mb-2">
          <FileCode className="w-3 h-3" />
          <span className="truncate">{finding.file_path}</span>
          <span className="text-accent">L{finding.line_start}</span>
        </div>

        {/* Description (truncated) */}
        {finding.description && (
          <div className="text-xs text-text-muted line-clamp-2">
            {finding.description}
          </div>
        )}
      </div>

      {/* Navigate button */}
      <div className="px-3 pb-2 flex justify-end">
        <button
          onClick={(e) => {
            e.stopPropagation();
            onNavigateToFile();
          }}
          className="btn-icon"
          title="Go to file"
        >
          <ExternalLink className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
```

**Step 2: Update the filter buttons styling**

Replace the inline styles in the filter button mapping with cleaner class-based approach using the new design tokens.

**Step 3: Verify build succeeds**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes without errors

**Step 4: Commit**

```bash
git add frontend/components/FindingsPanel/FindingsList.tsx
git commit -m "feat(ui): update FindingsList with new card structure and severity styling"
```

---

### Task 5: Update ValidationBadge Component

**Files:**
- Modify: `frontend/components/ValidationBadge/ValidationBadge.tsx`
- Modify: `frontend/components/ValidationBadge/ValidationBadge.css`

**Step 1: Update ValidationBadge.tsx**

```tsx
'use client';

import React from 'react';
import { ValidationResult } from '@/types';
import './ValidationBadge.css';

interface ValidationBadgeProps {
  validationResult?: ValidationResult | null;
}

export const ValidationBadge: React.FC<ValidationBadgeProps> = ({ validationResult }) => {
  if (!validationResult) {
    return null;
  }

  const { is_valid, confidence, reasoning } = validationResult;

  return (
    <div className={`validation-badge-container ${is_valid ? 'valid' : 'invalid'}`}>
      <div className="validation-badge-header">
        <span className={`validation-status-indicator ${is_valid ? 'confirmed' : 'rejected'}`}>
          {is_valid ? '● CONFIRMED' : '● REJECTED'}
        </span>
        {confidence !== null && (
          <span className="validation-confidence">
            {confidence}%
          </span>
        )}
      </div>
      {reasoning && reasoning.length > 0 && (
        <div className="validation-reasoning">
          <ul>
            {reasoning.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
```

**Step 2: Update ValidationBadge.css**

```css
.validation-badge-container {
  padding: 12px;
  border-radius: 6px;
  font-family: var(--font-mono), 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  border-left: 4px solid transparent;
}

.validation-badge-container.valid {
  background: rgba(74, 222, 128, 0.1);
  border-left-color: var(--status-confirmed, #4ade80);
}

.validation-badge-container.invalid {
  background: rgba(248, 113, 113, 0.1);
  border-left-color: var(--status-rejected, #f87171);
}

.validation-badge-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.validation-status-indicator {
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.validation-status-indicator.confirmed {
  color: var(--status-confirmed, #4ade80);
}

.validation-status-indicator.rejected {
  color: var(--status-rejected, #f87171);
}

.validation-confidence {
  color: var(--text-secondary, #8892a0);
  font-size: 0.75rem;
}

.validation-reasoning {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--border-subtle, #1e2430);
}

.validation-reasoning ul {
  margin: 0;
  padding-left: 16px;
  color: var(--text-secondary, #8892a0);
}

.validation-reasoning li {
  margin-bottom: 4px;
  line-height: 1.4;
}

.validation-reasoning li:last-child {
  margin-bottom: 0;
}
```

**Step 3: Verify build succeeds**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes without errors

**Step 4: Commit**

```bash
git add frontend/components/ValidationBadge/
git commit -m "feat(ui): update ValidationBadge with new terminal aesthetic"
```

---

### Task 6: Update FlowVisualization Node Colors

**Files:**
- Modify: `frontend/components/FlowVisualization/FlowVisualization.tsx`
- Modify: `frontend/components/FlowVisualization/structuredTraceRisk.js`

**Step 1: Update FlowVisualization.tsx status colors and node styling**

Update the statusColors object in FlowNodeComponent:
```tsx
const statusColors = {
  pending: 'border-border-default bg-bg-secondary',
  running: 'border-accent bg-accent/20 animate-pulse',
  completed: 'border-status-confirmed bg-status-confirmed/20',
  failed: 'border-sev-critical bg-sev-critical/20',
};
```

Update MiniMap nodeColor function to use new colors:
```tsx
nodeColor={(node) => {
  const data = node.data as FlowNode;
  if (variant === 'structured') {
    const risk = (data as any)?.structured_risk;
    if (risk === 'finding') return '#ff5f5f';  // sev-critical
    if (risk === 'sink') return '#fbbf24';     // status-needs-review
    return '#4ade80';                           // status-confirmed
  }
  // ... rest of logic with updated colors
}}
```

Update edge colors:
```tsx
style: {
  stroke: isNodeRunning(nodesForView, edge.target) ? '#60a5fa' : '#2a3040',
}
```

**Step 2: Update structuredTraceRisk.js ring classes**

```javascript
export function getStructuredTraceRiskRingClass({ risk, isTouchedEntrypoint }) {
  if (risk === 'finding') return 'ring-2 ring-node-finding ring-offset-1 ring-offset-bg-primary';
  if (risk === 'sink') return 'ring-2 ring-node-sink ring-offset-1 ring-offset-bg-primary';
  if (isTouchedEntrypoint) return 'ring-2 ring-node-touched ring-offset-1 ring-offset-bg-primary';
  return 'ring-2 ring-node-normal ring-offset-1 ring-offset-bg-primary';
}
```

**Step 3: Verify build succeeds**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes without errors

**Step 4: Commit**

```bash
git add frontend/components/FlowVisualization/
git commit -m "feat(ui): update FlowVisualization with new node colors"
```

---

### Task 7: Update Main Page Layout Classes

**Files:**
- Modify: `frontend/app/page.tsx`

**Step 1: Update page.tsx class references**

Key updates:
- Replace `bg-vsc-bg` with `bg-bg-primary`
- Replace `bg-vsc-activitybar` with `bg-bg-secondary`
- Replace `bg-vsc-sidebar` with `bg-bg-secondary`
- Replace `bg-vsc-statusbar` with `bg-bg-primary border-t border-border-default`
- Replace text color classes with new ones
- Add scanlines class to root div for subtle CRT effect

Update the main container:
```tsx
<div className="h-screen flex flex-col bg-bg-primary scanlines">
```

Update header:
```tsx
<header className="h-9 bg-bg-secondary flex items-center justify-between px-3 border-b border-border-subtle select-none">
```

Update activity bar:
```tsx
<aside className="w-12 bg-bg-secondary flex flex-col items-center py-1 border-r border-border-subtle">
```

Update sidebar:
```tsx
<aside className="w-64 bg-bg-secondary flex flex-col border-r border-border-subtle">
```

Update status bar:
```tsx
<footer className="h-6 bg-bg-primary border-t border-border-default flex items-center px-3 text-xs text-text-secondary select-none">
```

**Step 2: Verify build succeeds**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes without errors

**Step 3: Commit**

```bash
git add frontend/app/page.tsx
git commit -m "feat(ui): update main layout with new color classes and scanlines"
```

---

### Task 8: Visual Testing and Final Polish

**Files:**
- No file changes, testing only

**Step 1: Run dev server and visual inspection**

Run: `cd .worktrees/ui-redesign/frontend && npm run dev`

Check these views:
1. Login/Auth screen - fonts and colors
2. Project selector - fonts and cards
3. Main IDE view:
   - Activity bar icons and active states
   - Sidebar panels (Explorer, Agents, Findings)
   - Finding cards with severity badges and validation status
   - Flow visualization with node colors
   - Status bar at bottom
4. Modals (Settings, Threat Model)

**Step 2: Verify the build passes**

Run: `cd .worktrees/ui-redesign/frontend && npm run build`
Expected: Build completes successfully

**Step 3: Create final commit**

```bash
git add -A
git commit -m "feat(ui): complete futuristic-retro terminal aesthetic redesign

- JetBrains Mono font throughout
- New color palette with warm dark undertones
- Bold severity badges with glow effects
- Validation status indicators (green/yellow/red/white)
- Left border accents on finding cards
- Terminal-style panel headers with > prefix
- Subtle scanline overlay
- Updated flow diagram node colors
- All existing functionality preserved"
```

---

## Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | Add JetBrains Mono font | layout.tsx |
| 2 | Update Tailwind color palette | tailwind.config.ts |
| 3 | Update global CSS tokens | globals.css |
| 4 | Update FindingsList cards | FindingsList.tsx |
| 5 | Update ValidationBadge | ValidationBadge.tsx, .css |
| 6 | Update FlowVisualization | FlowVisualization.tsx |
| 7 | Update main page layout | page.tsx |
| 8 | Visual testing | N/A |

**Total commits:** 8

**Post-implementation:** Use superpowers:finishing-a-development-branch to merge or create PR.
