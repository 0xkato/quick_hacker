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
        // Legacy font sizes (for compatibility during migration)
        'vsc-xs': '11px',
        'vsc-sm': '12px',
        'vsc-base': '13px',
        'vsc-lg': '14px',
      },
      spacing: {
        'activity': '48px',
        'sidebar': '250px',
        'panel': '320px',
        // Legacy spacing (for compatibility during migration)
        'vsc-activity': '48px',
        'vsc-sidebar': '250px',
        'vsc-panel': '320px',
      },
      boxShadow: {
        'glow-critical': '0 0 12px rgba(255, 95, 95, 0.4)',
        'glow-high': '0 0 12px rgba(240, 180, 41, 0.4)',
        'glow-success': '0 0 10px rgba(74, 222, 128, 0.3)',
        'glow-accent': '0 0 10px rgba(96, 165, 250, 0.3)',
        'dropdown': '0 4px 12px rgba(0, 0, 0, 0.5)',
        'elevated': '0 8px 24px rgba(0, 0, 0, 0.4)',
        // Legacy shadows (for compatibility during migration)
        'vsc-dropdown': '0 4px 8px rgba(0, 0, 0, 0.3)',
        'vsc-widget': '0 0 8px 2px rgba(0, 0, 0, 0.36)',
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
