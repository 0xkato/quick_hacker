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
        // VSCode Dark+ Theme - Exact colors
        'vsc-bg': '#1e1e1e',
        'vsc-sidebar': '#252526',
        'vsc-activitybar': '#333333',
        'vsc-panel': '#1e1e1e',
        'vsc-input': '#3c3c3c',
        'vsc-dropdown': '#3c3c3c',
        'vsc-border': '#454545',
        'vsc-border-subtle': '#3c3c3c',

        // Text colors
        'vsc-text': '#cccccc',
        'vsc-text-muted': '#858585',
        'vsc-text-link': '#3794ff',

        // Interactive states
        'vsc-accent': '#0078d4',
        'vsc-accent-hover': '#1f8ad2',
        'vsc-selection': '#264f78',
        'vsc-hover': '#2a2d2e',
        'vsc-active': '#37373d',
        'vsc-focus': '#007fd4',

        // Tab bar
        'vsc-tab-active': '#1e1e1e',
        'vsc-tab-inactive': '#2d2d2d',
        'vsc-tab-border': '#1e1e1e',

        // Status bar
        'vsc-statusbar': '#007acc',
        'vsc-statusbar-debug': '#cc6633',

        // Severity colors - slightly muted for VSCode feel
        'sev-critical': '#f14c4c',
        'sev-high': '#cca700',
        'sev-medium': '#e9a700',
        'sev-low': '#3794ff',
        'sev-info': '#75beff',

        // Git colors
        'vsc-git-added': '#81b88b',
        'vsc-git-modified': '#e2c08d',
        'vsc-git-deleted': '#c74e39',

        // Notification colors
        'vsc-error': '#f14c4c',
        'vsc-warning': '#cca700',
        'vsc-success': '#89d185',
      },
      fontFamily: {
        mono: [
          'Menlo',
          'Monaco',
          'Consolas',
          'Liberation Mono',
          'Courier New',
          'monospace',
        ],
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica',
          'Arial',
          'sans-serif',
        ],
      },
      fontSize: {
        'vsc-xs': '11px',
        'vsc-sm': '12px',
        'vsc-base': '13px',
        'vsc-lg': '14px',
      },
      spacing: {
        'vsc-activity': '48px',
        'vsc-sidebar': '250px',
        'vsc-panel': '320px',
      },
      boxShadow: {
        'vsc-dropdown': '0 4px 8px rgba(0, 0, 0, 0.3)',
        'vsc-widget': '0 0 8px 2px rgba(0, 0, 0, 0.36)',
      },
      animation: {
        'vsc-spin': 'spin 1.5s linear infinite',
      },
    },
  },
  plugins: [],
};

export default config;
