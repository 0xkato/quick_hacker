/**
 * ErrorBoundary Component
 *
 * Catches React errors in the investigation flow visualization and displays a fallback UI.
 * Prevents ReactFlow failures from crashing the entire application.
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('Investigation flow error:', error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full w-full bg-gray-50 p-8">
          <div className="max-w-md text-center">
            <div className="text-red-600 text-lg font-semibold mb-2">
              Investigation Flow Error
            </div>
            <div className="text-gray-700 mb-4">
              Unable to render the investigation tree visualization.
            </div>
            {this.state.error && (
              <div className="text-sm text-gray-600 bg-gray-100 p-3 rounded font-mono text-left overflow-auto">
                {this.state.error.message}
              </div>
            )}
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Try Again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
