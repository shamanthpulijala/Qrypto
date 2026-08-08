// ============================================================
// QuantumGuard AI — §21 Error Boundary Component
//
// Prevents dashboard crashes from unexpected rendering errors,
// malformed data, or missing metadata.
// ============================================================

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('QuantumGuard UI Error Boundary caught an error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '48px 24px',
          minHeight: '400px',
          background: 'var(--bg-card, #131b2e)',
          border: '1px solid var(--border-color, #1e2d4a)',
          borderRadius: '12px',
          margin: '24px',
          textAlign: 'center',
        }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '50%',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#ef4444',
            marginBottom: '16px',
          }}>
            <AlertTriangle size={28} />
          </div>

          <h3 style={{ color: '#f8fafc', fontSize: '20px', fontWeight: 600, marginBottom: '8px' }}>
            {this.props.fallbackTitle || 'Component Error Recovered'}
          </h3>

          <p style={{ color: '#94a3b8', fontSize: '14px', maxWidth: '480px', marginBottom: '20px', lineHeight: 1.5 }}>
            QuantumGuard prevented a dashboard crash. The system handled an unexpected data format or rendering issue gracefully.
          </p>

          {this.state.error && (
            <div style={{
              background: '#0d1322',
              border: '1px solid #1e2d4a',
              borderRadius: '6px',
              padding: '12px 16px',
              fontFamily: 'monospace',
              fontSize: '12px',
              color: '#f87171',
              marginBottom: '24px',
              maxWidth: '560px',
              wordBreak: 'break-word',
            }}>
              {this.state.error.message}
            </div>
          )}

          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              className="btn btn-primary"
              onClick={this.handleReset}
              style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <RefreshCw size={16} /> Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
