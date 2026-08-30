import React, { useCallback, useEffect, useState } from 'react';
import {
  ScrollText, Cloud, Monitor, AlertCircle, RefreshCw, Shield,
} from 'lucide-react';
import { firebaseDb, type AuditLogEntry } from '../../lib/firebaseDb';
import { useAuthStore } from '../../store/authStore';
import './Platform.css';

const TRACKED_EVENTS = [
  { action: 'user_registered', label: 'Account created', desc: 'New user registration' },
  { action: 'user_login', label: 'Sign in', desc: 'Successful authentication' },
  { action: 'user_login_failed', label: 'Failed sign in', desc: 'Invalid credentials attempt' },
  { action: 'user_role_changed', label: 'Role changed', desc: 'User privilege update by admin' },
  { action: 'finding_status_changed', label: 'Finding updated', desc: 'Remediation status change' },
  { action: 'report_generated', label: 'Report exported', desc: 'JSON, CSV, or CBOM download' },
];

const ACTION_LABELS: Record<string, string> = Object.fromEntries(
  TRACKED_EVENTS.map(e => [e.action, e.label])
);

function formatAction(action: string): string {
  return ACTION_LABELS[action] ?? action.replace(/_/g, ' ');
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function formatMetadata(metadata: Record<string, unknown> | null | undefined): string {
  if (!metadata || Object.keys(metadata).length === 0) return '—';
  const parts: string[] = [];
  if (metadata.format) parts.push(String(metadata.format).toUpperCase());
  if (metadata.newStatus) parts.push(`→ ${metadata.newStatus}`);
  if (metadata.role) parts.push(`role: ${metadata.role}`);
  return parts.length > 0 ? parts.join(' · ') : JSON.stringify(metadata);
}

export function AuditLog() {
  const { user } = useAuthStore();
  const apiConfigured = !!user;

  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchEntries = useCallback(async () => {
    if (!user) {
      setEntries([]);
      return;
    }
    
    setLoading(true);
    setError(null);
    try {
      const logs = await firebaseDb.getAuditLogs(user.id || '');
      setEntries(logs);
    } catch (err: any) {
      setError(err.message || 'Failed to load audit logs.');
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    fetchEntries();
  }, [fetchEntries]);

  // Firestore pagination can be complex, so we limit to 100 on the backend and just display them here.
  const totalPages = 1;
  const page = 1;
  const total = entries.length;

  return (
    <div className="platform-page animate-fade-in">
      <div className="platform-header">
        <div className="platform-header-left">
          <div className="platform-header-icon">
            <ScrollText size={22} />
          </div>
          <div>
            <h2>Audit Log</h2>
            <p>Security-relevant actions recorded when running against the Qrypto API server.</p>
          </div>
        </div>
        <span className={`platform-mode-badge ${apiConfigured ? 'server' : 'browser'}`}>
          {apiConfigured ? <Cloud size={14} /> : <Monitor size={14} />}
          {apiConfigured ? 'Server-backed' : 'Browser-only'}
        </span>
      </div>

      {!apiConfigured && (
        <div className="platform-callout warn">
          <AlertCircle size={20} className="platform-callout-icon" style={{ color: '#eab308' }} />
          <div className="platform-callout-body">
            <h3>Audit logging requires sign in</h3>
            <p>
              In guest mode, actions are not recorded to an audit trail. Sign in to your account to enable tamper-evident activity logging.
            </p>
          </div>
        </div>
      )}

      {apiConfigured && error && (
        <div className="platform-callout error">
          <AlertCircle size={20} className="platform-callout-icon" style={{ color: '#ef4444' }} />
          <div className="platform-callout-body">
            <h3>Unable to load audit log</h3>
            <p>{error}</p>
            <div className="platform-actions">
              <button className="btn btn-ghost btn-sm" onClick={() => fetchEntries()} disabled={loading}>
                <RefreshCw size={14} /> Retry
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 'var(--space-5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 'var(--space-4)' }}>
          <Shield size={16} style={{ color: 'var(--accent-violet)' }} />
          <h3 style={{ fontSize: '0.95rem' }}>Events tracked by the server</h3>
        </div>
        <div className="platform-ref-grid">
          {TRACKED_EVENTS.map(evt => (
            <div key={evt.action} className="platform-ref-item">
              <h4>{evt.label}</h4>
              <p>{evt.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {apiConfigured && !error && (
        <div className="card platform-table-card">
          <div className="platform-table-header">
            <h3>Activity log</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => fetchEntries()} disabled={loading}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>

          {loading && entries.length === 0 ? (
            <div className="platform-empty">
              <div className="spinner" style={{ width: 32, height: 32, marginBottom: 16 }} />
              <p>Loading audit log…</p>
            </div>
          ) : entries.length === 0 ? (
            <div className="platform-empty">
              <ScrollText size={40} className="platform-empty-icon" />
              <h3>No audit events yet</h3>
              <p>Sign in, run scans, update findings, or export reports to generate audit entries.</p>
            </div>
          ) : (
            <>
              <div className="platform-table-wrap">
                <table className="platform-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Action</th>
                      <th>Target</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map(entry => (
                      <tr key={entry.id}>
                        <td>{formatDate(entry.timestamp)}</td>
                        <td>{formatAction(entry.action)}</td>
                        <td>
                          <span className="platform-meta">
                            {entry.targetId ? entry.targetId.slice(0, 8) + '…' : '—'}
                          </span>
                        </td>
                        <td>{formatMetadata(entry.metadata as Record<string, unknown> | null)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="platform-pagination">
                <span>{total} event{total !== 1 ? 's' : ''} total</span>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
