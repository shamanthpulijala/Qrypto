import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History, Cloud, Monitor, AlertCircle, RefreshCw, ExternalLink, Zap,
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';
import { firebaseDb } from '../../lib/firebaseDb';
import type { Assessment } from '../../types';
import './Platform.css';

function formatDate(iso: string | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function statusClass(status: string): string {
  const s = status.toLowerCase();
  if (s === 'complete') return 'complete';
  if (s === 'error') return 'error';
  return 'running';
}

export function ScanHistory() {
  const navigate = useNavigate();
  const { assessment, loadScan, setCurrentPage } = useAppStore();
  const { user } = useAuthStore();
  const apiConfigured = !!user;

  const [scans, setScans] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingScanId, setLoadingScanId] = useState<string | null>(null);

  const fetchScans = useCallback(async () => {
    if (!user) {
      setScans([]);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await firebaseDb.getScans(user.id || '');
      setScans(result);
    } catch (err: any) {
      setError(err.message || 'Failed to load scans.');
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  const handleOpenScan = async (scanId: string) => {
    setLoadingScanId(scanId);
    useAppStore.setState({ scanError: null });
    try {
      await loadScan(scanId);
      const { scanError, assessment: loaded } = useAppStore.getState();
      if (scanError || !loaded) {
        setError(scanError || 'Failed to load scan.');
        return;
      }
      setCurrentPage('dashboard');
      navigate('/dashboard');
    } finally {
      setLoadingScanId(null);
    }
  };

  const total = scans.length;
  const totalPages = 1;

  return (
    <div className="platform-page animate-fade-in">
      <div className="platform-header">
        <div className="platform-header-left">
          <div className="platform-header-icon">
            <History size={22} />
          </div>
          <div>
            <h2>Scan History</h2>
            <p>Review past cryptographic assessments. Server-backed mode persists scans across sessions.</p>
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
            <h3>Scans are not persisted in guest mode</h3>
            <p>
              Your current session keeps one active scan in memory. Closing the tab or refreshing the page clears it.
              Sign in to your account to securely save and reload past scans across sessions.
            </p>
          </div>
        </div>
      )}

      {apiConfigured && error && (
        <div className="platform-callout error">
          <AlertCircle size={20} className="platform-callout-icon" style={{ color: '#ef4444' }} />
          <div className="platform-callout-body">
            <h3>Unable to load scan history</h3>
            <p>{error}</p>
            <div className="platform-actions">
              <button className="btn btn-ghost btn-sm" onClick={() => fetchScans()} disabled={loading}>
                <RefreshCw size={14} /> Retry
              </button>
            </div>
          </div>
        </div>
      )}

      {assessment && (
        <div className="card platform-table-card">
          <div className="platform-table-header">
            <h3>{apiConfigured ? 'Current session' : 'Active scan (this session only)'}</h3>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => { setCurrentPage('dashboard'); navigate('/dashboard'); }}
            >
              <ExternalLink size={14} /> Open dashboard
            </button>
          </div>
          <div className="platform-table-wrap">
            <table className="platform-table">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Scanned</th>
                  <th>Findings</th>
                  <th>Readiness</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>{assessment.name}</td>
                  <td>{formatDate(assessment.scannedAt)}</td>
                  <td>{assessment.scanStats?.findingsTotal || assessment.findings?.length || 0}</td>
                  <td>{assessment.quantumReadinessScore ?? '—'}</td>
                  <td>
                    <span className="platform-status complete">In memory</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {apiConfigured && !error && (
        <div className="card platform-table-card">
          <div className="platform-table-header">
            <h3>Saved scans</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => fetchScans()} disabled={loading}>
              <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
            </button>
          </div>

          {loading && scans.length === 0 ? (
            <div className="platform-empty">
              <div className="spinner" style={{ width: 32, height: 32, marginBottom: 16 }} />
              <p>Loading scan history…</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="platform-empty">
              <History size={40} className="platform-empty-icon" />
              <h3>No saved scans yet</h3>
              <p>Upload a repository from the home page while connected to the API server. Completed scans will appear here.</p>
              <div className="platform-actions">
                <button className="btn btn-primary btn-sm" onClick={() => { setCurrentPage('landing'); navigate('/'); }}>
                  <Zap size={14} /> Start a scan
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="platform-table-wrap">
                <table className="platform-table">
                  <thead>
                    <tr>
                      <th>Project</th>
                      <th>Started</th>
                      <th>Findings</th>
                      <th>Readiness</th>
                      <th>Status</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map(scan => (
                      <tr key={scan.id}>
                        <td>{scan.name}</td>
                        <td>{formatDate(scan.scannedAt)}</td>
                        <td>{scan.scanStats?.findingsTotal || scan.findings?.length || 0}</td>
                        <td>{scan.quantumReadinessScore ?? '—'}</td>
                        <td>
                          <span className={`platform-status ${statusClass(scan.status)}`}>
                            {scan.status.toLowerCase()}
                          </span>
                        </td>
                        <td>
                          {scan.status === 'complete' ? (
                            <button
                              className="btn btn-primary btn-sm"
                              disabled={loadingScanId === scan.id}
                              onClick={() => handleOpenScan(scan.id)}
                            >
                              {loadingScanId === scan.id ? 'Loading…' : 'Open'}
                            </button>
                          ) : (
                            <span className="platform-meta">{scan.scanProgress}%</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="platform-pagination">
                <span>{total} scan{total !== 1 ? 's' : ''} total</span>
              </div>
            </>
          )}
        </div>
      )}

      {!apiConfigured && !assessment && (
        <div className="card platform-empty">
          <History size={40} className="platform-empty-icon" />
          <h3>No scan loaded</h3>
          <p>Start a scan from the home page. It will stay available for this browser session only.</p>
          <div className="platform-actions">
            <button className="btn btn-primary btn-sm" onClick={() => { setCurrentPage('landing'); navigate('/'); }}>
              <Zap size={14} /> Start a scan
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
