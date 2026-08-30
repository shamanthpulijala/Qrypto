// ============================================================
// Qrypto AI Advisor — Minimal Topbar §24
// Left: Assessment name | Right: Live status + Re-scan + Q-Day toggle
// ============================================================

import React, { useState } from 'react';
import {
  Zap, CheckCircle2, FolderGit2,
  Home, Settings, Search, Shield, LogOut, User
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';
import { RepositoryDetailModal } from '../repository/RepositoryDetailModal';
import './Topbar.css';

export function Topbar() {
  const { currentPage, assessment, qdayActive, setCurrentPage, clearAssessment,
          runQDaySimulation, resetQDaySimulation } = useAppStore();
  const { user, logout } = useAuthStore();
  const [showRepoModal, setShowRepoModal] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  return (
    <>
      {showRepoModal && <RepositoryDetailModal onClose={() => setShowRepoModal(false)} />}

      <header className="topbar">
        <div className="topbar-left">
          {assessment ? (
            <div className="topbar-assessment-info">
              <span className="topbar-org">{assessment.organization || 'ASSESSMENT'}</span>
              <span className="topbar-divider">·</span>
              <span className="topbar-label">QUANTUM ASSESSMENT</span>
            </div>
          ) : (
            <div className="topbar-assessment-info">
              <Shield size={14} style={{ color: 'var(--accent-violet)' }} />
              <span className="topbar-org">Qrypto AI Advisor</span>
            </div>
          )}
        </div>

        <div className="topbar-right">
          {/* User profile */}
          {user && (
            <div className="topbar-user" style={{ position: 'relative' }}>
              <button
                className="topbar-user-btn"
                onClick={() => setShowUserMenu(!showUserMenu)}
                title="User menu"
              >
                <div
                  className="user-avatar"
                  style={{ background: user.avatarColor, width: 28, height: 28, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', fontWeight: 700, color: '#fff' }}
                >
                  {user.initials}
                </div>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginLeft: 8, fontWeight: 600 }}>
                  {user.name.split(' ')[0]}
                </span>
              </button>
              {showUserMenu && (
                <div
                  className="user-menu-dropdown"
                  style={{
                    position: 'absolute',
                    top: '100%',
                    right: 0,
                    marginTop: 8,
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 8,
                    padding: 8,
                    minWidth: 180,
                    zIndex: 100,
                    boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
                  }}
                >
                  <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border-subtle)', marginBottom: 4 }}>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>{user.name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{user.email}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', marginTop: 4 }}>{user.role}</div>
                  </div>
                  <button
                    className="nav-item"
                    style={{ width: '100%', justifyContent: 'flex-start' }}
                    onClick={() => { setShowUserMenu(false); setCurrentPage('settings'); }}
                  >
                    <Settings size={14} />
                    <span className="nav-label">Settings</span>
                  </button>
                  <button
                    className="nav-item"
                    style={{ width: '100%', justifyContent: 'flex-start' }}
                    onClick={() => { setShowUserMenu(false); logout(); }}
                  >
                    <LogOut size={14} />
                    <span className="nav-label">Sign Out</span>
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Q-Day Toggle §36 */}
          {assessment && (
            <div className="qday-toggle-wrap">
              <button
                className={`qday-toggle ${qdayActive ? 'active' : ''}`}
                onClick={() => qdayActive ? resetQDaySimulation() : runQDaySimulation()}
                title={qdayActive ? 'Exit Q-Day simulation' : 'Activate Q-Day simulation'}
              >
                <span className={`qday-toggle-option ${!qdayActive ? 'selected' : ''}`}>NORMAL</span>
                <span className={`qday-toggle-option ${qdayActive ? 'selected' : ''}`}>
                  <Zap size={10} /> Q-DAY
                </span>
              </button>
            </div>
          )}

          {/* Scan status indicator */}
          {assessment && (
            <div className="topbar-live">
              <span className="live-dot" />
              <span className="live-text">SCAN COMPLETE</span>
            </div>
          )}

          {/* Repository badge */}
          {assessment && (
            <button
              className="topbar-badge"
              onClick={() => setShowRepoModal(true)}
              title="View repository files"
            >
              <FolderGit2 size={12} />
              {assessment.scanStats?.filesScanned || '—'} files
            </button>
          )}

          {/* New Scan */}
          {assessment && (
            <button className="topbar-badge topbar-badge-action" onClick={() => clearAssessment()} title="Start new scan">
              <Home size={12} /> Re-scan
            </button>
          )}

          {/* Ctrl+K hint */}
          <button
            className="topbar-cmd-hint"
            onClick={() => {
              window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }));
            }}
            title="Search (Ctrl+K)"
          >
            <Search size={13} />
            <span className="cmd-shortcut">⌘K</span>
          </button>
        </div>
      </header>
    </>
  );
}
