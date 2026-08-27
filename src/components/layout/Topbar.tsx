// ============================================================
// QuantumGuard AI — Minimal Topbar §24
// Left: Assessment name | Right: Live status + Re-scan + Q-Day toggle
// ============================================================

import React, { useState } from 'react';
import {
  Zap, CheckCircle2, FolderGit2,
  Home, Settings, Search, Shield
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { RepositoryDetailModal } from '../repository/RepositoryDetailModal';
import './Topbar.css';

export function Topbar() {
  const { currentPage, assessment, qdayActive, setCurrentPage, clearAssessment,
          runQDaySimulation, resetQDaySimulation } = useAppStore();
  const [showRepoModal, setShowRepoModal] = useState(false);

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
              <span className="topbar-org">QuantumGuard AI</span>
            </div>
          )}
        </div>

        <div className="topbar-right">
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
