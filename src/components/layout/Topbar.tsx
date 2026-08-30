// ============================================================
// Qrypto — Application Top Bar §5 / §38.6
//
// Three deliberate clusters instead of one flat row of equal-
// weight chips:
//   1. CONTEXT — org + current workspace       (left)
//   2. STATUS  — scan state / files / Q-Day    (centre-right)
//   3. ACTIONS — re-scan, ⌘K, account          (right)
//
// Every readout in cluster 2 is the SAME <StatusPill> component.
// Only the fill colour changes per state (§38.6) — shape, height
// and type size never do.
//
// §3: no value here is invented. When a number is missing we say
// so ("Files unknown") rather than printing a placeholder.
// ============================================================

import React, { useState } from 'react';
import {
  Zap, FolderGit2, Home, Settings, Search, Shield, LogOut,
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';
import { RepositoryDetailModal } from '../repository/RepositoryDetailModal';
import './Topbar.css';

/** Fill states for the one shared status pill (§38.6). */
type PillState = 'ok' | 'active' | 'warning' | 'elevated';

/**
 * ── THE Q-DAY ELEVATED RULE (§38.6) ─────────────────────────
 * The Q-Day pill goes solid red for exactly one reason:
 * *elevated Q-Day risk has been detected in this assessment.*
 *
 * That is defined as:
 *   quantumReadinessScore < QDAY_ELEVATED_THRESHOLD
 *   OR the Q-Day simulation is currently projecting the post-Q-Day
 *   posture (qdayActive), which is by definition the elevated view.
 *
 * Exported so any other surface rendering this pill applies the
 * identical rule — the state must not mean one thing here and
 * something else on the dashboard.
 */
export const QDAY_ELEVATED_THRESHOLD = 50;

export function isQDayElevated(
  readinessScore: number | undefined | null,
  qdayActive: boolean,
): boolean {
  if (qdayActive) return true;
  if (typeof readinessScore !== 'number') return false; // unknown ≠ elevated (§3)
  return readinessScore < QDAY_ELEVATED_THRESHOLD;
}

/** One pill component. Every status readout in the bar is this. */
function StatusPill({
  state = 'ok',
  dot = false,
  className = '',
  children,
  onClick,
  title,
}: {
  state?: PillState;
  dot?: boolean;
  className?: string;
  children: React.ReactNode;
  onClick?: () => void;
  title?: string;
}) {
  const cls = `tb-pill tb-pill-${state} ${className}`.trim();
  const body = (
    <>
      {dot && <span className="tb-pill-dot" aria-hidden />}
      <span>{children}</span>
    </>
  );
  return onClick ? (
    <button type="button" className={cls} onClick={onClick} title={title}>{body}</button>
  ) : (
    <span className={cls} title={title}>{body}</span>
  );
}

/** Current-workspace label for the context breadcrumb. */
const PAGE_LABELS: Record<string, string> = {
  landing: 'Scan',
  dashboard: 'Overview',
  inventory: 'Cryptographic Inventory',
  findings: 'Findings',
  quantumrisk: 'Quantum Risk',
  hndl: 'Mosca / HNDL',
  attackmap: 'Relationship Graph',
  qday: 'Q-Day Assumptions',
  pqcrecs: 'PQC Recommendations',
  hybridmig: 'Hybrid Migration',
  migration: 'Migration Roadmap',
  agility: 'Crypto Agility',
  ai: 'AI Consultant',
  reports: 'Reports',
  scanhistory: 'Scan History',
  auditlog: 'Audit Log',
  settings: 'Settings',
};

export function Topbar() {
  const {
    currentPage, assessment, qdayActive, setCurrentPage, clearAssessment,
    runQDaySimulation, resetQDaySimulation, isScanning, scanError,
  } = useAppStore();
  const { user, logout } = useAuthStore();
  const [showRepoModal, setShowRepoModal] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  // Scan state is derived from live store flags, never a fixed literal (§3, §5).
  const scan: { state: PillState; text: string } = isScanning
    ? { state: 'active', text: 'SCANNING' }
    : scanError
      ? { state: 'warning', text: 'COMPLETE · WARNINGS' }
      : { state: 'ok', text: 'SCAN COMPLETE' };

  // File count: print the real number or say it is unknown (§3).
  const filesScanned = assessment?.scanStats?.filesScanned;
  const filesText = typeof filesScanned === 'number'
    ? `${filesScanned.toLocaleString()} FILES`
    : 'FILES UNKNOWN';

  const readiness = assessment?.quantumReadinessScore;
  const elevated = isQDayElevated(readiness, qdayActive);

  const qdayText = qdayActive
    ? 'Q-DAY PROJECTION'
    : elevated
      ? 'Q-DAY RISK ELEVATED'
      : 'Q-DAY SIM';

  const qdayTitle = qdayActive
    ? 'Exit Q-Day simulation and return to the present-day posture'
    : elevated
      ? `Elevated Q-Day risk: quantum readiness ${readiness} is below ${QDAY_ELEVATED_THRESHOLD}. Click to project the post-Q-Day posture.`
      : 'Project this assessment under the assumption a cryptanalytically relevant quantum computer exists';

  const workspace = PAGE_LABELS[currentPage];

  return (
    <>
      {showRepoModal && <RepositoryDetailModal onClose={() => setShowRepoModal(false)} />}

      <header className="topbar">
        {/* ── Cluster 1 · Context ─────────────────────────── */}
        <div className="topbar-left">
          {assessment ? (
            <div className="topbar-assessment-info">
              <span className="topbar-org">{assessment.organization || 'Assessment'}</span>
              {workspace && (
                <>
                  <span className="topbar-divider" aria-hidden>/</span>
                  <span className="topbar-label">{workspace}</span>
                </>
              )}
            </div>
          ) : (
            <div className="topbar-assessment-info">
              <Shield size={14} className="topbar-mark" aria-hidden />
              <span className="topbar-org">Qrypto</span>
              <span className="topbar-divider" aria-hidden>/</span>
              <span className="topbar-label">{workspace || 'Awaiting scan'}</span>
            </div>
          )}
        </div>

        {/* ── Cluster 2 · Status ──────────────────────────── */}
        {assessment && (
          <div className="topbar-status" role="group" aria-label="Assessment status">
            <StatusPill state={scan.state} dot title="Live scan state">
              {scan.text}
            </StatusPill>

            <StatusPill
              className="tb-pill-files"
              onClick={() => setShowRepoModal(true)}
              title="Files read by the scanner — click to inspect the repository"
            >
              {filesText}
            </StatusPill>

            <StatusPill
              state={elevated ? 'elevated' : 'ok'}
              onClick={() => (qdayActive ? resetQDaySimulation() : runQDaySimulation())}
              title={qdayTitle}
            >
              {qdayActive && <Zap size={10} aria-hidden />} {qdayText}
            </StatusPill>
          </div>
        )}

        {/* ── Cluster 3 · Actions ─────────────────────────── */}
        <div className="topbar-right">
          <div className="topbar-actions">
            {assessment && (
              <button
                className="topbar-badge topbar-badge-action"
                onClick={() => clearAssessment()}
                title="Discard this assessment and start a new scan"
              >
                <Home size={12} aria-hidden /> Re-scan
              </button>
            )}

            <button
              className="topbar-cmd-hint"
              onClick={() => {
                window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }));
              }}
              title="Open the command center"
              aria-label="Open the command center"
            >
              <Search size={13} aria-hidden />
              <span className="keycap-row" aria-hidden>
                <span className="keycap">⌘</span>
                <span className="keycap">K</span>
              </span>
            </button>
          </div>

          {user && (
            <div className="topbar-user">
              <button
                className="topbar-user-btn"
                onClick={() => setShowUserMenu(v => !v)}
                aria-haspopup="menu"
                aria-expanded={showUserMenu}
                title={`${user.name} — account menu`}
              >
                <span className="topbar-avatar" style={{ background: user.avatarColor }}>
                  {user.initials}
                </span>
                <span className="topbar-user-name">{user.name.split(' ')[0]}</span>
              </button>

              {showUserMenu && (
                <div className="user-menu-dropdown" role="menu">
                  <div className="user-menu-head">
                    <div className="user-menu-name">{user.name}</div>
                    <div className="user-menu-email">{user.email}</div>
                    <div className="user-menu-role">{user.role}</div>
                  </div>
                  <button
                    className="nav-item"
                    role="menuitem"
                    onClick={() => { setShowUserMenu(false); setCurrentPage('settings'); }}
                  >
                    <Settings size={14} aria-hidden />
                    <span className="nav-label">Settings</span>
                  </button>
                  <button
                    className="nav-item"
                    role="menuitem"
                    onClick={() => { setShowUserMenu(false); logout(); }}
                  >
                    <LogOut size={14} aria-hidden />
                    <span className="nav-label">Sign Out</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </header>
    </>
  );
}
