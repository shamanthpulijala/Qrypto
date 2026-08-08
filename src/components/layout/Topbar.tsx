// ============================================================
// QuantumGuard AI — §26 Navigation Topbar & §23 Demo Mode
//
// Topbar items: Organization | Project | Scan Status | Notifications | User
// Prominent §23 "Demo Mode" button that immediately loads NovaBank data.
// ============================================================

import React from 'react';
import { Bell, Settings, User, ChevronDown, Zap, Play, CheckCircle2, Building2, FolderGit2 } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './Topbar.css';

const PAGE_TITLES: Record<string, { title: string; subtitle?: string }> = {
  landing:    { title: 'QuantumGuard AI', subtitle: 'Quantum Readiness Platform' },
  dashboard:  { title: 'Overview', subtitle: 'Enterprise Quantum Readiness Posture' },
  inventory:  { title: 'Inventory', subtitle: 'Cryptographic Bill of Materials (CBOM)' },
  findings:   { title: 'Findings', subtitle: 'Detected Cryptographic Vulnerabilities & Liabilities' },
  qday:       { title: 'Q-Day Simulator', subtitle: 'Quantum Threat Threat-Scenario Modeling' },
  attackmap:  { title: 'Attack Graph', subtitle: 'Vulnerability Propagation & Critical Paths' },
  ai:         { title: 'AI Advisor', subtitle: 'Grounded Post-Quantum Cryptography Consultant' },
  migration:  { title: 'Migration', subtitle: 'Prioritized 4-Phase PQC Migration Roadmap' },
  agility:    { title: 'Crypto Agility', subtitle: 'Architectural Flexibility & Algorithm Abstraction' },
  reports:    { title: 'Reports', subtitle: 'Executive Summaries & Compliance Assessments' },
  settings:   { title: 'Settings', subtitle: 'API Key Configuration & Risk Engine Parameters' },
};

export function Topbar() {
  const { currentPage, assessment, qdayActive, loadNovaBankDemo, setCurrentPage, isScanning } = useAppStore();
  const pageInfo = PAGE_TITLES[currentPage] || PAGE_TITLES.dashboard;

  return (
    <header className="topbar">
      <div className="topbar-left">
        <div className="topbar-title">
          <h1 className="topbar-page-title">{pageInfo.title}</h1>
          {pageInfo.subtitle && (
            <span className="topbar-subtitle">{pageInfo.subtitle}</span>
          )}
        </div>
      </div>

      <div className="topbar-right">
        {/* §23 Demo Mode Button */}
        <button
          className="btn btn-sm btn-demo-mode"
          onClick={loadNovaBankDemo}
          disabled={isScanning}
          title="Instantly load NovaBank Demo Enterprise Dataset"
          style={{
            background: 'linear-gradient(135deg, rgba(0,212,255,0.15) 0%, rgba(139,92,246,0.15) 100%)',
            border: '1px solid rgba(0,212,255,0.4)',
            color: '#00d4ff',
            fontWeight: 600,
            fontSize: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '6px 12px',
            borderRadius: '6px',
            cursor: 'pointer',
          }}
        >
          <Play size={12} fill="#00d4ff" /> Demo Mode (NovaBank)
        </button>

        {/* Q-Day active indicator */}
        {qdayActive && (
          <div className="qday-indicator" style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#ef4444',
            fontSize: '11px',
            fontWeight: 600,
            padding: '4px 8px',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
          }}>
            <Zap size={12} /> Q-DAY SIMULATED
          </div>
        )}

        {/* §26 Topbar Context Elements: Organization & Project */}
        {assessment && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {/* Organization */}
            <div className="topbar-badge" title="Organization" style={{
              display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#94a3b8', background: '#131b2e', padding: '4px 10px', borderRadius: '6px', border: '1px solid #1e2d4a'
            }}>
              <Building2 size={13} color="#00d4ff" />
              <strong style={{ color: '#f8fafc' }}>{assessment.organization}</strong>
            </div>

            {/* Project */}
            <div className="topbar-badge" title="Project" style={{
              display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#94a3b8', background: '#131b2e', padding: '4px 10px', borderRadius: '6px', border: '1px solid #1e2d4a'
            }}>
              <FolderGit2 size={13} color="#8b5cf6" />
              <span>{assessment.name.replace(' Assessment', '')}</span>
            </div>

            {/* Scan Status */}
            <div className="topbar-badge" title="Scan Status" style={{
              display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: '#22c55e', background: 'rgba(34, 197, 94, 0.1)', padding: '4px 8px', borderRadius: '4px', border: '1px solid rgba(34, 197, 94, 0.3)'
            }}>
              <CheckCircle2 size={12} />
              <span>Scan Complete</span>
            </div>
          </div>
        )}

        {/* Notifications */}
        <button className="topbar-icon-btn" title="Notifications" style={{ position: 'relative' }}>
          <Bell size={16} />
          <span style={{ position: 'absolute', top: 4, right: 4, width: 6, height: 6, borderRadius: '50%', background: '#00d4ff' }} />
        </button>

        {/* Settings */}
        <button
          className="topbar-icon-btn"
          onClick={() => setCurrentPage('settings')}
          title="Settings"
        >
          <Settings size={16} />
        </button>

        {/* User Avatar */}
        <div className="topbar-user" title="Security Lead">
          <div className="user-avatar" style={{
            width: 28, height: 28, borderRadius: '50%', background: 'linear-gradient(135deg, #00d4ff, #8b5cf6)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff'
          }}>
            <User size={14} />
          </div>
        </div>
      </div>
    </header>
  );
}
