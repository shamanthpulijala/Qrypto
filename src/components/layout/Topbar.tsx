import React from 'react';
import { Bell, Search, Settings, User, ChevronDown, Zap } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './Topbar.css';

const PAGE_TITLES: Record<string, { title: string; subtitle?: string }> = {
  landing:    { title: 'QuantumGuard AI', subtitle: 'Quantum Readiness Platform' },
  dashboard:  { title: 'Dashboard', subtitle: 'Quantum Readiness Overview' },
  inventory:  { title: 'Cryptographic Inventory', subtitle: 'CBOM — Crypto Bill of Materials' },
  findings:   { title: 'Findings', subtitle: 'All detected cryptographic issues' },
  qday:       { title: 'Q-Day Simulator', subtitle: 'Quantum threat scenario analysis' },
  attackmap:  { title: 'Attack Map', subtitle: 'Dependency graph & attack paths' },
  hndl:       { title: 'HNDL Analyzer', subtitle: 'Harvest Now, Decrypt Later assessment' },
  migration:  { title: 'Migration Planner', subtitle: 'Prioritized quantum migration roadmap' },
  agility:    { title: 'Crypto Agility', subtitle: 'Architectural cryptographic flexibility' },
  ai:         { title: 'AI Advisor', subtitle: 'Quantum security consultant' },
  compliance: { title: 'Compliance', subtitle: 'Framework alignment assessment' },
  reports:    { title: 'Reports', subtitle: 'Executive and technical reporting' },
  settings:   { title: 'Settings', subtitle: 'API keys and configuration' },
};

export function Topbar() {
  const { currentPage, assessment, qdayActive, setCurrentPage } = useAppStore();
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
        {/* Q-Day indicator */}
        {qdayActive && (
          <div className="qday-indicator">
            <Zap size={12} />
            Q-DAY SIMULATION ACTIVE
          </div>
        )}

        {/* Assessment selector */}
        {assessment && (
          <div className="assessment-selector">
            <div className="assessment-badge">
              <span className="assessment-name">{assessment.organization}</span>
              <ChevronDown size={12} />
            </div>
          </div>
        )}

        {/* Settings */}
        <button
          className="topbar-icon-btn"
          onClick={() => setCurrentPage('settings')}
          title="Settings"
        >
          <Settings size={16} />
        </button>

        {/* User */}
        <div className="topbar-user">
          <div className="user-avatar">
            <User size={14} />
          </div>
        </div>
      </div>
    </header>
  );
}
