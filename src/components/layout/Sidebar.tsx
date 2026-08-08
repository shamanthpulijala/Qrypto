// ============================================================
// QuantumGuard AI — §26 Navigation Sidebar
//
// Sidebar items:
// Overview | Inventory | Findings | Q-Day Simulator |
// Attack Graph | AI Advisor | Migration | Crypto Agility |
// Reports | Settings
// ============================================================

import React from 'react';
import {
  LayoutDashboard, Package, AlertTriangle, Zap, Network,
  Map, Bot, FileText, Shield, BarChart3, ChevronLeft,
  ChevronRight, Settings
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './Sidebar.css';

const NAV_ITEMS = [
  { id: 'dashboard',  icon: LayoutDashboard, label: 'Overview',       group: 'main' },
  { id: 'inventory',  icon: Package,         label: 'Inventory',      group: 'main' },
  { id: 'findings',   icon: AlertTriangle,   label: 'Findings',       group: 'main' },
  { id: 'qday',       icon: Zap,             label: 'Q-Day Simulator',group: 'quantum' },
  { id: 'attackmap',  icon: Network,         label: 'Attack Graph',   group: 'quantum' },
  { id: 'ai',         icon: Bot,             label: 'AI Advisor',     group: 'quantum' },
  { id: 'migration',  icon: Map,             label: 'Migration',      group: 'planning' },
  { id: 'agility',    icon: BarChart3,       label: 'Crypto Agility', group: 'planning' },
  { id: 'reports',    icon: FileText,        label: 'Reports',        group: 'planning' },
];

const GROUP_LABELS: Record<string, string> = {
  main: 'Core Platform',
  quantum: 'Quantum Analysis',
  planning: 'Migration & Governance',
};

export function Sidebar() {
  const { currentPage, setCurrentPage, sidebarCollapsed, toggleSidebar, assessment } = useAppStore();

  const groups = ['main', 'quantum', 'planning'];

  return (
    <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="logo-icon">
          <Shield size={20} />
        </div>
        {!sidebarCollapsed && (
          <div className="logo-text">
            <span className="logo-name">QuantumGuard</span>
            <span className="logo-tag">AI</span>
          </div>
        )}
        <button className="sidebar-toggle" onClick={toggleSidebar} title="Toggle sidebar">
          {sidebarCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </div>

      {/* Nav Groups */}
      <nav className="sidebar-nav">
        {groups.map(group => {
          const items = NAV_ITEMS.filter(i => i.group === group);
          return (
            <div key={group} className="nav-group">
              {!sidebarCollapsed && (
                <span className="nav-group-label">{GROUP_LABELS[group]}</span>
              )}
              {items.map(item => {
                const Icon = item.icon;
                const isActive = currentPage === item.id;
                const isDisabled = !assessment && item.id !== 'dashboard';
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${isActive ? 'active' : ''} ${isDisabled ? 'disabled' : ''}`}
                    onClick={() => !isDisabled && setCurrentPage(item.id)}
                    title={sidebarCollapsed ? item.label : undefined}
                  >
                    <Icon size={16} className="nav-icon" />
                    {!sidebarCollapsed && <span className="nav-label">{item.label}</span>}
                    {isActive && !sidebarCollapsed && <div className="nav-active-dot" />}
                  </button>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Bottom Settings item */}
      <div className="sidebar-bottom">
        <button
          className={`nav-item ${currentPage === 'settings' ? 'active' : ''}`}
          onClick={() => setCurrentPage('settings')}
          title={sidebarCollapsed ? 'Settings' : undefined}
        >
          <Settings size={16} />
          {!sidebarCollapsed && <span className="nav-label">Settings</span>}
        </button>
      </div>
    </aside>
  );
}
