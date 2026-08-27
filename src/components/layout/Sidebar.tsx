// ============================================================
// QuantumGuard AI — Navigation Rail §22
// Slim floating glass sidebar with icon-only default state
// ============================================================

import React from 'react';
import {
  LayoutDashboard, Search, Network, AlertTriangle, Zap,
  Map, Bot, FileText, Shield, BarChart3, Settings, LogOut
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';
import './Sidebar.css';

const NAV_ITEMS = [
  { id: 'dashboard',  icon: LayoutDashboard, label: 'Overview',       group: 'main' },
  { id: 'inventory',  icon: Search,          label: 'Discovery',      group: 'main' },
  { id: 'findings',   icon: AlertTriangle,   label: 'Findings',       group: 'main' },
  { id: 'attackmap',  icon: Network,         label: 'Crypto Twin',    group: 'quantum' },
  { id: 'qday',       icon: Zap,             label: 'Q-Day',          group: 'quantum' },
  { id: 'agility',    icon: BarChart3,       label: 'Agility',        group: 'quantum' },
  { id: 'migration',  icon: Map,             label: 'Migration',      group: 'planning' },
  { id: 'ai',         icon: Bot,             label: 'AI Advisor',     group: 'planning' },
  { id: 'reports',    icon: FileText,        label: 'Reports',        group: 'planning' },
];

const GROUP_LABELS: Record<string, string> = {
  main: 'Core',
  quantum: 'Analysis',
  planning: 'Actions',
};

export function Sidebar() {
  const { currentPage, setCurrentPage, sidebarCollapsed, toggleSidebar, assessment } = useAppStore();
  const { user, logout } = useAuthStore();

  const groups = ['main', 'quantum', 'planning'];

  // Role-based access: certain features require specific roles
  const isAdmin = user?.role === 'ADMIN' || user?.role === 'Security Lead';
  const isCISO = user?.role === 'CISO' || user?.role === 'EXECUTIVE';
  const canAccessReports = isAdmin || isCISO || user?.role === 'ANALYST' || user?.role === 'Security Analyst';

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="logo-icon">
          <Shield size={16} />
        </div>
        <div className="logo-text">
          <span className="logo-name">QuantumGuard</span>
        </div>
      </div>

      {/* Nav Groups */}
      <nav className="sidebar-nav">
        {groups.map(group => {
          const items = NAV_ITEMS.filter(i => i.group === group);
          return (
            <div key={group} className="nav-group">
              <span className="nav-group-label">{GROUP_LABELS[group]}</span>
              {items.map(item => {
                const Icon = item.icon;
                const isActive = currentPage === item.id;
                const isDisabled = !assessment && item.id !== 'dashboard';
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${isActive ? 'active' : ''} ${isDisabled ? 'disabled' : ''}`}
                    onClick={() => !isDisabled && setCurrentPage(item.id)}
                    title={item.label}
                  >
                    <Icon size={16} className="nav-icon" />
                    <span className="nav-label">{item.label}</span>
                    {isActive && <div className="nav-active-dot" />}
                  </button>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Bottom Settings + Logout */}
      <div className="sidebar-bottom">
        <button
          className={`nav-item ${currentPage === 'settings' ? 'active' : ''}`}
          onClick={() => setCurrentPage('settings')}
          title="Settings"
        >
          <Settings size={16} />
          <span className="nav-label">Settings</span>
        </button>
        {user && (
          <button
            className="nav-item"
            onClick={logout}
            title="Sign out"
          >
            <LogOut size={16} />
            <span className="nav-label">Sign Out</span>
          </button>
        )}
      </div>
    </aside>
  );
}
