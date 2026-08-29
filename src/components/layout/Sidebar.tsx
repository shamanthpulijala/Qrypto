// ============================================================
// QuantumGuard AI — Navigation Rail §22
// Slim floating glass sidebar with icon-only default state
// ============================================================

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, Search, Network, AlertTriangle, Zap,
  Map, Bot, FileText, Shield, BarChart3, Settings, LogOut,
  FileCode2, Upload
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';
import './Sidebar.css';

const NAV_ITEMS = [
  // DISCOVER
  { id: 'dashboard',    icon: LayoutDashboard, label: 'Dashboard',             group: 'discover', status: 'ready' },
  { id: 'landing',      icon: Zap,             label: 'Scan',                  group: 'discover', status: 'ready' },
  { id: 'inventory',    icon: Search,          label: 'Inventory',             group: 'discover', status: 'ready' },
  { id: 'algorithms',   icon: Search,          label: 'Algorithms',            group: 'discover', status: 'partial' },
  { id: 'secrets',      icon: Shield,          label: 'Secrets & Keys',        group: 'discover', status: 'partial' },
  { id: 'certificates', icon: FileText,        label: 'Certificates',          group: 'discover', status: 'partial' },
  { id: 'tls',          icon: Network,         label: 'TLS / Protocols',       group: 'discover', status: 'partial' },
  { id: 'libraries',    icon: FileCode2,       label: 'Libraries / Dependencies', group: 'discover', status: 'partial' },
  { id: 'hsm',          icon: Shield,          label: 'HSM / PKCS#11',         group: 'discover', status: 'partial' },
  { id: 'cloudkms',     icon: Network,         label: 'Cloud KMS',             group: 'discover', status: 'partial' },
  { id: 'containers',   icon: Zap,             label: 'Containers',            group: 'discover', status: 'partial' },
  { id: 'binary',       icon: FileCode2,       label: 'Binary Artifacts',      group: 'discover', status: 'partial' },
  { id: 'depgraph',     icon: Network,         label: 'Dependency Graph',      group: 'discover', status: 'partial' },

  // ASSESS
  { id: 'findings',     icon: AlertTriangle,   label: 'Findings',              group: 'assess',   status: 'ready' },
  { id: 'quantumrisk',  icon: AlertTriangle,   label: 'Quantum Risk',          group: 'assess',   status: 'partial' },
  { id: 'hndl',         icon: Shield,          label: 'Mosca / HNDL',          group: 'assess',   status: 'ready' },
  { id: 'attackmap',    icon: Network,         label: 'Attack Map',            group: 'assess',   status: 'ready' },
  { id: 'qday',         icon: Zap,             label: 'Q-Day Assumptions',     group: 'assess',   status: 'ready' },

  // MIGRATE
  { id: 'pqcrecs',      icon: Map,             label: 'PQC Recommendations',   group: 'migrate',  status: 'partial' },
  { id: 'hybridmig',    icon: Map,             label: 'Hybrid Migration',      group: 'migrate',  status: 'partial' },
  { id: 'migration',    icon: Map,             label: 'Migration Roadmap',     group: 'migrate',  status: 'ready' },
  { id: 'agility',      icon: BarChart3,       label: 'Crypto Agility',        group: 'migrate',  status: 'ready' },

  // REPORT
  { id: 'execreport',   icon: FileText,        label: 'Executive Report',      group: 'report',   status: 'partial' },
  { id: 'techreport',   icon: FileText,        label: 'Technical Report',      group: 'report',   status: 'partial' },
  { id: 'devfindings',  icon: FileCode2,       label: 'Developer Findings',    group: 'report',   status: 'partial' },
  { id: 'cbom',         icon: FileText,        label: 'CBOM',                  group: 'report',   status: 'partial' },
  { id: 'export',       icon: Upload,          label: 'Export',                group: 'report',   status: 'partial' },

  // PLATFORM
  { id: 'scanhistory',  icon: LayoutDashboard, label: 'Scan History',          group: 'platform', status: 'partial' },
  { id: 'auditlog',     icon: FileText,        label: 'Audit Log',             group: 'platform', status: 'partial' },
];

const GROUP_LABELS: Record<string, string> = {
  discover: 'DISCOVER',
  assess: 'ASSESS',
  migrate: 'MIGRATE',
  report: 'REPORT',
  platform: 'PLATFORM',
};

const PAGE_ROUTES: Record<string, string> = {
  landing: '/',
  dashboard: '/dashboard',
  inventory: '/inventory',
  findings: '/findings',
  qday: '/qday',
  attackmap: '/attackmap',
  hndl: '/hndl',
  migration: '/migration',
  agility: '/agility',
  ai: '/ai',
  reports: '/reports',
  compliance: '/compliance',
  settings: '/settings',
};

export function Sidebar() {
  const { currentPage, setCurrentPage, sidebarCollapsed, toggleSidebar, assessment } = useAppStore();
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const navigateTo = (pageId: string) => {
    setCurrentPage(pageId);
    const route = PAGE_ROUTES[pageId];
    if (route) navigate(route);
  };

  const groups = ['discover', 'assess', 'migrate', 'report', 'platform'];

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
                const isPartial = item.status === 'partial' || item.status === 'coming';
                // Scan (landing) and Dashboard are always accessible. 
                // Partial items are navigable but visually flagged.
                // Other items require an assessment.
                const alwaysOn = item.id === 'dashboard' || item.id === 'landing';
                const isDisabled = !alwaysOn && !assessment && !isPartial;
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${isActive ? 'active' : ''} ${isPartial ? 'partial' : ''} ${isDisabled ? 'disabled' : ''}`}
                    onClick={() => !isDisabled && navigateTo(item.id)}
                    title={isPartial ? `${item.label} — Partial` : item.label}
                  >
                    <Icon size={16} className="nav-icon" />
                    <span className="nav-label">
                      {item.label}
                      {isPartial && <span className="text-xs ml-2 opacity-50">(Partial)</span>}
                    </span>
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
          onClick={() => navigateTo('settings')}
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
