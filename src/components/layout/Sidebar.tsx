// ============================================================
// Qrypto AI Advisor — Navigation Rail §22
// Slim floating glass sidebar with icon-only default state
// ============================================================

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, Search, Network, AlertTriangle, Zap,
  Map, Bot, FileText, Shield, BarChart3, Settings, LogOut,
  History, ScrollText, PanelLeftClose, PanelLeftOpen,
  Key, Lock, Wifi, Library, HardDrive, Cloud, Box, Binary, GitBranch,
  Download, BookOpen, ShieldCheck, CheckCircle2, Layers,
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';
import './Sidebar.css';

const NAV_ITEMS = [
  // ─── DISCOVER ──────────────────────────────────────────
  { id: 'dashboard',    icon: LayoutDashboard, label: 'Dashboard',             group: 'discover', status: 'ready' },
  { id: 'landing',      icon: Zap,             label: 'Scan',                  group: 'discover', status: 'ready' },
  { id: 'inventory',    icon: Search,          label: 'Inventory',             group: 'discover', status: 'ready' },
  { id: 'secrets',      icon: Key,             label: 'Secrets & Keys',        group: 'discover', status: 'ready' },
  { id: 'certificates', icon: Lock,            label: 'Certificates',          group: 'discover', status: 'ready' },
  { id: 'tls',          icon: Wifi,            label: 'TLS / Protocols',       group: 'discover', status: 'ready' },
  { id: 'libraries',    icon: Library,         label: 'Libraries / Deps',      group: 'discover', status: 'ready' },
  { id: 'hsm',          icon: HardDrive,       label: 'HSM / PKCS#11',        group: 'discover', status: 'ready' },
  { id: 'cloudkms',     icon: Cloud,           label: 'Cloud KMS',             group: 'discover', status: 'ready' },
  { id: 'containers',   icon: Box,             label: 'Containers',            group: 'discover', status: 'ready' },
  { id: 'binary',       icon: Binary,          label: 'Binary Artifacts',      group: 'discover', status: 'ready' },
  { id: 'depgraph',     icon: GitBranch,       label: 'Dependency Graph',      group: 'discover', status: 'ready' },

  // ─── ASSESS ────────────────────────────────────────────
  { id: 'findings',     icon: AlertTriangle,   label: 'Findings',              group: 'assess',   status: 'ready' },
  { id: 'quantumrisk',  icon: AlertTriangle,   label: 'Quantum Risk',          group: 'assess',   status: 'ready' },
  { id: 'hndl',         icon: Shield,          label: 'Mosca / HNDL',          group: 'assess',   status: 'ready' },
  { id: 'attackmap',    icon: Network,         label: 'Attack Map',            group: 'assess',   status: 'ready' },
  { id: 'qday',         icon: Zap,             label: 'Q-Day Assumptions',     group: 'assess',   status: 'ready' },

  // ─── MIGRATE ───────────────────────────────────────────
  { id: 'pqcrecs',      icon: ShieldCheck,     label: 'PQC Recommendations',   group: 'migrate',  status: 'ready' },
  { id: 'hybridmig',    icon: Layers,          label: 'Hybrid Migration',      group: 'migrate',  status: 'ready' },
  { id: 'migration',    icon: Map,             label: 'Migration Roadmap',     group: 'migrate',  status: 'ready' },
  { id: 'agility',      icon: BarChart3,       label: 'Crypto Agility',        group: 'migrate',  status: 'ready' },

  // ─── REPORT ────────────────────────────────────────────
  { id: 'reports',      icon: FileText,        label: 'Reports',               group: 'report',   status: 'ready' },
  { id: 'scanhistory',  icon: History,         label: 'Scan History',          group: 'report',   status: 'ready' },

  // ─── SECURITY ──────────────────────────────────────────
  { id: 'ai',           icon: Bot,             label: 'AI Security Advisor',   group: 'security', status: 'ready' },
  { id: 'auditlog',     icon: ScrollText,      label: 'Audit Log',             group: 'security', status: 'ready' },
];

const GROUP_LABELS: Record<string, string> = {
  discover: 'DISCOVER',
  assess: 'ASSESS',
  migrate: 'MIGRATE',
  report: 'REPORT',
  security: 'SECURITY',
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
  settings: '/settings',
  // DISCOVER scanner views
  algorithms: '/algorithms',
  secrets: '/secrets',
  certificates: '/certificates',
  tls: '/tls',
  libraries: '/libraries',
  hsm: '/hsm',
  cloudkms: '/cloudkms',
  containers: '/containers',
  binary: '/binary',
  depgraph: '/depgraph',
  // ASSESS
  quantumrisk: '/quantumrisk',
  // MIGRATE
  pqcrecs: '/pqcrecs',
  hybridmig: '/hybridmig',
  // PLATFORM
  scanhistory: '/scanhistory',
  auditlog: '/auditlog',
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

  const groups = ['discover', 'assess', 'migrate', 'report', 'security'];

  return (
    <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
      {/* Logo + explicit collapse control (§38.7) */}
      <div className="sidebar-logo">
        <div className="logo-icon">
          <Shield size={16} aria-hidden />
        </div>
        <div className="logo-text">
          <span className="logo-name">Qrypto</span>
        </div>
        <button
          className="sidebar-toggle"
          onClick={toggleSidebar}
          title={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}
          aria-label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}
          aria-expanded={!sidebarCollapsed}
        >
          {sidebarCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
        </button>
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
                const alwaysOn = item.id === 'dashboard' || item.id === 'landing' || item.id === 'ai' || item.id === 'scanhistory' || item.id === 'auditlog' || item.id === 'depgraph';
                const isDisabled = !alwaysOn && !assessment && !isPartial;

                return (
                  <button
                    key={item.id}
                    className={`nav-item ${isActive ? 'active' : ''} ${isPartial ? 'partial' : ''} ${isDisabled ? 'disabled' : ''}`}
                    onClick={() => !isDisabled && navigateTo(item.id)}
                    aria-current={isActive ? 'page' : undefined}
                    aria-disabled={isDisabled}
                    title={
                      isDisabled
                        ? `${item.label} — needs a completed scan`
                        : isPartial
                          ? `${item.label} — partial coverage`
                          : item.label
                    }
                  >
                    <Icon size={16} className="nav-icon" aria-hidden />
                    <span className="nav-label">{item.label}</span>
                    {isPartial && <span className="nav-partial">PARTIAL</span>}
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
          <Settings size={16} className="nav-icon" aria-hidden />
          <span className="nav-label">Settings</span>
        </button>
        {user && (
          <button className="nav-item" onClick={logout} title="Sign out">
            <LogOut size={16} className="nav-icon" aria-hidden />
            <span className="nav-label">Sign Out</span>
          </button>
        )}
      </div>
    </aside>
  );
}
