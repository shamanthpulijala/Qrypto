import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { Topbar } from './components/layout/Topbar';
import { Landing } from './components/landing/Landing';
import { Dashboard } from './components/dashboard/Dashboard';
import { Inventory } from './components/inventory/Inventory';
import { FindingsList } from './components/findings/FindingsList';
import { QDaySimulator } from './components/qday/QDaySimulator';
import { AttackMap } from './components/attackMap/AttackMap';
import { HNDLAnalyzer } from './components/hndl/HNDLAnalyzer';
import { MigrationPlanner } from './components/migration/MigrationPlanner';
import { CryptoAgility } from './components/agility/CryptoAgility';
import { AIAdvisor } from './components/aiAdvisor/AIAdvisor';
import { Reports } from './components/reports/Reports';
import { Settings } from './components/settings/Settings';
import { QuantumCursor } from './components/cursor/QuantumCursor';
import { DashboardBackground } from './components/dashboard/DashboardBackground';
import { CommandPalette } from './components/common/CommandPalette';
import { LoginModal } from './components/auth/LoginModal';
import { PQCRecommendations } from './components/migration/PQCRecommendations';
import { HybridMigration } from './components/migration/HybridMigration';
import { useAppStore } from './store/assessmentStore';
import { useAuthStore } from './store/authStore';
import { ScannerFilterPage } from './components/common/ScannerFilterPage';
import { ScanHistory } from './components/platform/ScanHistory';
import { AuditLog } from './components/platform/AuditLog';
import { StubPage } from './components/common/StubPage';

// ─── P1-14: Route ↔ Store sync ─────────────────────────────
// Maps URL paths to the store's currentPage values.
// bidirectional: URL → store (on load/back-forward)
//                store → URL (on sidebar click)

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

const ROUTE_TO_PAGE: Record<string, string> = Object.fromEntries(
  Object.entries(PAGE_ROUTES).map(([page, route]) => [route, page])
);

/**
 * Syncs URL path with the Zustand store.
 * On URL change (back/forward): updates store.
 * On store change: does NOT navigate (sidebar handles that via useNavigate).
 */
function RouteSync() {
  const location = useLocation();
  const { currentPage, assessment } = useAppStore();

  // On URL change → update store
  React.useEffect(() => {
    const page = ROUTE_TO_PAGE[location.pathname];
    if (page && page !== currentPage) {
      useAppStore.setState({ currentPage: page });
    } else if (location.pathname === '/' && currentPage !== 'landing') {
      useAppStore.setState({ currentPage: 'landing' });
    }
    
    // Reset scroll to top on any route/page change
    window.scrollTo(0, 0);
    const pageContent = document.querySelector('.page-content');
    if (pageContent) pageContent.scrollTo(0, 0);
  }, [location.pathname]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}

function App() {
  const { currentPage, assessment, isScanning, scanError } = useAppStore();
  const { user, isInitialized, initAuth } = useAuthStore();

  React.useEffect(() => {
    initAuth();
  }, [initAuth]);

  // Reset scroll to top whenever we navigate to a new page (covers store-driven navigation)
  React.useEffect(() => {
    window.scrollTo(0, 0);
    const pageContent = document.querySelector('.page-content');
    if (pageContent) pageContent.scrollTo(0, 0);
  }, [currentPage]);

  if (!isInitialized) {
    return null; // Wait for Firebase auth to initialize
  }

  // Auth gate: require login before accessing protected pages unless an assessment or scan is active
  if (!user && !assessment && !isScanning && currentPage !== 'landing' && currentPage !== 'settings') {
    return (
      <>
        <QuantumCursor />
        <Landing />
        <LoginModal />
      </>
    );
  }

  const renderPage = () => {
    // Pages that don't require an assessment
    if (currentPage === 'landing') return <Landing />;
    // Platform pages — no active scan required
    if (currentPage === 'scanhistory') return <ScanHistory />;
    if (currentPage === 'auditlog') return <AuditLog />;
    if (currentPage === 'settings') return <Settings />;

    // Loading State
    if (isScanning) {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div className="spinner" style={{ width: 48, height: 48, borderWidth: 4, marginBottom: 16 }} />
          <h2 style={{ color: 'var(--text-primary)' }}>Analyzing Codebase...</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Scanning for cryptographic primitives and evaluating quantum risk.</p>
        </div>
      );
    }

    // Error State from Scanning
    if (scanError && !assessment) {
      return (
        <div className="empty-state">
          <div className="empty-state-icon" style={{ opacity: 1 }}>❌</div>
          <h2 style={{ color: 'var(--status-critical)' }}>Scan Failed</h2>
          <p style={{ color: 'var(--text-secondary)', maxWidth: '500px' }}>{scanError}</p>
          <button className="btn btn-primary mt-4" onClick={() => {
            useAppStore.setState({ scanError: null });
            useAppStore.getState().setCurrentPage('landing');
          }}>
            Return to Home
          </button>
        </div>
      );
    }

    // Require assessment for these pages
    if (!assessment) {
      return (
        <div className="empty-state">
          <div className="empty-state-icon">🛡️</div>
          <h2>No Scan Loaded</h2>
          <p>Start a scan from the home page to explore your cryptographic inventory.</p>
          <button className="btn btn-primary mt-4" onClick={() => useAppStore.getState().setCurrentPage('landing')}>
            Start a Scan
          </button>
        </div>
      );
    }

    switch (currentPage) {
      case 'dashboard':   return <Dashboard />;
      case 'inventory':   return <Inventory />;
      case 'findings':    return <FindingsList />;
      case 'qday':        return <QDaySimulator />;
      case 'attackmap':   return <AttackMap />;
      case 'hndl':        return <HNDLAnalyzer />;
      case 'migration':   return <MigrationPlanner />;
      case 'agility':     return <CryptoAgility />;
      case 'ai':          return <AIAdvisor />;
      case 'reports':     return <Reports />;
      // Scanner-filtered views — real data, filtered by category
      case 'algorithms':  return <ScannerFilterPage title="Algorithms" category="all" description="All cryptographic algorithms detected across your codebase." />;
      case 'secrets':     return <ScannerFilterPage title="Secrets &amp; Keys" category="secret" description="Detected secrets, API keys, and hardcoded credentials." />;
      case 'certificates':return <ScannerFilterPage title="Certificates / X.509" category="certificate" description="Detected X.509 certificates and public key material." />;
      case 'tls':         return <ScannerFilterPage title="TLS / Protocols" category="tls" description="Detected TLS/SSL protocol configurations." />;
      case 'libraries':   return <ScannerFilterPage title="Libraries / Dependencies" category="dependency" description="Detected cryptographic library dependencies." />;
      case 'hsm':         return <ScannerFilterPage title="HSM / PKCS#11" category="hardware" description="Detected hardware security module references." />;
      case 'cloudkms':    return <ScannerFilterPage title="Cloud KMS" category="kms" description="Detected cloud key management service integrations." />;
      case 'containers':  return <ScannerFilterPage title="Containers" category="container" description="Detected cryptographic evidence in container definitions." />;
      case 'binary':      return <ScannerFilterPage title="Binary Artifacts" category="binary" description="Detected cryptographic references in binary files." />;
      case 'quantumrisk': return <ScannerFilterPage title="Quantum Risk" category="vulnerable" description="Findings with confirmed quantum-vulnerable algorithm usage." />;
      // Stub pages — honestly labeled
      case 'depgraph':   return <StubPage title="Dependency Graph" description="Visual dependency graph is not yet implemented." />;
      case 'pqcrecs':    return <PQCRecommendations />;
      case 'hybridmig':  return <HybridMigration />;
      default:            return <Dashboard />;
    }
  };

  if (currentPage === 'landing') {
    return <><QuantumCursor /><Landing /><LoginModal /></>;
  }

  return (
    <div className="app-shell">
      <QuantumCursor />
      <DashboardBackground />
      <CommandPalette />
      <LoginModal />
      <Sidebar />
      <main className="main-content">
        <Topbar />
        <div className="page-content">
          {renderPage()}
        </div>
      </main>
    </div>
  );
}

// ─── P1-14: App with Router ─────────────────────────────────
// BrowserRouter wraps the app so every page gets a real URL.
// RouteSync keeps the Zustand store in sync with the URL.

export default function AppWithRouter() {
  return (
    <BrowserRouter>
      <RouteSync />
      <App />
    </BrowserRouter>
  );
}
