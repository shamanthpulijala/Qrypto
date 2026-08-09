import React from 'react';
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
import { useAppStore } from './store/assessmentStore';

function App() {
  const { currentPage, assessment, isScanning, scanError } = useAppStore();

  const renderPage = () => {
    // Pages that don't require an assessment
    if (currentPage === 'landing') return <Landing />;
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
          <h2>No Assessment Loaded</h2>
          <p>Return to the landing page to load a demo or start a new scan.</p>
          <button className="btn btn-primary mt-4" onClick={() => useAppStore.getState().setCurrentPage('landing')}>
            Go to Home
          </button>
        </div>
      );
    }

    switch (currentPage) {
      case 'dashboard': return <Dashboard />;
      case 'inventory': return <Inventory />;
      case 'findings': return <FindingsList />;
      case 'qday': return <QDaySimulator />;
      case 'attackmap': return <AttackMap />;
      case 'hndl': return <HNDLAnalyzer />;
      case 'migration': return <MigrationPlanner />;
      case 'agility': return <CryptoAgility />;
      case 'ai': return <AIAdvisor />;
      case 'reports': return <Reports />;
      case 'compliance':
        return (
          <div className="empty-state">
            <div className="empty-state-icon">🚧</div>
            <h2>Coming Soon</h2>
            <p>Compliance mapping module is currently in development.</p>
          </div>
        );
      default:
        return <Dashboard />;
    }
  };

  if (currentPage === 'landing') {
    return <><QuantumCursor /><Landing /></>;
  }

  return (
    <div className="app-shell">
      <QuantumCursor />
      <DashboardBackground />
      <CommandPalette />
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

export default App;
