// ============================================================
// QuantumGuard AI — Reports Page
//
// §26 Navigation: Reports
// Provides executive summary, compliance checklist,
// findings breakdown, and JSON export.
// §21 Error handling: gracefully handles missing assessment.
// ============================================================

import React, { useState } from 'react';
import { FileText, Download, Shield, AlertTriangle, CheckCircle2, XCircle, Clock, BarChart2 } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import './Reports.css';

const NIST_CONTROLS = [
  {
    id: 'PQC-1',
    title: 'Cryptographic Inventory',
    desc: 'All cryptographic assets identified and cataloged in a CBOM.',
    getStatus: (a: any) => a.findings.length > 0 ? 'compliant' : 'not-assessed',
  },
  {
    id: 'PQC-2',
    title: 'Quantum-Vulnerable Algorithm Identification',
    desc: 'RSA, ECC, ECDH, ECDSA, DSA, DH identified and flagged.',
    getStatus: (a: any) => a.findings.some((f: any) => f.quantumStatus === 'vulnerable') ? 'partial' : 'compliant',
  },
  {
    id: 'PQC-3',
    title: 'Hardcoded Secret Elimination',
    desc: 'No cryptographic secrets stored in source code.',
    getStatus: (a: any) => {
      const secrets = a.findings.filter((f: any) => f.category === 'secret' && f.remediationStatus === 'open');
      return secrets.length === 0 ? 'compliant' : 'non-compliant';
    },
  },
  {
    id: 'PQC-4',
    title: 'Legacy Algorithm Deprecation',
    desc: 'MD5, SHA-1, DES, 3DES, SSL/TLS 1.0/1.1 eliminated.',
    getStatus: (a: any) => {
      const legacy = a.findings.filter((f: any) => f.classicalStatus === 'broken' && f.remediationStatus === 'open');
      return legacy.length === 0 ? 'compliant' : 'non-compliant';
    },
  },
  {
    id: 'PQC-5',
    title: 'Post-Quantum Migration Plan',
    desc: 'Documented migration roadmap aligned with NIST FIPS 203/204/205.',
    getStatus: (a: any) => a.migrationTasks.length > 0 ? 'compliant' : 'partial',
  },
  {
    id: 'PQC-6',
    title: 'Crypto-Agility Architecture',
    desc: 'Cryptographic algorithms are replaceable without major refactoring.',
    getStatus: (a: any) => a.cryptoAgilityScore && a.cryptoAgilityScore.score >= 70 ? 'compliant' :
      a.cryptoAgilityScore && a.cryptoAgilityScore.score >= 40 ? 'partial' : 'non-compliant',
  },
  {
    id: 'PQC-7',
    title: 'HNDL Risk Assessment',
    desc: 'Harvest-Now-Decrypt-Later risk evaluated for long-lived data.',
    getStatus: (a: any) => a.hndlAssessments.length > 0 ? 'compliant' : 'partial',
  },
  {
    id: 'PQC-8',
    title: 'TLS Configuration Hardening',
    desc: 'TLS 1.3 preferred; deprecated ciphers and protocol versions removed.',
    getStatus: (a: any) => {
      const tlsIssues = a.findings.filter((f: any) => f.category === 'tls' && f.remediationStatus === 'open');
      return tlsIssues.length === 0 ? 'compliant' : 'partial';
    },
  },
];

function StatusBadge({ status }: { status: string }) {
  const cfg: Record<string, { icon: any; color: string; label: string }> = {
    'compliant':     { icon: CheckCircle2, color: '#22c55e', label: 'Compliant' },
    'partial':       { icon: Clock,        color: '#eab308', label: 'Partial' },
    'non-compliant': { icon: XCircle,      color: '#ef4444', label: 'Non-Compliant' },
    'not-assessed':  { icon: AlertTriangle, color: '#64748b', label: 'Not Assessed' },
  };
  const c = cfg[status] ?? cfg['not-assessed'];
  const Icon = c.icon;
  return (
    <span className="report-status-badge" style={{ color: c.color, borderColor: `${c.color}33`, background: `${c.color}11` }}>
      <Icon size={12} />
      {c.label}
    </span>
  );
}

export function Reports() {
  const { assessment, setCurrentPage } = useAppStore();
  const [exportDone, setExportDone] = useState(false);

  // §21 graceful empty state
  if (!assessment) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">📄</div>
        <h2>No Assessment Loaded</h2>
        <p>Load a demo or run a scan to generate a report.</p>
        <button className="btn btn-primary" onClick={() => setCurrentPage('landing')}>
          Go to Home
        </button>
      </div>
    );
  }

  const { findings, scanStats, quantumReadinessScore, migrationTasks, cryptoAgilityScore } = assessment;

  const vulnCount = findings.filter(f => f.quantumStatus === 'vulnerable').length;
  const classicWeakCount = findings.filter(f => f.classicalStatus === 'broken' || f.classicalStatus === 'weak').length;
  const pqcCount = findings.filter(f => f.quantumStatus === 'quantum-resistant').length;
  const openFindings = findings.filter(f => f.remediationStatus === 'open').length;
  const remediatedFindings = findings.filter(f => f.remediationStatus === 'remediated').length;

  const algoCounts: Record<string, { count: number; risk: string }> = {};
  findings.forEach(f => {
    if (!algoCounts[f.algorithm]) algoCounts[f.algorithm] = { count: 0, risk: f.quantumStatus };
    algoCounts[f.algorithm].count++;
  });
  const topAlgos = Object.entries(algoCounts).sort((a, b) => b[1].count - a[1].count).slice(0, 10);

  const controls = NIST_CONTROLS.map(ctrl => ({
    ...ctrl,
    status: ctrl.getStatus(assessment),
  }));
  const compliantCount = controls.filter(c => c.status === 'compliant').length;
  const partialCount = controls.filter(c => c.status === 'partial').length;
  const nonCompliantCount = controls.filter(c => c.status === 'non-compliant').length;

  const handleExport = () => {
    const report = {
      generatedAt: new Date().toISOString(),
      organization: assessment.organization,
      project: assessment.name,
      quantumReadinessScore,
      scanStats,
      topFindings: findings.filter(f => f.severity === 'critical').slice(0, 10).map(f => ({
        id: f.id, algorithm: f.algorithm, file: f.file, line: f.line,
        service: f.service, quantumStatus: f.quantumStatus, riskScore: f.riskScore,
      })),
      compliance: controls.map(c => ({ id: c.id, title: c.title, status: c.status })),
      migrationTasks: migrationTasks.length,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `quantumguard-report-${assessment.organization.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setExportDone(true);
    setTimeout(() => setExportDone(false), 3000);
  };

  return (
    <div className="reports-page animate-fade-in">
      {/* Header */}
      <div className="reports-header">
        <div className="rh-left">
          <FileText size={24} className="rh-icon" />
          <div>
            <h2>Quantum Readiness Report</h2>
            <p>{assessment.organization} · {assessment.name} · Generated {new Date().toLocaleDateString()}</p>
          </div>
        </div>
        <button className="btn btn-primary" onClick={handleExport}>
          {exportDone ? <><CheckCircle2 size={15} /> Exported</> : <><Download size={15} /> Export JSON</>}
        </button>
      </div>

      {/* Executive Summary */}
      <div className="report-section">
        <h3 className="section-heading">Executive Summary</h3>
        <div className="exec-summary-grid">
          <div className="exec-card readiness-exec" style={{ borderColor: `${scoreToColor(quantumReadinessScore)}44` }}>
            <span className="exec-val" style={{ color: scoreToColor(quantumReadinessScore) }}>
              {quantumReadinessScore}<span className="exec-unit">/100</span>
            </span>
            <span className="exec-lbl">Quantum Readiness Score</span>
            <span className="exec-sub" style={{ color: scoreToColor(quantumReadinessScore) }}>
              {quantumReadinessScore >= 80 ? 'Good' : quantumReadinessScore >= 60 ? 'Moderate Risk' : 'High Risk'}
            </span>
          </div>
          <div className="exec-card">
            <span className="exec-val" style={{ color: '#ef4444' }}>{scanStats.criticalCount}</span>
            <span className="exec-lbl">Critical Findings</span>
            <span className="exec-sub">{openFindings} open · {remediatedFindings} remediated</span>
          </div>
          <div className="exec-card">
            <span className="exec-val" style={{ color: '#f97316' }}>{vulnCount}</span>
            <span className="exec-lbl">Quantum-Vulnerable Assets</span>
            <span className="exec-sub">Require post-quantum migration</span>
          </div>
          <div className="exec-card">
            <span className="exec-val" style={{ color: '#eab308' }}>{classicWeakCount}</span>
            <span className="exec-lbl">Classically Deprecated</span>
            <span className="exec-sub">MD5, SHA-1, TLS 1.0/1.1</span>
          </div>
          <div className="exec-card">
            <span className="exec-val" style={{ color: '#22c55e' }}>{pqcCount}</span>
            <span className="exec-lbl">PQC-Ready Findings</span>
            <span className="exec-sub">Already using quantum-resistant crypto</span>
          </div>
          <div className="exec-card">
            <span className="exec-val" style={{ color: '#00d4ff' }}>{scanStats.filesScanned}</span>
            <span className="exec-lbl">Files Scanned</span>
            <span className="exec-sub">{scanStats.linesScanned.toLocaleString()} lines of code</span>
          </div>
        </div>
      </div>

      {/* NIST PQC Compliance Checklist */}
      <div className="report-section">
        <div className="section-heading-row">
          <h3 className="section-heading">NIST PQC Readiness Checklist</h3>
          <div className="compliance-summary">
            <span style={{ color: '#22c55e' }}>{compliantCount} Compliant</span>
            <span style={{ color: '#eab308' }}>{partialCount} Partial</span>
            <span style={{ color: '#ef4444' }}>{nonCompliantCount} Non-Compliant</span>
          </div>
        </div>
        <div className="card compliance-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Control ID</th>
                <th>Control</th>
                <th>Description</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {controls.map(ctrl => (
                <tr key={ctrl.id}>
                  <td className="mono">{ctrl.id}</td>
                  <td style={{ fontWeight: 600 }}>{ctrl.title}</td>
                  <td style={{ color: '#94a3b8', fontSize: '0.875rem' }}>{ctrl.desc}</td>
                  <td><StatusBadge status={ctrl.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Algorithm Breakdown */}
      <div className="report-section">
        <h3 className="section-heading">Cryptographic Algorithm Inventory</h3>
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Occurrences</th>
                <th>Quantum Status</th>
                <th>Risk Level</th>
              </tr>
            </thead>
            <tbody>
              {topAlgos.map(([algo, { count, risk }]) => (
                <tr key={algo}>
                  <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{algo}</td>
                  <td style={{ color: '#94a3b8' }}>{count}</td>
                  <td>
                    <span className={`quantum-badge qb-${risk}`}>{risk.replace('-', ' ')}</span>
                  </td>
                  <td>
                    <span style={{
                      color: risk === 'vulnerable' ? '#f97316' :
                             risk === 'classical-weak' ? '#ef4444' :
                             risk === 'quantum-resistant' ? '#22c55e' : '#3b82f6',
                      fontWeight: 600, fontSize: '0.875rem'
                    }}>
                      {risk === 'vulnerable' ? 'HIGH' :
                       risk === 'classical-weak' ? 'CRITICAL' :
                       risk === 'quantum-resistant' ? 'MINIMAL' : 'LOW'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Migration Progress */}
      <div className="report-section">
        <h3 className="section-heading">Migration Plan Overview</h3>
        <div className="migration-summary-grid">
          <div className="card mig-stat-card">
            <span className="mig-stat-val">{migrationTasks.length}</span>
            <span className="mig-stat-lbl">Total Migration Tasks</span>
          </div>
          <div className="card mig-stat-card">
            <span className="mig-stat-val" style={{ color: '#22c55e' }}>
              {migrationTasks.filter(t => t.status === 'done').length}
            </span>
            <span className="mig-stat-lbl">Completed</span>
          </div>
          <div className="card mig-stat-card">
            <span className="mig-stat-val" style={{ color: '#eab308' }}>
              {migrationTasks.filter(t => t.status === 'in-progress').length}
            </span>
            <span className="mig-stat-lbl">In Progress</span>
          </div>
          <div className="card mig-stat-card">
            <span className="mig-stat-val" style={{ color: '#ef4444' }}>
              {migrationTasks.filter(t => t.priority === 'critical' && t.status === 'todo').length}
            </span>
            <span className="mig-stat-lbl">Critical / Pending</span>
          </div>
        </div>
        <div style={{ marginTop: '16px' }}>
          <button className="btn btn-ghost" onClick={() => setCurrentPage('migration')}>
            View Full Migration Roadmap →
          </button>
        </div>
      </div>

      {/* Crypto Agility */}
      {cryptoAgilityScore && (
        <div className="report-section">
          <h3 className="section-heading">Crypto Agility Assessment</h3>
          <div className="card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '24px', flexWrap: 'wrap' }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '3rem', fontWeight: 900, color: scoreToColor(cryptoAgilityScore.score), fontFamily: 'var(--font-mono)' }}>
                  {cryptoAgilityScore.score}
                </div>
                <div style={{ color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase' }}>Agility Score / 100</div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ color: '#22c55e', fontSize: '0.85rem', fontWeight: 600 }}>✓ Strengths</div>
                  {cryptoAgilityScore.positives.slice(0, 3).map((p, i) => (
                    <div key={i} style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '4px' }}>• {p}</div>
                  ))}
                </div>
                <div>
                  <div style={{ color: '#f97316', fontSize: '0.85rem', fontWeight: 600 }}>✗ Gaps</div>
                  {cryptoAgilityScore.negatives.slice(0, 3).map((n, i) => (
                    <div key={i} style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '4px' }}>• {n}</div>
                  ))}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                <div style={{ textAlign: 'center', background: 'var(--bg-elevated)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: 800, color: cryptoAgilityScore.hardcodedReferences > 0 ? '#ef4444' : '#22c55e' }}>
                    {cryptoAgilityScore.hardcodedReferences}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase' }}>Hardcoded Refs</div>
                </div>
                <div style={{ textAlign: 'center', background: 'var(--bg-elevated)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: 800, color: cryptoAgilityScore.directLowLevelCalls > 5 ? '#f97316' : '#22c55e' }}>
                    {cryptoAgilityScore.directLowLevelCalls}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase' }}>Low-Level Calls</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Disclaimer */}
      <div className="report-disclaimer">
        <Shield size={14} />
        <span>
          This report was generated by QuantumGuard AI on {new Date().toLocaleString()}.
          Findings are based on static analysis of detected cryptographic patterns.
          Quantum risk assessments are forward-looking estimates and not predictions.
          All migration recommendations should be validated by qualified security engineers before production deployment.
          No customer data is included in this report.
        </span>
      </div>
    </div>
  );
}
