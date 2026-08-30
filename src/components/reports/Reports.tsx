// ============================================================
// Qrypto AI Advisor — §33 Reports Page
//
// Buttons:
//   Generate Executive Report
//   Generate Technical Report
//   Export Findings
//
// Executive report sections:
//   Overall Readiness · Critical Risks · Business Impact
//   Top Recommendations · Migration Timeline
//
// Technical report sections:
//   Every finding · File/line · Evidence · Algorithm · Risk · Recommendation
// ============================================================

import React, { useState } from 'react';
import {
  FileText, Download, Shield, AlertTriangle, CheckCircle2, XCircle,
  Clock, Briefcase, TrendingUp, ListChecks, BookOpen, Cpu
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import { generateCBOM, serializeCBOM } from '../../engine/cbom';
import { generatePDFReport } from '../../engine/pdfReport';
import './Reports.css';

// ─── NIST PQC Compliance Controls ─────────────────────────────

const NIST_CONTROLS = [
  {
    id: 'PQC-1', title: 'Cryptographic Inventory',
    desc: 'All cryptographic assets identified and cataloged in a CBOM.',
    getStatus: (a: any) => a.findings.length > 0 ? 'compliant' : 'not-assessed',
  },
  {
    id: 'PQC-2', title: 'Quantum-Vulnerable Algorithm Identification',
    desc: 'RSA, ECC, ECDH, ECDSA, DSA, DH identified and flagged.',
    getStatus: (a: any) => a.findings.some((f: any) => f.quantumStatus === 'vulnerable') ? 'partial' : 'compliant',
  },
  {
    id: 'PQC-3', title: 'Hardcoded Secret Elimination',
    desc: 'No cryptographic secrets stored in source code.',
    getStatus: (a: any) => {
      const secrets = a.findings.filter((f: any) => f.category === 'secret' && f.remediationStatus === 'open');
      return secrets.length === 0 ? 'compliant' : 'non-compliant';
    },
  },
  {
    id: 'PQC-4', title: 'Legacy Algorithm Deprecation',
    desc: 'MD5, SHA-1, DES, 3DES, SSL/TLS 1.0/1.1 eliminated.',
    getStatus: (a: any) => {
      const legacy = a.findings.filter((f: any) => f.classicalStatus === 'broken' && f.remediationStatus === 'open');
      return legacy.length === 0 ? 'compliant' : 'non-compliant';
    },
  },
  {
    id: 'PQC-5', title: 'Post-Quantum Migration Plan',
    desc: 'Documented migration roadmap aligned with NIST FIPS 203/204/205.',
    getStatus: (a: any) => a.migrationTasks.length > 0 ? 'compliant' : 'partial',
  },
  {
    id: 'PQC-6', title: 'Crypto-Agility Architecture',
    desc: 'Cryptographic algorithms are replaceable without major refactoring.',
    getStatus: (a: any) =>
      a.cryptoAgilityScore && a.cryptoAgilityScore.score >= 70 ? 'compliant' :
      a.cryptoAgilityScore && a.cryptoAgilityScore.score >= 40 ? 'partial' : 'non-compliant',
  },
  {
    id: 'PQC-7', title: 'HNDL Risk Assessment',
    desc: 'Harvest-Now-Decrypt-Later risk evaluated for long-lived data.',
    getStatus: (a: any) => a.hndlAssessments.length > 0 ? 'compliant' : 'partial',
  },
  {
    id: 'PQC-8', title: 'TLS Configuration Hardening',
    desc: 'TLS 1.3 preferred; deprecated ciphers and protocol versions removed.',
    getStatus: (a: any) => {
      const tlsIssues = a.findings.filter((f: any) => f.category === 'tls' && f.remediationStatus === 'open');
      return tlsIssues.length === 0 ? 'compliant' : 'partial';
    },
  },
];

// ─── Sub-components ────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cfg: Record<string, { icon: any; color: string; label: string }> = {
    'compliant':     { icon: CheckCircle2,  color: '#4CAF6D', label: 'Compliant' },
    'partial':       { icon: Clock,         color: '#F5B84D', label: 'Partial' },
    'non-compliant': { icon: XCircle,       color: '#F5484B', label: 'Non-Compliant' },
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

// ─── Report View Types ─────────────────────────────────────────

type ReportView = 'overview' | 'executive' | 'technical';

// ─── Executive Report Component ────────────────────────────────

function ExecutiveReport({ assessment }: { assessment: any }) {
  const { findings, scanStats, quantumReadinessScore, migrationTasks, cryptoAgilityScore } = assessment;

  const criticals = findings.filter((f: any) => f.severity === 'critical');
  const vulnerables = findings.filter((f: any) => f.quantumStatus === 'vulnerable');
  const secretFindings = findings.filter((f: any) => f.category === 'secret');
  const doneTasks = migrationTasks.filter((t: any) => t.status === 'done').length;
  const migProgress = Math.round((doneTasks / Math.max(migrationTasks.length, 1)) * 100);

  // Business impact estimation
  const affectedServicesSet = new Set(criticals.map((f: any) => f.service));
  const affectedServices = Array.from(affectedServicesSet);

  // Top Recommendations
  const recommendations = [
    criticals.length > 0 && `Immediately address ${criticals.length} critical cryptographic vulnerabilities — most in ${criticals[0]?.service}`,
    vulnerables.length > 0 && `Initiate PQC migration for ${vulnerables.length} quantum-vulnerable assets before the quantum computing horizon (~2029–2035)`,
    secretFindings.length > 0 && `Rotate ${secretFindings.length} exposed credential(s) and adopt a centralized secrets manager (e.g. HashiCorp Vault)`,
    cryptoAgilityScore && cryptoAgilityScore.score < 70 && `Improve crypto-agility score from ${cryptoAgilityScore.score} to 70+ by centralizing algorithm configuration`,
    `Deploy hybrid key encapsulation (X25519 + ML-KEM-768) on all internet-facing payment and authentication endpoints`,
  ].filter(Boolean) as string[];

  return (
    <div className="report-view executive-view animate-fade-in" id="executive-report-content">
      {/* Overall Readiness */}
      <div className="report-section">
        <h3 className="section-heading">
          <Shield size={18} style={{ display: 'inline', marginRight: 8, verticalAlign: 'middle' }} />
          Overall Quantum Readiness
        </h3>
        <div className="exec-readiness-block">
          <div className="erb-score-col">
            <div className="erb-score" style={{ color: scoreToColor(quantumReadinessScore) }}>
              {quantumReadinessScore}
              <span className="erb-unit">/100</span>
            </div>
            <div className="erb-grade" style={{ color: scoreToColor(quantumReadinessScore) }}>
              {quantumReadinessScore >= 80 ? 'GOOD' : quantumReadinessScore >= 60 ? 'AT RISK' : 'CRITICAL'}
            </div>
            <p className="erb-desc">
              {quantumReadinessScore >= 80
                ? 'Your codebase is well-positioned for the quantum transition. Monitor for new algorithm deprecations.'
                : quantumReadinessScore >= 60
                ? 'Moderate quantum risk. Key systems remain vulnerable to future quantum attacks. Migration plan is underway.'
                : 'Significant quantum exposure. Immediate action required across multiple services before Q-Day.'}
            </p>
          </div>
          <div className="erb-stats-col">
            {[
              { label: 'Total Findings', value: findings.length, color: 'var(--text-primary)' },
              { label: 'Critical', value: scanStats.criticalCount, color: '#F5484B' },
              { label: 'Quantum-Vulnerable', value: vulnerables.length, color: '#FF8A3D' },
              { label: 'Files Scanned', value: scanStats.filesScanned, color: '#4DD0E1' },
              { label: 'Migration Progress', value: `${migProgress}%`, color: '#4CAF6D' },
            ].map((item, i) => (
              <div key={i} className="erb-stat">
                <span className="erb-stat-val" style={{ color: item.color }}>{item.value}</span>
                <span className="erb-stat-lbl">{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Critical Risks */}
      <div className="report-section">
        <h3 className="section-heading">
          <AlertTriangle size={18} style={{ display: 'inline', marginRight: 8, verticalAlign: 'middle' }} />
          Critical Risks
        </h3>
        <div className="card">
          <table className="data-table">
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Algorithm</th>
                <th>Service</th>
                <th>Quantum Risk</th>
                <th>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {criticals.slice(0, 8).map((f: any) => (
                <tr key={f.id}>
                  <td className="mono" style={{ color: '#4DD0E1' }}>{f.id}</td>
                  <td style={{ fontWeight: 700 }}>{f.algorithm}</td>
                  <td style={{ color: '#94a3b8' }}>{f.service}</td>
                  <td>
                    <span className={`quantum-badge qb-${f.quantumStatus}`}>{f.quantumStatus.replace(/-/g, ' ')}</span>
                  </td>
                  <td>
                    <span style={{ color: scoreToColor(f.riskScore), fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                      {f.riskScore}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Business Impact */}
      <div className="report-section">
        <h3 className="section-heading">
          <Briefcase size={18} style={{ display: 'inline', marginRight: 8, verticalAlign: 'middle' }} />
          Business Impact
        </h3>
        <div className="impact-grid">
          <div className="card impact-card">
            <div className="impact-icon" style={{ background: 'rgba(245, 72, 75,0.1)', color: '#F5484B' }}>
              <AlertTriangle size={20} />
            </div>
            <div>
              <h4>Immediate Risk</h4>
              <p>
                {affectedServices.length} business-critical service(s) contain cryptographic vulnerabilities that
                can be exploited using currently available compute (classical attacks): {affectedServices.slice(0, 3).join(', ')}.
              </p>
            </div>
          </div>
          <div className="card impact-card">
            <div className="impact-icon" style={{ background: 'rgba(255, 138, 61,0.1)', color: '#FF8A3D' }}>
              <Cpu size={20} />
            </div>
            <div>
              <h4>Quantum Horizon Risk (2029–2035)</h4>
              <p>
                {vulnerables.length} asset(s) using RSA, ECC, or ECDH are vulnerable to Shor's algorithm.
                HNDL (Harvest-Now-Decrypt-Later) attacks are already a present threat for data with long retention periods.
              </p>
            </div>
          </div>
          <div className="card impact-card">
            <div className="impact-icon" style={{ background: 'rgba(245, 184, 77,0.1)', color: '#F5B84D' }}>
              <Shield size={20} />
            </div>
            <div>
              <h4>Compliance & Regulatory</h4>
              <p>
                NIST released FIPS 203/204/205 in 2024. Federal agencies and regulated sectors face
                migration deadlines. Delayed action increases compliance exposure.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Top Recommendations */}
      <div className="report-section">
        <h3 className="section-heading">
          <ListChecks size={18} style={{ display: 'inline', marginRight: 8, verticalAlign: 'middle' }} />
          Top Recommendations
        </h3>
        <div className="card recs-card">
          {recommendations.map((rec, i) => (
            <div key={i} className="exec-rec-item">
              <div className="exec-rec-num">{i + 1}</div>
              <p>{rec}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Migration Timeline */}
      <div className="report-section">
        <h3 className="section-heading">
          <TrendingUp size={18} style={{ display: 'inline', marginRight: 8, verticalAlign: 'middle' }} />
          Migration Timeline
        </h3>
        <div className="timeline-grid">
          {[
            { phase: 'Phase 1', label: 'Immediate (0–30 days)', color: '#F5484B', items: ['Remove hardcoded secrets', 'Deprecate MD5 / SHA-1', 'Fix TLS 1.0/1.1 endpoints'] },
            { phase: 'Phase 2', label: 'Short-Term (1–6 months)', color: '#FF8A3D', items: ['Deploy hybrid ML-KEM on payment/auth', 'Rotate exposed certificates', 'Adopt secrets manager'] },
            { phase: 'Phase 3', label: 'Medium-Term (6–18 months)', color: '#F5B84D', items: ['Full PQC migration for internal services', 'Transition JWT signing to ML-DSA', 'Update TLS cipher suites'] },
            { phase: 'Phase 4', label: 'Long-Term (18+ months)', color: '#4CAF6D', items: ['CA infrastructure migration', 'Crypto-agility framework deployment', 'Dependency audit & PQC library adoption'] },
          ].map((ph, i) => (
            <div key={i} className="timeline-card card" style={{ borderTopColor: ph.color }}>
              <div className="tc-phase" style={{ background: ph.color }}>{ph.phase}</div>
              <div className="tc-label">{ph.label}</div>
              <ul className="tc-items">
                {ph.items.map((item, j) => (
                  <li key={j}>{item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Technical Report Component ────────────────────────────────

function TechnicalReport({ assessment }: { assessment: any }) {
  const { findings } = assessment;
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  const filtered = filterSeverity === 'all'
    ? findings
    : findings.filter((f: any) => f.severity === filterSeverity);

  return (
    <div className="report-view technical-view animate-fade-in" id="technical-report-content">
      <div className="tech-toolbar">
        <div className="tech-toolbar-left">
          <BookOpen size={16} />
          <span>All Findings — {filtered.length} of {findings.length} shown</span>
        </div>
        <select
          className="input filter-select-sm"
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value)}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      <div className="card tech-table-wrapper">
        <table className="data-table tech-findings-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>File / Line</th>
              <th>Algorithm</th>
              <th>Evidence</th>
              <th>Risk Score</th>
              <th>Quantum Status</th>
              <th>Severity</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f: any) => (
              <tr key={f.id} className={`tech-row sev-${f.severity}`}>
                <td className="mono" style={{ color: '#4DD0E1', whiteSpace: 'nowrap' }}>{f.id}</td>
                <td>
                  <div className="tech-file">{f.file}</div>
                  <div className="tech-line">Line {f.line}</div>
                </td>
                <td style={{ fontWeight: 700, whiteSpace: 'nowrap' }}>{f.algorithm}</td>
                <td>
                  <div className="tech-evidence-box">
                    <code>{f.detectedPattern}</code>
                  </div>
                </td>
                <td>
                  <span style={{ color: scoreToColor(f.riskScore), fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                    {f.riskScore}
                  </span>
                </td>
                <td>
                  <span className={`quantum-badge qb-${f.quantumStatus}`}>{f.quantumStatus.replace(/-/g, ' ')}</span>
                </td>
                <td>
                  <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                </td>
                <td>
                  <div className="tech-rec">{f.recommendedAlgorithm}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Main Reports Component ────────────────────────────────────

export function Reports() {
  const { assessment, setCurrentPage } = useAppStore();
  const [view, setView] = useState<ReportView>('overview');
  const [exportDone, setExportDone] = useState(false);

  if (!assessment) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">📄</div>
        <h2>No Assessment Loaded</h2>
        <p>Run a cryptographic scan on your uploaded files to generate a report.</p>
        <button className="btn btn-primary" onClick={() => setCurrentPage('landing')}>
          Go to Home
        </button>
      </div>
    );
  }

  const { findings, scanStats, quantumReadinessScore, migrationTasks, cryptoAgilityScore } = assessment;

  const vulnCount = findings.filter((f: any) => f.quantumStatus === 'vulnerable').length;
  const classicWeakCount = findings.filter((f: any) => f.classicalStatus === 'broken' || f.classicalStatus === 'weak').length;
  const pqcCount = findings.filter((f: any) => f.quantumStatus === 'quantum-resistant').length;
  const openFindings = findings.filter((f: any) => f.remediationStatus === 'open').length;
  const remediatedFindings = findings.filter((f: any) => f.remediationStatus === 'remediated').length;

  const algoCounts: Record<string, { count: number; risk: string }> = {};
  findings.forEach((f: any) => {
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

  const [pdfGenerating, setPdfGenerating] = useState(false);

  const buildPDFData = () => ({
    projectName: assessment.name,
    organization: assessment.organization,
    scannedAt: assessment.scannedAt ?? assessment.createdAt,
    quantumReadinessScore,
    findings,
    migrationTasks,
    cryptoAgilityScore,
    hndlAssessments: assessment.hndlAssessments ?? [],
    scanStats,
  });

  const handleExportPDF = async (type: 'executive' | 'technical' | 'developer') => {
    setPdfGenerating(true);
    try {
      const blob = await generatePDFReport(buildPDFData(), type);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `qrypto-${type}-report-${assessment.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('PDF generation failed:', err);
    } finally {
      setPdfGenerating(false);
    }
  };

  const handleExportCBOM = () => {
    const bom = generateCBOM(findings, { projectName: assessment.name, toolVersion: '2.0.0' });
    const json = serializeCBOM(bom);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom-${assessment.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setExportDone(true);
    setTimeout(() => setExportDone(false), 3000);
  };

  const handleExportJSON = () => {
    const report = {
      generatedAt: new Date().toISOString(),
      organization: assessment.organization,
      project: assessment.name,
      quantumReadinessScore,
      scanStats,
      findings: findings.map((f: any) => ({
        id: f.id, file: f.file, line: f.line, algorithm: f.algorithm,
        detectedPattern: f.detectedPattern, service: f.service,
        quantumStatus: f.quantumStatus, severity: f.severity, riskScore: f.riskScore,
        recommendedAlgorithm: f.recommendedAlgorithm, migrationStrategy: f.migrationStrategy,
      })),
      compliance: controls.map(c => ({ id: c.id, title: c.title, status: c.status })),
      migrationTasks: migrationTasks.length,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Qrypto-findings-${assessment.organization.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.json`;
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
          <div className="rh-icon">
            <FileText size={22} />
          </div>
          <div>
            <h2>Quantum Readiness Report</h2>
            <p>{assessment.organization} · {assessment.name} · Generated {new Date().toLocaleDateString()}</p>
          </div>
        </div>

        {/* §33 Three action buttons */}
        <div className="rh-actions">
          <button
            id="btn-executive-report"
            className={`btn ${view === 'executive' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setView(view === 'executive' ? 'overview' : 'executive')}
          >
            <Briefcase size={15} />
            {view === 'executive' ? 'Hide Executive Report' : 'Generate Executive Report'}
          </button>
          <button
            id="btn-technical-report"
            className={`btn ${view === 'technical' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setView(view === 'technical' ? 'overview' : 'technical')}
          >
            <BookOpen size={15} />
            {view === 'technical' ? 'Hide Technical Report' : 'Generate Technical Report'}
          </button>
          <button
            id="btn-export-pdf-exec"
            className="btn btn-ghost"
            onClick={() => handleExportPDF('executive')}
            disabled={pdfGenerating}
            title="Download Executive PDF Report"
          >
            <FileText size={15} />
            {pdfGenerating ? 'Generating...' : 'PDF Executive'}
          </button>
          <button
            id="btn-export-pdf-tech"
            className="btn btn-ghost"
            onClick={() => handleExportPDF('technical')}
            disabled={pdfGenerating}
            title="Download Technical PDF Report"
          >
            <BookOpen size={15} />
            {pdfGenerating ? 'Generating...' : 'PDF Technical'}
          </button>
          <button
            id="btn-export-pdf-dev"
            className="btn btn-ghost"
            onClick={() => handleExportPDF('developer')}
            disabled={pdfGenerating}
            title="Download Developer Remediation PDF"
          >
            <BookOpen size={15} />
            {pdfGenerating ? 'Generating...' : 'PDF Developer'}
          </button>
          <button
            id="btn-export-cbom"
            className="btn btn-ghost"
            onClick={handleExportCBOM}
            title="Export as CycloneDX 1.6 CBOM (Cryptographic Bill of Materials)"
          >
            <Cpu size={15} />
            Export CBOM
          </button>
          <button
            id="btn-export-findings"
            className="btn btn-ghost"
            onClick={handleExportJSON}
          >
            {exportDone
              ? <><CheckCircle2 size={15} /> Exported</>
              : <><Download size={15} /> Export JSON</>}
          </button>
        </div>
      </div>

      {/* Executive or Technical Report Views */}
      {view === 'executive' && <ExecutiveReport assessment={assessment} />}
      {view === 'technical' && <TechnicalReport assessment={assessment} />}

      {/* Overview (default) */}
      {view === 'overview' && (
        <>
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
                <span className="exec-val" style={{ color: '#F5484B' }}>{scanStats.criticalCount}</span>
                <span className="exec-lbl">Critical Findings</span>
                <span className="exec-sub">{openFindings} open · {remediatedFindings} remediated</span>
              </div>
              <div className="exec-card">
                <span className="exec-val" style={{ color: '#FF8A3D' }}>{vulnCount}</span>
                <span className="exec-lbl">Quantum-Vulnerable Assets</span>
                <span className="exec-sub">Require post-quantum migration</span>
              </div>
              <div className="exec-card">
                <span className="exec-val" style={{ color: '#F5B84D' }}>{classicWeakCount}</span>
                <span className="exec-lbl">Classically Deprecated</span>
                <span className="exec-sub">MD5, SHA-1, TLS 1.0/1.1</span>
              </div>
              <div className="exec-card">
                <span className="exec-val" style={{ color: '#4CAF6D' }}>{pqcCount}</span>
                <span className="exec-lbl">PQC-Ready Findings</span>
                <span className="exec-sub">Already using quantum-resistant crypto</span>
              </div>
              <div className="exec-card">
                <span className="exec-val" style={{ color: '#4DD0E1' }}>{scanStats.filesScanned}</span>
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
                <span style={{ color: '#4CAF6D' }}>{compliantCount} Compliant</span>
                <span style={{ color: '#F5B84D' }}>{partialCount} Partial</span>
                <span style={{ color: '#F5484B' }}>{nonCompliantCount} Non-Compliant</span>
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
                        <span className={`quantum-badge qb-${risk}`}>{risk.replace(/-/g, ' ')}</span>
                      </td>
                      <td>
                        <span style={{
                          color: risk === 'vulnerable' ? '#FF8A3D' :
                                 risk === 'classical-weak' ? '#F5484B' :
                                 risk === 'quantum-resistant' ? '#4CAF6D' : '#3b82f6',
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
                <span className="mig-stat-val" style={{ color: '#4CAF6D' }}>
                  {migrationTasks.filter((t: any) => t.status === 'done').length}
                </span>
                <span className="mig-stat-lbl">Completed</span>
              </div>
              <div className="card mig-stat-card">
                <span className="mig-stat-val" style={{ color: '#F5B84D' }}>
                  {migrationTasks.filter((t: any) => t.status === 'in-progress').length}
                </span>
                <span className="mig-stat-lbl">In Progress</span>
              </div>
              <div className="card mig-stat-card">
                <span className="mig-stat-val" style={{ color: '#F5484B' }}>
                  {migrationTasks.filter((t: any) => t.priority === 'critical' && t.status === 'todo').length}
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
                      <div style={{ color: '#4CAF6D', fontSize: '0.85rem', fontWeight: 600 }}>✓ Strengths</div>
                      {cryptoAgilityScore.positives.slice(0, 3).map((p: string, i: number) => (
                        <div key={i} style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '4px' }}>• {p}</div>
                      ))}
                    </div>
                    <div>
                      <div style={{ color: '#FF8A3D', fontSize: '0.85rem', fontWeight: 600 }}>✗ Gaps</div>
                      {cryptoAgilityScore.negatives.slice(0, 3).map((n: string, i: number) => (
                        <div key={i} style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '4px' }}>• {n}</div>
                      ))}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                    <div style={{ textAlign: 'center', background: 'var(--bg-elevated)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '1.5rem', fontWeight: 800, color: cryptoAgilityScore.hardcodedReferences > 0 ? '#F5484B' : '#4CAF6D' }}>
                        {cryptoAgilityScore.hardcodedReferences}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase' }}>Hardcoded Refs</div>
                    </div>
                    <div style={{ textAlign: 'center', background: 'var(--bg-elevated)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '1.5rem', fontWeight: 800, color: cryptoAgilityScore.directLowLevelCalls > 5 ? '#FF8A3D' : '#4CAF6D' }}>
                        {cryptoAgilityScore.directLowLevelCalls}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase' }}>Low-Level Calls</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* CycloneDX CBOM Compliance */}
          <div className="report-section">
            <h3 className="section-heading">CycloneDX 1.6 CBOM Compliance</h3>
            <div className="card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '24px', flexWrap: 'wrap' }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '2rem', fontWeight: 900, color: '#4DD0E1', fontFamily: 'var(--font-mono)' }}>
                    {topAlgos.length}
                  </div>
                  <div style={{ color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase' }}>Unique Algorithms</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '2rem', fontWeight: 900, color: '#4CAF6D' }}>
                    {findings.length}
                  </div>
                  <div style={{ color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase' }}>CBOM Components</div>
                </div>
                <div style={{ flex: 1, color: '#94a3b8', fontSize: '0.85rem' }}>
                  <p>The Cryptographic Bill of Materials maps every detected algorithm to its CycloneDX 1.6 canonical representation,
                    including NIST OIDs, quantum status, and migration recommendations.</p>
                  <button className="btn btn-ghost btn-sm" onClick={handleExportCBOM} style={{ marginTop: '8px' }}>
                    <Cpu size={14} /> Export CycloneDX CBOM (JSON)
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Disclaimer */}
          <div className="report-disclaimer">
            <Shield size={14} />
            <span>
              This report was generated by Qrypto on {new Date().toLocaleString()}.
              Findings are based on static analysis of detected cryptographic patterns.
              Quantum risk assessments are forward-looking estimates and not predictions.
              All migration recommendations should be validated by qualified security engineers before production deployment.
            </span>
          </div>
        </>
      )}
    </div>
  );
}
