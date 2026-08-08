import React, { useState, useMemo } from 'react';
import { Search, Filter, ChevronDown, ChevronUp, X, Download, ExternalLink } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import type { Finding, AlgorithmCategory, QuantumStatus, Severity } from '../../types';
import './Inventory.css';

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function Inventory() {
  const { assessment, setCurrentPage } = useAppStore();
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [quantumFilter, setQuantumFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [languageFilter, setLanguageFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'riskScore' | 'severity' | 'algorithm' | 'service'>('riskScore');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  if (!assessment) return null;

  const findings = assessment.findings;

  // Filter
  const filtered = useMemo(() => {
    let result = findings;

    if (search) {
      const s = search.toLowerCase();
      result = result.filter(f =>
        f.algorithm.toLowerCase().includes(s) ||
        f.file.toLowerCase().includes(s) ||
        f.service.toLowerCase().includes(s) ||
        f.id.toLowerCase().includes(s) ||
        f.usage.toLowerCase().includes(s)
      );
    }
    if (severityFilter !== 'all') result = result.filter(f => f.severity === severityFilter);
    if (quantumFilter !== 'all') result = result.filter(f => f.quantumStatus === quantumFilter);
    if (categoryFilter !== 'all') result = result.filter(f => f.category === categoryFilter);
    if (languageFilter !== 'all') result = result.filter(f => f.language === languageFilter);

    // Sort
    result = [...result].sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'riskScore') cmp = b.riskScore - a.riskScore;
      if (sortBy === 'severity') cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      if (sortBy === 'algorithm') cmp = a.algorithm.localeCompare(b.algorithm);
      if (sortBy === 'service') cmp = a.service.localeCompare(b.service);
      return sortDir === 'desc' ? cmp : -cmp;
    });

    return result;
  }, [findings, search, severityFilter, quantumFilter, categoryFilter, languageFilter, sortBy, sortDir]);

  const PER_PAGE = 20;
  const paginated = filtered.slice(page * PER_PAGE, (page + 1) * PER_PAGE);
  const totalPages = Math.ceil(filtered.length / PER_PAGE);

  function toggleSort(col: typeof sortBy) {
    if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortBy(col); setSortDir('desc'); }
  }

  function exportCSV() {
    const headers = ['ID', 'Algorithm', 'Key Size', 'File', 'Line', 'Service', 'Language', 'Category', 'Quantum Status', 'Severity', 'Risk Score', 'Remediation Status'];
    const rows = filtered.map(f => [
      f.id, f.algorithm, f.keySize || '', f.file, f.line, f.service, f.language,
      f.category, f.quantumStatus, f.severity, f.riskScore, f.remediationStatus
    ]);
    const csv = [headers, ...rows].map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'quantumguard-cbom.csv'; a.click();
  }

  const uniqueLanguages = [...new Set(findings.map(f => f.language))];
  const uniqueCategories = [...new Set(findings.map(f => f.category))];

  return (
    <div className="inventory animate-fade-in">
      {/* Summary cards */}
      <div className="inv-summary">
        {[
          { label: 'Total Findings', value: findings.length, color: 'var(--accent-cyan)' },
          { label: 'Quantum-Vulnerable', value: findings.filter(f=>f.quantumStatus==='vulnerable').length, color: 'var(--status-high)' },
          { label: 'Classical-Weak', value: findings.filter(f=>f.quantumStatus==='classical-weak').length, color: 'var(--status-critical)' },
          { label: 'PQC / Adequate', value: findings.filter(f=>f.quantumStatus==='quantum-resistant'||f.quantumStatus==='adequate').length, color: 'var(--status-low)' },
          { label: 'Hardcoded Secrets', value: findings.filter(f=>f.category==='secret').length, color: 'var(--status-critical)' },
          { label: 'Filtered Results', value: filtered.length, color: 'var(--text-secondary)' },
        ].map(s => (
          <div key={s.label} className="inv-stat">
            <span className="inv-stat-value" style={{ color: s.color }}>{s.value}</span>
            <span className="inv-stat-label">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="card inv-filters">
        <div className="filter-row">
          <div className="search-box">
            <Search size={14} className="search-icon" />
            <input
              className="input search-input"
              placeholder="Search by algorithm, file, service, or ID..."
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(0); }}
            />
            {search && <button className="search-clear" onClick={() => setSearch('')}><X size={12} /></button>}
          </div>

          <select className="input filter-select" value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(0); }}>
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select className="input filter-select" value={quantumFilter} onChange={e => { setQuantumFilter(e.target.value); setPage(0); }}>
            <option value="all">All Quantum Status</option>
            <option value="vulnerable">Quantum-Vulnerable</option>
            <option value="classical-weak">Classical-Weak</option>
            <option value="adequate">Adequate</option>
            <option value="quantum-resistant">Quantum-Resistant (PQC)</option>
          </select>

          <select className="input filter-select" value={categoryFilter} onChange={e => { setCategoryFilter(e.target.value); setPage(0); }}>
            <option value="all">All Categories</option>
            {uniqueCategories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>

          <select className="input filter-select" value={languageFilter} onChange={e => { setLanguageFilter(e.target.value); setPage(0); }}>
            <option value="all">All Languages</option>
            {uniqueLanguages.map(l => <option key={l} value={l}>{l}</option>)}
          </select>

          <button className="btn btn-ghost btn-sm" onClick={exportCSV}>
            <Download size={14} /> Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="card inv-table-card">
        <table className="data-table inv-table">
          <thead>
            <tr>
              <th style={{ width: 90 }}>ID</th>
              <th onClick={() => toggleSort('algorithm')} className="sortable">
                Algorithm {sortBy === 'algorithm' && (sortDir === 'desc' ? <ChevronDown size={12} /> : <ChevronUp size={12} />)}
              </th>
              <th>Category</th>
              <th>File / Line</th>
              <th onClick={() => toggleSort('service')} className="sortable">
                Service {sortBy === 'service' && (sortDir === 'desc' ? <ChevronDown size={12} /> : <ChevronUp size={12} />)}
              </th>
              <th>Quantum Status</th>
              <th onClick={() => toggleSort('severity')} className="sortable">
                Severity {sortBy === 'severity' && (sortDir === 'desc' ? <ChevronDown size={12} /> : <ChevronUp size={12} />)}
              </th>
              <th onClick={() => toggleSort('riskScore')} className="sortable">
                Risk Score {sortBy === 'riskScore' && (sortDir === 'desc' ? <ChevronDown size={12} /> : <ChevronUp size={12} />)}
              </th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {paginated.map(f => (
              <React.Fragment key={f.id}>
                <tr
                  className={`inv-row ${expanded === f.id ? 'expanded' : ''}`}
                  onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                >
                  <td className="mono" style={{ color: 'var(--text-tertiary)' }}>{f.id}</td>
                  <td>
                    <span style={{ fontWeight: 600 }}>{f.algorithm}</span>
                    {f.keySize && <span style={{ color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>-{f.keySize}</span>}
                  </td>
                  <td>
                    <span className="badge badge-cyan">{f.category}</span>
                  </td>
                  <td className="mono" style={{ maxWidth: 200 }}>
                    <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', display: 'block', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.file.split('/').slice(-2).join('/')}
                    </span>
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>:{f.line}</span>
                  </td>
                  <td>{f.service}</td>
                  <td>
                    <span className={`badge badge-${f.quantumStatus}`}>
                      {f.quantumStatus === 'vulnerable' ? '⚠ Vulnerable' :
                       f.quantumStatus === 'classical-weak' ? '🔴 Classical-Weak' :
                       f.quantumStatus === 'quantum-resistant' ? '✅ PQC' :
                       f.quantumStatus}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div className="progress-bar" style={{ width: 50 }}>
                        <div className="progress-fill" style={{ width: `${f.riskScore}%`, background: scoreToColor(f.riskScore) }} />
                      </div>
                      <span style={{ color: scoreToColor(f.riskScore), fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                        {f.riskScore}
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className={`badge badge-${f.remediationStatus === 'remediated' ? 'low' : f.remediationStatus === 'in-progress' ? 'medium' : 'high'}`}>
                      {f.remediationStatus}
                    </span>
                  </td>
                </tr>
                {expanded === f.id && (
                  <tr className="finding-detail-row">
                    <td colSpan={9}>
                      <FindingDetail finding={f} />
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="empty-state">
            <div className="empty-state-icon">🔍</div>
            <p>No findings match your filters.</p>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="pagination">
            <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</button>
            <span className="page-info">Page {page + 1} of {totalPages} ({filtered.length} findings)</span>
            <button className="btn btn-ghost btn-sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>Next</button>
          </div>
        )}
      </div>
    </div>
  );
}

function FindingDetail({ finding: f }: { finding: Finding }) {
  const { updateFindingStatus } = useAppStore();

  return (
    <div className="finding-detail">
      <div className="fd-grid">
        <div className="fd-section">
          <h4 className="fd-section-title">Detection Context</h4>
          <div className="fd-rows">
            <FDRow label="Usage" value={f.usage} />
            <FDRow label="Detected Pattern" value={<code className="mono" style={{ background: '#0d1525', padding: '2px 8px', borderRadius: 4, fontSize: '0.8rem' }}>{f.detectedPattern}</code>} />
            <FDRow label="Language" value={f.language} />
            <FDRow label="Confidence" value={`${Math.round(f.confidence * 100)}%`} />
            <FDRow label="Internet Facing" value={f.internetFacing ? '⚠ Yes' : 'No'} />
            <FDRow label="Hardcoded" value={f.isHardcoded ? '⚠ Yes' : 'No'} />
          </div>
        </div>

        <div className="fd-section">
          <h4 className="fd-section-title">Risk Breakdown</h4>
          <div className="risk-breakdown-detail">
            {[
              { label: 'Algorithm Risk (×30%)', val: f.riskBreakdown.algorithmRisk, max: 100 },
              { label: 'Business Criticality (×20%)', val: f.riskBreakdown.businessCriticality, max: 100 },
              { label: 'Internet Exposure (×15%)', val: f.riskBreakdown.internetExposure, max: 100 },
              { label: 'Data Lifetime (×15%)', val: f.riskBreakdown.dataLifetime, max: 100 },
              { label: 'Data Sensitivity (×10%)', val: f.riskBreakdown.dataSensitivity, max: 100 },
              { label: 'Migration Difficulty (×10%)', val: f.riskBreakdown.migrationDifficulty, max: 100 },
            ].map(r => (
              <div key={r.label} className="risk-bar-item">
                <span className="risk-bar-label">{r.label}</span>
                <div className="progress-bar" style={{ flex: 1 }}>
                  <div className="progress-fill" style={{ width: `${r.val}%`, background: scoreToColor(r.val) }} />
                </div>
                <span className="risk-bar-value">{r.val}/100</span>
              </div>
            ))}
            <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid var(--border-default)', display: 'flex', justifyContent: 'space-between' }}>
              <strong style={{ color: 'var(--text-secondary)' }}>Total Risk Score</strong>
              <strong style={{ color: scoreToColor(f.riskScore), fontFamily: 'var(--font-mono)', fontSize: '1rem' }}>{f.riskScore} / 100</strong>
            </div>
          </div>
        </div>

        <div className="fd-section">
          <h4 className="fd-section-title">Migration Guidance</h4>
          <div className="fd-rows">
            <FDRow label="Recommended" value={f.recommendedAlgorithm || '—'} />
            <FDRow label="Strategy" value={f.migrationStrategy || '—'} />
          </div>
          <div style={{ marginTop: 'var(--space-3)' }}>
            <h4 className="fd-section-title">Update Status</h4>
            <select
              className="input"
              value={f.remediationStatus}
              onChange={e => updateFindingStatus(f.id, e.target.value as any)}
              style={{ marginTop: 'var(--space-2)' }}
            >
              <option value="open">Open</option>
              <option value="in-progress">In Progress</option>
              <option value="remediated">Remediated</option>
              <option value="accepted-risk">Accepted Risk</option>
              <option value="wont-fix">Won't Fix</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}

function FDRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="fd-row">
      <span className="fd-label">{label}</span>
      <span className="fd-value">{value}</span>
    </div>
  );
}
