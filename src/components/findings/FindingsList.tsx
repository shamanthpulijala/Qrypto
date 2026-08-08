// ============================================================
// QuantumGuard AI — §27 Findings Page
//
// Table columns:
// Severity | Algorithm | Category | Application | File | Line |
// Quantum Risk | Classical Risk | Status | Action
//
// Example:
// CRITICAL | RSA-2048 | Key Establishment | Payment API | auth.py | 83 | High | Low | Open | View
// ============================================================

import React, { useState, useMemo } from 'react';
import { Search, Filter, Eye, Download, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import type { Finding, Severity } from '../../types';
import { FindingDetailModal } from './FindingDetailModal';
import './FindingsList.css';

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function FindingsList() {
  const { assessment, updateFindingStatus } = useAppStore();
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [quantumFilter, setQuantumFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  if (!assessment) return null;

  const findings = assessment.findings;

  const filtered = useMemo(() => {
    let res = findings;

    if (search) {
      const s = search.toLowerCase();
      res = res.filter(f =>
        f.algorithm.toLowerCase().includes(s) ||
        f.file.toLowerCase().includes(s) ||
        f.service.toLowerCase().includes(s) ||
        f.id.toLowerCase().includes(s) ||
        f.usage.toLowerCase().includes(s)
      );
    }

    if (severityFilter !== 'all') res = res.filter(f => f.severity === severityFilter);
    if (quantumFilter !== 'all') res = res.filter(f => f.quantumStatus === quantumFilter);
    if (categoryFilter !== 'all') res = res.filter(f => f.category === categoryFilter);

    return [...res].sort((a, b) => b.riskScore - a.riskScore);
  }, [findings, search, severityFilter, quantumFilter, categoryFilter]);

  const categories = [...new Set(findings.map(f => f.category))];

  function formatQuantumRiskLabel(status: string): string {
    if (status === 'vulnerable') return 'High';
    if (status === 'classical-weak') return 'Moderate';
    if (status === 'adequate') return 'Low';
    if (status === 'quantum-resistant') return 'Minimal';
    return 'Unknown';
  }

  function formatClassicalRiskLabel(status: string): string {
    if (status === 'broken') return 'Critical';
    if (status === 'weak') return 'High';
    if (status === 'adequate') return 'Low';
    if (status === 'strong') return 'Minimal';
    return 'Low';
  }

  return (
    <div className="findings-page animate-fade-in">
      {/* Top Banner Stats */}
      <div className="findings-summary-bar">
        <div className="fs-item">
          <span className="fs-val" style={{ color: 'var(--accent-cyan)' }}>{findings.length}</span>
          <span className="fs-lbl">Total Findings</span>
        </div>
        <div className="fs-item">
          <span className="fs-val" style={{ color: '#ef4444' }}>
            {findings.filter(f => f.severity === 'critical').length}
          </span>
          <span className="fs-lbl">Critical Severity</span>
        </div>
        <div className="fs-item">
          <span className="fs-val" style={{ color: '#f97316' }}>
            {findings.filter(f => f.quantumStatus === 'vulnerable').length}
          </span>
          <span className="fs-lbl">Quantum Vulnerable</span>
        </div>
        <div className="fs-item">
          <span className="fs-val" style={{ color: '#eab308' }}>
            {findings.filter(f => f.classicalStatus === 'broken' || f.classicalStatus === 'weak').length}
          </span>
          <span className="fs-lbl">Classically Deprecated</span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="findings-toolbar">
        <div className="search-box">
          <Search size={16} />
          <input
            type="text"
            placeholder="Search by algorithm, file, service, ID..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="filter-group">
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select value={quantumFilter} onChange={e => setQuantumFilter(e.target.value)}>
            <option value="all">All Quantum Postures</option>
            <option value="vulnerable">Quantum Vulnerable</option>
            <option value="classical-weak">Classical Weak</option>
            <option value="adequate">Adequate</option>
            <option value="quantum-resistant">Quantum Resistant (PQC)</option>
          </select>

          <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}>
            <option value="all">All Categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
      </div>

      {/* Table (§27 Spec Required Columns) */}
      <div className="findings-table-wrapper card">
        <table className="findings-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Algorithm</th>
              <th>Category</th>
              <th>Application</th>
              <th>File</th>
              <th>Line</th>
              <th>Quantum Risk</th>
              <th>Classical Risk</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id} className={`row-severity-${f.severity}`}>
                {/* 1. Severity */}
                <td>
                  <span className={`badge badge-${f.severity}`}>
                    {f.severity.toUpperCase()}
                  </span>
                </td>

                {/* 2. Algorithm */}
                <td>
                  <div className="algo-cell">
                    <strong>{f.algorithm}</strong>
                    {f.keySize && <span className="keysize-tag">{f.keySize}-bit</span>}
                  </div>
                </td>

                {/* 3. Category */}
                <td>
                  <span className="cat-tag">{f.usage || f.category}</span>
                </td>

                {/* 4. Application (Service) */}
                <td>
                  <span className="app-cell">{f.service}</span>
                </td>

                {/* 5. File */}
                <td>
                  <span className="file-cell" title={f.file}>
                    {f.file.split('/').pop()}
                  </span>
                </td>

                {/* 6. Line */}
                <td>
                  <span className="line-cell">{f.line}</span>
                </td>

                {/* 7. Quantum Risk */}
                <td>
                  <span className={`qrisk-tag qr-${formatQuantumRiskLabel(f.quantumStatus).toLowerCase()}`}>
                    {formatQuantumRiskLabel(f.quantumStatus)}
                  </span>
                </td>

                {/* 8. Classical Risk */}
                <td>
                  <span className={`crisk-tag cr-${formatClassicalRiskLabel(f.classicalStatus).toLowerCase()}`}>
                    {formatClassicalRiskLabel(f.classicalStatus)}
                  </span>
                </td>

                {/* 9. Status */}
                <td>
                  <span className={`status-pill status-${f.remediationStatus}`}>
                    {f.remediationStatus}
                  </span>
                </td>

                {/* 10. Action */}
                <td>
                  <button
                    className="btn btn-sm btn-ghost btn-view-action"
                    onClick={() => setSelectedFinding(f)}
                  >
                    <Eye size={13} /> View
                  </button>
                </td>
              </tr>
            ))}

            {filtered.length === 0 && (
              <tr>
                <td colSpan={10} style={{ textAlign: 'center', padding: '40px', color: '#64748b' }}>
                  No findings match the selected filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* §28 Finding Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
