import React, { useState, useMemo } from 'react';
import { FolderGit2, X, FileCode2, Search, Filter, ShieldAlert, CheckCircle2, Code, HardDrive, Layers } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import type { ScannedFileDetail } from '../../types';
import './RepositoryDetailModal.css';

interface Props {
  onClose: () => void;
}

export function RepositoryDetailModal({ onClose }: Props) {
  const { assessment, setCurrentPage } = useAppStore();
  const [search, setSearch] = useState('');
  const [langFilter, setLangFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  if (!assessment) return null;

  // Derive file details if not explicitly stored
  const filesList: ScannedFileDetail[] = useMemo(() => {
    if (assessment.scannedFiles && assessment.scannedFiles.length > 0) {
      return assessment.scannedFiles;
    }

    // Fallback: group findings by file if scannedFiles wasn't stored.
    // Do NOT fabricate LOC/size — use the highest finding line as a
    // minimum line count, and leave size as 0 (unknown) rather than inventing numbers.
    const fileMap = new Map<string, ScannedFileDetail>();
    assessment.findings.forEach(f => {
      if (!fileMap.has(f.file)) {
        fileMap.set(f.file, {
          path: f.file,
          lineCount: f.line || 0,
          sizeBytes: 0, // unknown — not fabricated
          language: f.language.toUpperCase(),
          findingsCount: 0,
          criticalCount: 0,
          vulnerableCount: 0,
        });
      }
      const entry = fileMap.get(f.file)!;
      entry.findingsCount++;
      if (f.severity === 'critical') entry.criticalCount++;
      if (f.quantumStatus === 'vulnerable') entry.vulnerableCount++;
    });

    return [...fileMap.values()];
  }, [assessment]);

  // Compute stats
  const totalFiles = assessment.scanStats?.filesScanned || filesList.length;
  const totalLines = assessment.scanStats?.linesScanned || filesList.reduce((s, f) => s + f.lineCount, 0);
  const totalSize = filesList.reduce((s, f) => s + f.sizeBytes, 0);
  const formattedSize = totalSize > 1024 * 1024
    ? `${(totalSize / (1024 * 1024)).toFixed(2)} MB`
    : `${(totalSize / 1024).toFixed(1)} KB`;

  const languages = [...new Set(filesList.map(f => f.language))];

  // Filtered files
  const filtered = useMemo(() => {
    return filesList.filter(f => {
      if (search) {
        const s = search.toLowerCase();
        if (!f.path.toLowerCase().includes(s) && !f.language.toLowerCase().includes(s)) return false;
      }
      if (langFilter !== 'all' && f.language.toLowerCase() !== langFilter.toLowerCase()) return false;
      if (statusFilter === 'vulnerable' && f.vulnerableCount === 0) return false;
      if (statusFilter === 'critical' && f.criticalCount === 0) return false;
      if (statusFilter === 'clean' && f.findingsCount > 0) return false;
      return true;
    }).sort((a, b) => b.findingsCount - a.findingsCount);
  }, [filesList, search, langFilter, statusFilter]);

  return (
    <div className="modal-backdrop animate-fade-in" onClick={onClose}>
      <div className="modal-content repo-detail-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="rdm-header">
          <div className="rdm-title-area">
            <div className="rdm-icon"><FolderGit2 size={22} color="#00d4ff" /></div>
            <div>
              <h2>{assessment.name.replace(' Assessment', '').replace(' Scan', '')} — Uploaded File Details</h2>
              <p className="rdm-subtitle">Scanned Source Code Repository & File Breakdown</p>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose} title="Close">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="rdm-body">
          {/* Summary Stats Grid */}
          <div className="rdm-stats-grid">
            <div className="rdm-stat-card">
              <FileCode2 size={18} className="rdm-stat-icon" color="#00d4ff" />
              <div>
                <span className="rdm-stat-val">{totalFiles}</span>
                <span className="rdm-stat-lbl">Uploaded Files</span>
              </div>
            </div>
            <div className="rdm-stat-card">
              <Code size={18} className="rdm-stat-icon" color="#8b5cf6" />
              <div>
                <span className="rdm-stat-val">{totalLines.toLocaleString()}</span>
                <span className="rdm-stat-lbl">Lines of Code</span>
              </div>
            </div>
            <div className="rdm-stat-card">
              <HardDrive size={18} className="rdm-stat-icon" color="#14b8a6" />
              <div>
                <span className="rdm-stat-val">{formattedSize}</span>
                <span className="rdm-stat-lbl">Repository Size</span>
              </div>
            </div>
            <div className="rdm-stat-card">
              <Layers size={18} className="rdm-stat-icon" color="#eab308" />
              <div>
                <span className="rdm-stat-val">{assessment.findings.length}</span>
                <span className="rdm-stat-lbl">Total Detected Findings</span>
              </div>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="rdm-controls">
            <div className="rdm-search">
              <Search size={14} className="rdm-search-icon" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search uploaded file path..."
              />
              {search && <button className="rdm-clear-search" onClick={() => setSearch('')}><X size={12} /></button>}
            </div>

            <div className="rdm-filters">
              <select value={langFilter} onChange={e => setLangFilter(e.target.value)}>
                <option value="all">All Languages</option>
                {languages.map(l => <option key={l} value={l}>{l}</option>)}
              </select>

              <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
                <option value="all">All File Statuses</option>
                <option value="vulnerable">Quantum-Vulnerable</option>
                <option value="critical">Critical Vulnerabilities</option>
                <option value="clean">Clean (No Findings)</option>
              </select>
            </div>
          </div>

          {/* Files Table */}
          <div className="rdm-table-wrap">
            <table className="rdm-table">
              <thead>
                <tr>
                  <th>File Path</th>
                  <th>Language</th>
                  <th>Lines</th>
                  <th>Size</th>
                  <th>Detected Findings</th>
                  <th>Security Posture</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f, i) => {
                  const sizeStr = f.sizeBytes > 1024 ? `${(f.sizeBytes / 1024).toFixed(1)} KB` : `${f.sizeBytes} B`;
                  return (
                    <tr key={f.path || i}>
                      <td>
                        <div className="rdm-file-cell">
                          <FileCode2 size={15} className="rdm-file-icon" />
                          <span className="rdm-file-path" title={f.path}>{f.path}</span>
                        </div>
                      </td>
                      <td><span className="rdm-lang-badge">{f.language}</span></td>
                      <td className="mono">{f.lineCount}</td>
                      <td className="mono">{sizeStr}</td>
                      <td>
                        {f.findingsCount > 0 ? (
                          <span className="rdm-findings-count">
                            {f.findingsCount} finding{f.findingsCount > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span className="rdm-clean-tag"><CheckCircle2 size={12} /> Clean</span>
                        )}
                      </td>
                      <td>
                        {f.criticalCount > 0 ? (
                          <span className="badge badge-critical">🔴 Critical ({f.criticalCount})</span>
                        ) : f.vulnerableCount > 0 ? (
                          <span className="badge badge-high">⚠️ Quantum-Vulnerable</span>
                        ) : f.findingsCount > 0 ? (
                          <span className="badge badge-medium">🟡 Info / Weak</span>
                        ) : (
                          <span className="badge badge-low">✅ Verified Clean</span>
                        )}
                      </td>
                    </tr>
                  );
                })}

                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '36px', color: '#64748b' }}>
                      No uploaded files match the selected search filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="rdm-footer">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => { onClose(); setCurrentPage('findings'); }}
          >
            View All Scanned Findings →
          </button>
          <button className="btn btn-primary btn-sm" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
