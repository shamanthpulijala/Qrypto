// ============================================================
// Qrypto — ScannerFilterPage
//
// Reusable page component for scanner-specific views.
// Filters findings from the current assessment by category.
// Shows real data only — no fabricated findings.
// ============================================================

import React, { useMemo } from 'react';
import { useAppStore } from '../../store/assessmentStore';
import { FindingDetailModal } from '../findings/FindingDetailModal';
import type { Finding } from '../../types';
import { scoreToColor } from '../../engine/riskEngine';

interface Props {
  title: string;
  category: string;
  description: string;
}

export function ScannerFilterPage({ title, category, description }: Props) {
  const { assessment } = useAppStore();
  const [selected, setSelected] = React.useState<Finding | null>(null);

  const findings = useMemo(() => {
    if (!assessment?.findings) return [];
    if (category === 'all') return assessment.findings;
    if (category === 'vulnerable') return assessment.findings.filter(f => f.quantumStatus === 'vulnerable');
    return assessment.findings.filter(f => f.category === category);
  }, [assessment, category]);

  return (
    <div className="page-container">
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '1.6rem', color: 'var(--text-primary)', marginBottom: '6px' }}>{title}</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>{description}</p>
        <div style={{ marginTop: '8px', fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
          {findings.length} finding{findings.length !== 1 ? 's' : ''} found
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">✅</div>
          <h2>No findings in this category</h2>
          <p>
            No <strong>{title.toLowerCase()}</strong> evidence was detected in the current scan.
            This may indicate no usage exists, or no matching files were included in the scan.
          </p>
        </div>
      ) : (
        <div className="findings-list-container">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px', fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>ID</th>
                <th style={{ padding: '10px 12px', fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Algorithm</th>
                <th style={{ padding: '10px 12px', fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>File</th>
                <th style={{ padding: '10px 12px', fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Severity</th>
                <th style={{ padding: '10px 12px', fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Risk</th>
                <th style={{ padding: '10px 12px', fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase' }}>Quantum Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(f => (
                <tr
                  key={f.id}
                  style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer' }}
                  onClick={() => setSelected(f)}
                >
                  <td style={{ padding: '10px 12px', fontSize: '0.78rem', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>{f.id}</td>
                  <td style={{ padding: '10px 12px', fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 }}>{f.algorithm}</td>
                  <td style={{ padding: '10px 12px', fontSize: '0.78rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={`${f.file}:${f.line}`}>{f.file}:{f.line}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: '0.85rem', fontWeight: 700, color: scoreToColor(f.riskScore) }}>{f.riskScore}</td>
                  <td style={{ padding: '10px 12px' }}>
                    <span className={`quantum-badge qb-${f.quantumStatus}`}>{f.quantumStatus}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <FindingDetailModal finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
