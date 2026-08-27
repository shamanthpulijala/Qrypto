// ============================================================
// QuantumGuard AI — Next Best Action Component §34
// Intelligent, action-oriented primary recommendation card
// ============================================================

import React from 'react';
import { ArrowRight, Sparkles, ShieldAlert } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './NextBestAction.css';

export function NextBestAction() {
  const { assessment, setCurrentPage } = useAppStore();

  if (!assessment) return null;

  // Derive top priority recommendation dynamically from highest risk finding/service
  const criticalFindings = assessment.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
  const topFinding = criticalFindings.sort((a, b) => b.riskScore - a.riskScore)[0] || assessment.findings[0];

  const targetService = topFinding ? topFinding.service : 'Payment API';
  const targetAlgo = topFinding ? topFinding.algorithm : 'RSA-2048';
  const recommendedPQC = topFinding?.recommendedAlgorithm || 'Hybrid ML-KEM';

  return (
    <div className="next-best-action-card">
      <div className="nba-badge">
        <Sparkles size={12} /> NEXT BEST ACTION
      </div>

      <h3 className="nba-title">
        Migrate {targetService} to {recommendedPQC}.
      </h3>

      <div className="nba-grid">
        <div>
          <div className="nba-section-label">WHY THIS MATTERS</div>
          <div className="nba-tags">
            <span className="nba-tag">High Criticality</span>
            {topFinding?.internetFacing && <span className="nba-tag" style={{ color: '#ef4444' }}>Internet Exposed</span>}
            <span className="nba-tag" style={{ color: '#f97316' }}>{targetAlgo} Vulnerable</span>
            <span className="nba-tag">Long-Lived Data</span>
          </div>
        </div>

        <div>
          <div className="nba-section-label">RISK SCORE</div>
          <div className="nba-impact-val" style={{ color: topFinding?.riskScore ? (topFinding.riskScore >= 60 ? '#ef4444' : '#f97316') : undefined }}>
            {topFinding?.riskScore ?? '—'} / 100
          </div>
        </div>

        <div>
          <div className="nba-section-label">PRIORITY</div>
          <div className="nba-effort-val">
            #{topFinding?.migrationPriority ?? '—'}
          </div>
        </div>
      </div>

      <div className="nba-actions">
        <button className="btn-nba" onClick={() => setCurrentPage('migration')}>
          START MIGRATION <ArrowRight size={14} />
        </button>
      </div>
    </div>
  );
}
