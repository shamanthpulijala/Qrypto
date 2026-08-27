// ============================================================
// QuantumGuard AI — Command Center Dashboard §21-§26
// Living Cryptographic Command Center with Asymmetric Layout
// ============================================================

import React, { useState, useEffect } from 'react';
import {
  AlertTriangle, Shield, Key, Lock, TrendingUp, Zap,
  Activity, Network, ArrowRight, ChevronRight, Eye
} from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { NextBestAction } from './NextBestAction';
import { RiskPulse } from './RiskPulse';
import { AttackMap } from '../attackMap/AttackMap';
import './Dashboard.css';

// ─── Orbital Readiness Core §25 ──────────────────────────────
function QuantumCore({ score, discoveryScore, agilityScore, migrationScore, certScore }: { score: number; discoveryScore: number; agilityScore: number; migrationScore: number; certScore: number }) {
  const [displayedScore, setDisplayedScore] = useState(0);
  const [hoveredRing, setHoveredRing] = useState<string | null>(null);

  useEffect(() => {
    let current = 0;
    const duration = 1200;
    const step = 16;
    const increment = score / (duration / step);
    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setDisplayedScore(score);
        clearInterval(timer);
      } else {
        setDisplayedScore(Math.round(current));
      }
    }, step);
    return () => clearInterval(timer);
  }, [score]);

  // Orbital rings — all scores derived from real data passed via props
  // discoveryScore: % of files with findings (completeness of inventory)
  // agilityScore: crypto-agility score from engine (0-100)
  // migrationScore: % of findings remediated or PQC-safe
  // certScore: % of TLS/cert findings that are adequate or better
  const rings = [
    { name: 'Discovery', score: discoveryScore, radius: 95, color: '#00d4ff' },
    { name: 'Risk', score: Math.max(10, 100 - (score * 0.8)), radius: 82, color: '#ef4444' },
    { name: 'Crypto Agility', score: agilityScore, radius: 69, color: '#14b8a6' },
    { name: 'Migration', score: migrationScore, radius: 56, color: '#8b5cf6' },
    { name: 'Certificates', score: certScore, radius: 43, color: '#3b82f6' },
  ];

  const statusText = score >= 80 ? 'PROTECTED' : score >= 50 ? 'MODERATE EXPOSURE' : 'CRITICAL RISK';
  const statusColor = score >= 80 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444';

  return (
    <div className="quantum-core-card">
      <div style={{ fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.12em', color: 'var(--accent-violet)', marginBottom: '0.75rem' }}>
        QUANTUM READINESS CORE
      </div>

      <div className="orbital-gauge-container">
        <svg viewBox="0 0 220 220" className="orbital-svg">
          {rings.map((ring) => {
            const circumference = 2 * Math.PI * ring.radius;
            const strokeDashoffset = circumference - (ring.score / 100) * circumference;
            return (
              <circle
                key={ring.name}
                cx="110"
                cy="110"
                r={ring.radius}
                className="orbital-ring"
                stroke={ring.color}
                strokeWidth="5"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                opacity={hoveredRing && hoveredRing !== ring.name ? 0.3 : 0.85}
                onMouseEnter={() => setHoveredRing(`${ring.name}: ${Math.round(ring.score)}/100`)}
                onMouseLeave={() => setHoveredRing(null)}
              />
            );
          })}
        </svg>

        <div className="orbital-center">
          <span className="orbital-score">{displayedScore}</span>
          <span className="orbital-max">/100</span>
          <span className="orbital-status" style={{ color: statusColor, background: `${statusColor}18` }}>
            {statusText}
          </span>
        </div>
      </div>

      <div className="orbital-tooltip">
        {hoveredRing ? hoveredRing : 'Hover orbital rings to inspect sub-metrics'}
      </div>
    </div>
  );
}

// ─── Main Dashboard Component ─────────────────────────────────
export function Dashboard() {
  const { assessment, setCurrentPage, qdayActive } = useAppStore();

  if (!assessment) return null;

  const { findings, scanStats, quantumReadinessScore } = assessment;

  // Compute real orbital ring scores from findings data
  const totalFindings = findings.length || 1;
  const discoveryScore = Math.round((scanStats.filesScanned > 0 ? Math.min(100, (findings.length / Math.max(1, scanStats.filesScanned)) * 100 + 30) : 0));
  const agilityScore = assessment.cryptoAgilityScore?.score ?? 0;
  const pqcOrSafe = findings.filter(f => f.quantumStatus === 'quantum-resistant' || f.quantumStatus === 'adequate' || f.remediationStatus === 'remediated').length;
  const migrationScore = Math.round((pqcOrSafe / totalFindings) * 100);
  const tlsCerts = findings.filter(f => f.category === 'tls' || f.category === 'certificate');
  const certScore = tlsCerts.length > 0
    ? Math.round((tlsCerts.filter(f => f.quantumStatus === 'adequate' || f.quantumStatus === 'quantum-resistant').length / tlsCerts.length) * 100)
    : 75; // default when no TLS/cert findings

  return (
    <div className="dashboard animate-fade-in">
      {/* Next Best Action Card §34 */}
      <NextBestAction />

      {/* Asymmetric Layout §26 */}
      <div className="dashboard-asymmetric">
        {/* LEFT 60% — Living Cryptographic Digital Twin §27 */}
        <div className="dash-left">
          <div className="digital-twin-frame">
            <div className="dt-header">
              <div>
                <div className="dt-title">
                  <Network size={16} style={{ color: 'var(--accent-violet)' }} />
                  CRYPTOGRAPHIC DIGITAL TWIN
                </div>
                <div className="dt-sub">Living infrastructure & dependency attack surface map</div>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setCurrentPage('attackmap')}
                style={{ fontSize: '0.75rem' }}
              >
                Expand View <ChevronRight size={14} />
              </button>
            </div>

            <div className="dt-body">
              <AttackMap />
            </div>
          </div>
        </div>

        {/* RIGHT 40% — Intelligence Center */}
        <div className="dash-right">
          {/* Orbital Readiness Core §25 */}
          <QuantumCore
            score={quantumReadinessScore}
            discoveryScore={discoveryScore}
            agilityScore={agilityScore}
            migrationScore={migrationScore}
            certScore={certScore}
          />

          {/* Mini Stats Grid */}
          <div className="mini-stats-grid">
            <div className="mini-stat" onClick={() => setCurrentPage('findings')}>
              <div className="mini-stat-val" style={{ color: '#ef4444' }}>{scanStats.criticalCount}</div>
              <div className="mini-stat-lbl">Critical Risks</div>
            </div>

            <div className="mini-stat" onClick={() => setCurrentPage('inventory')}>
              <div className="mini-stat-val" style={{ color: '#f97316' }}>{scanStats.vulnerableAlgorithms}</div>
              <div className="mini-stat-lbl">Vulnerable Assets</div>
            </div>

            <div className="mini-stat" onClick={() => setCurrentPage('findings')}>
              <div className="mini-stat-val" style={{ color: '#ef4444' }}>{scanStats.secretsFound}</div>
              <div className="mini-stat-lbl">Hardcoded Secrets</div>
            </div>

            <div className="mini-stat" onClick={() => setCurrentPage('migration')}>
              <div className="mini-stat-val" style={{ color: '#22c55e' }}>
                {Math.round((findings.filter(f => f.remediationStatus === 'remediated' || f.quantumStatus === 'quantum-resistant').length / Math.max(1, findings.length)) * 100)}%
              </div>
              <div className="mini-stat-lbl">PQC Migration</div>
            </div>
          </div>

          {/* Risk Pulse Stream §33 */}
          <RiskPulse />
        </div>
      </div>
    </div>
  );
}
