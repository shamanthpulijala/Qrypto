import React, { useState, useEffect } from 'react';
import {
  AlertTriangle, Shield, Key, Lock, TrendingUp, Zap,
  Activity, BarChart2, ChevronRight, ArrowUpRight, CheckCircle
} from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, RadialBarChart, RadialBar, Legend, LineChart, Line
} from 'recharts';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import './Dashboard.css';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#94a3b8',
};

const QUANTUM_STATUS_COLORS: Record<string, string> = {
  vulnerable:         '#f97316',
  'classical-weak':   '#ef4444',
  adequate:           '#3b82f6',
  'quantum-resistant': '#22c55e',
  unknown:            '#94a3b8',
};

function ReadinessGauge({ score }: { score: number }) {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setAnimated(score), 200);
    return () => clearTimeout(timer);
  }, [score]);

  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animated / 100) * circumference * 0.75;
  const color = score >= 70 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444';

  return (
    <div className="readiness-gauge">
      <div className="gauge-container">
        <svg viewBox="0 0 180 180" className="gauge-svg">
          {/* Background arc */}
          <circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke="#1e2d4a"
            strokeWidth="12"
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeDashoffset={circumference * 0.125}
            strokeLinecap="round"
            transform="rotate(135 90 90)"
          />
          {/* Score arc */}
          <circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeDasharray={`${(animated / 100) * circumference * 0.75} ${circumference}`}
            strokeLinecap="round"
            transform="rotate(135 90 90)"
            style={{ transition: 'stroke-dasharray 1.5s ease, stroke 0.5s ease', filter: `drop-shadow(0 0 8px ${color}55)` }}
          />
          {/* Center text */}
          <text x="90" y="82" textAnchor="middle" fill={color} fontSize="36" fontWeight="800" fontFamily="Inter">
            {animated}
          </text>
          <text x="90" y="102" textAnchor="middle" fill="#94a3b8" fontSize="11" fontFamily="Inter">
            / 100
          </text>
          <text x="90" y="118" textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="Inter">
            QUANTUM READINESS
          </text>
        </svg>
      </div>
    </div>
  );
}

export function Dashboard() {
  const { assessment, readinessBreakdown, runQDaySimulation, qdayActive, resetQDaySimulation, setCurrentPage } = useAppStore();

  if (!assessment) return null;

  const { findings, scanStats, quantumReadinessScore } = assessment;

  // Severity distribution for pie chart
  const severityData = [
    { name: 'Critical', value: scanStats.criticalCount, color: '#ef4444' },
    { name: 'High',     value: scanStats.highCount,     color: '#f97316' },
    { name: 'Medium',   value: scanStats.mediumCount,   color: '#eab308' },
    { name: 'Low/Info', value: scanStats.lowCount,      color: '#22c55e' },
  ].filter(d => d.value > 0);

  // Algorithm distribution
  const algoCounts: Record<string, { count: number; color: string }> = {};
  findings.forEach(f => {
    if (!algoCounts[f.algorithm]) {
      algoCounts[f.algorithm] = { count: 0, color: QUANTUM_STATUS_COLORS[f.quantumStatus] || '#94a3b8' };
    }
    algoCounts[f.algorithm].count++;
  });
  const algoData = Object.entries(algoCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 8)
    .map(([name, { count, color }]) => ({ name, count, color }));

  // Top critical findings
  const topFindings = [...findings]
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5);

  // Service risk
  const serviceRisk = assessment.services
    .filter(s => s.id !== 'internet')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 6);

  // Readiness breakdown
  const rb = readinessBreakdown;

  return (
    <div className="dashboard animate-fade-in">
      {/* Top Row */}
      <div className="dashboard-top">
        {/* Readiness Gauge Card */}
        <div className="card readiness-card">
          <ReadinessGauge score={quantumReadinessScore} />
          <div className="readiness-breakdown">
            {rb && Object.entries({
              'Cryptographic Inventory': rb.cryptographicInventory,
              'Legacy Crypto':           rb.legacyCrypto,
              'PQC Migration':           rb.pqcMigration,
              'Crypto Agility':          rb.cryptoAgility,
              'Secret Management':       rb.secretManagement,
              'TLS Posture':             rb.tlsPosture,
              'Certificate Posture':     rb.certificatePosture,
            }).map(([label, score]) => (
              <div key={label} className="rb-row">
                <span className="rb-label">{label}</span>
                <div className="rb-bar">
                  <div
                    className="rb-fill"
                    style={{
                      width: `${score}%`,
                      background: score >= 70 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444',
                    }}
                  />
                </div>
                <span className="rb-value" style={{ color: score >= 70 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444' }}>
                  {score}%
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Stat Cards */}
        <div className="dashboard-stats">
          <div className="stat-card critical-card" onClick={() => setCurrentPage('findings')}>
            <div className="stat-icon"><AlertTriangle size={20} /></div>
            <div className="stat-value" style={{ color: '#ef4444' }}>{scanStats.criticalCount}</div>
            <div className="stat-label">Critical Findings</div>
            <div className="stat-action"><ChevronRight size={14} /></div>
          </div>

          <div className="stat-card" onClick={() => setCurrentPage('inventory')}>
            <div className="stat-icon"><Shield size={20} /></div>
            <div className="stat-value" style={{ color: '#f97316' }}>{scanStats.vulnerableAlgorithms}</div>
            <div className="stat-label">Quantum-Vulnerable Assets</div>
            <div className="stat-action"><ChevronRight size={14} /></div>
          </div>

          <div className="stat-card" onClick={() => setCurrentPage('findings')}>
            <div className="stat-icon"><Activity size={20} /></div>
            <div className="stat-value" style={{ color: '#eab308' }}>
              {findings.filter(f => f.quantumStatus === 'classical-weak').length}
            </div>
            <div className="stat-label">Weak/Legacy Crypto</div>
            <div className="stat-action"><ChevronRight size={14} /></div>
          </div>

          <div className="stat-card" onClick={() => setCurrentPage('findings')}>
            <div className="stat-icon"><Key size={20} /></div>
            <div className="stat-value" style={{ color: '#ef4444' }}>{scanStats.secretsFound}</div>
            <div className="stat-label">Hardcoded Secrets</div>
            <div className="stat-action"><ChevronRight size={14} /></div>
          </div>

          <div className="stat-card" onClick={() => setCurrentPage('migration')}>
            <div className="stat-icon"><TrendingUp size={20} /></div>
            <div className="stat-value" style={{ color: '#22c55e' }}>
              {Math.round((findings.filter(f => f.remediationStatus === 'remediated' || f.quantumStatus === 'quantum-resistant').length / findings.length) * 100)}%
            </div>
            <div className="stat-label">PQC Migration Progress</div>
            <div className="stat-action"><ChevronRight size={14} /></div>
          </div>

          <div className="stat-card" onClick={() => setCurrentPage('inventory')}>
            <div className="stat-icon"><Lock size={20} /></div>
            <div className="stat-value" style={{ color: '#00d4ff' }}>{scanStats.findingsTotal}</div>
            <div className="stat-label">Total Findings</div>
            <div className="stat-action"><ChevronRight size={14} /></div>
          </div>
        </div>
      </div>

      {/* Q-Day Button */}
      <div className="qday-section">
        <div className="qday-content">
          <div>
            <h3 className="qday-title">Q-Day Scenario Simulator</h3>
            <p className="qday-desc">
              Simulate your organization's exposure if cryptographically relevant quantum capabilities threatened current public-key cryptography.
            </p>
          </div>
          <button
            className={`btn btn-qday ${qdayActive ? 'active' : ''}`}
            onClick={qdayActive ? resetQDaySimulation : runQDaySimulation}
          >
            {qdayActive ? '🔴 RESET SIMULATION' : '⚡ SIMULATE Q-DAY'}
          </button>
        </div>

        {qdayActive && assessment.qDaySimulation && (
          <div className="qday-results animate-fade-in">
            <div className="scenario-label">
              <span>⚠️</span> SCENARIO MODEL — NOT A PREDICTION
            </div>
            <div className="qday-impact-grid">
              <div className="qday-impact-item">
                <span className="qi-value danger">{assessment.qDaySimulation.vulnerableFindings.length}</span>
                <span className="qi-label">Quantum-Vulnerable Assets</span>
              </div>
              <div className="qday-impact-item">
                <span className="qi-value warn">{assessment.qDaySimulation.affectedServices.length}</span>
                <span className="qi-label">Potentially Affected Services</span>
              </div>
              <div className="qday-impact-item">
                <span className="qi-value danger">{assessment.qDaySimulation.hndlExposure.toUpperCase()}</span>
                <span className="qi-label">Simulated HNDL Exposure</span>
              </div>
              <div className="qday-impact-item">
                <span className="qi-value" style={{ color: '#f97316' }}>
                  {assessment.qDaySimulation.beforeReadiness} → {assessment.qDaySimulation.afterReadiness}
                </span>
                <span className="qi-label">Readiness Score Impact</span>
              </div>
            </div>
            <p className="qday-narrative">{assessment.qDaySimulation.simulatedBusinessImpact}</p>
            <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
              <button className="btn btn-ghost btn-sm" onClick={() => setCurrentPage('qday')}>
                View Full Simulation <ArrowUpRight size={12} />
              </button>
              <button className="btn btn-ghost btn-sm" onClick={() => setCurrentPage('attackmap')}>
                View Attack Map <ArrowUpRight size={12} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Charts Row */}
      <div className="charts-row">
        {/* Severity Distribution */}
        <div className="card chart-card">
          <div className="card-header">
            <span className="card-title">Risk Distribution</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid #1e2d4a', borderRadius: '8px', color: '#f1f5f9', fontSize: '12px' }}
              />
              <Legend iconSize={10} wrapperStyle={{ fontSize: '12px', color: '#94a3b8' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Algorithm Breakdown */}
        <div className="card chart-card wide">
          <div className="card-header">
            <span className="card-title">Top Detected Algorithms</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={algoData} layout="vertical" margin={{ left: 20, right: 20 }}>
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} width={80} />
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid #1e2d4a', borderRadius: '8px', color: '#f1f5f9', fontSize: '12px' }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {algoData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Service Risk */}
        <div className="card chart-card">
          <div className="card-header">
            <span className="card-title">Service Risk</span>
          </div>
          <div className="service-risk-list">
            {serviceRisk.map(svc => (
              <div key={svc.id} className="srv-row">
                <span className="srv-name">{svc.name}</span>
                <div className="srv-bar-container">
                  <div className="progress-bar" style={{ flex: 1 }}>
                    <div className="progress-fill" style={{ width: `${svc.riskScore}%`, background: scoreToColor(svc.riskScore) }} />
                  </div>
                </div>
                <span className="srv-score" style={{ color: scoreToColor(svc.riskScore) }}>{svc.riskScore}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Critical Findings */}
      <div className="card mt-4">
        <div className="card-header">
          <span className="card-title">Top Priority Findings</span>
          <button className="btn btn-ghost btn-sm" onClick={() => setCurrentPage('findings')}>View All</button>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Algorithm</th>
              <th>File</th>
              <th>Service</th>
              <th>Quantum Status</th>
              <th>Risk Score</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {topFindings.map(f => (
              <tr key={f.id}>
                <td className="mono">{f.id}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    <span style={{ fontWeight: 600 }}>{f.algorithm}{f.keySize ? `-${f.keySize}` : ''}</span>
                  </div>
                </td>
                <td className="mono" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {f.file.split('/').slice(-2).join('/')}:{f.line}
                </td>
                <td>{f.service}</td>
                <td>
                  <span className={`badge badge-${f.quantumStatus.replace('-', '-')}`}>
                    {f.quantumStatus === 'vulnerable' ? '⚠ Quantum-Vulnerable' :
                     f.quantumStatus === 'classical-weak' ? '🔴 Classical-Weak' :
                     f.quantumStatus === 'quantum-resistant' ? '✅ PQC' : f.quantumStatus}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div className="progress-bar" style={{ width: 60 }}>
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
