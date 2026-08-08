import React, { useState } from 'react';
import { Map, Flag, CheckCircle, Circle, ChevronDown, ChevronUp, Bot, ExternalLink, Calendar, GitBranch } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import './MigrationPlanner.css';

export function MigrationPlanner() {
  const { assessment, setCurrentPage, qdayActive } = useAppStore();
  const [expandedPhase, setExpandedPhase] = useState<number>(0);

  if (!assessment) return null;

  const { migrationRoadmap } = assessment;

  return (
    <div className="migration-planner animate-fade-in">
      <div className="mp-header">
        <div className="mph-left">
          <Map size={24} className="mph-icon" />
          <div>
            <h2>PQC Migration Roadmap</h2>
            <p>Prioritized action plan based on business criticality, quantum risk, and implementation difficulty.</p>
          </div>
        </div>
        <div className="mph-right">
          {qdayActive && (
            <div className="qday-badge-warning">
              Q-Day Scenario constraints are active. Prioritization adjusted for rapid risk mitigation.
            </div>
          )}
        </div>
      </div>

      <div className="mp-layout">
        {/* Roadmap Timeline */}
        <div className="roadmap-container">
          {migrationRoadmap.map((phase, i) => (
            <div key={phase.phase} className={`phase-card ${expandedPhase === i ? 'expanded' : ''}`}>
              <div className="phase-header" onClick={() => setExpandedPhase(expandedPhase === i ? -1 : i)}>
                <div className="phase-h-left">
                  <div className="phase-num">Phase {i + 1}</div>
                  <div>
                    <h3 className="phase-title">{phase.phase}</h3>
                    <p className="phase-desc">{phase.description}</p>
                  </div>
                </div>
                <div className="phase-h-right">
                  <div className="phase-metrics">
                    <span className="pm-label">Findings</span>
                    <span className="pm-val">{phase.findings.length}</span>
                  </div>
                  <div className="phase-metrics">
                    <span className="pm-label">Est. Effort</span>
                    <span className="pm-val" style={{ color: phase.estimatedEffortHours > 100 ? '#f97316' : '#22c55e' }}>
                      {phase.estimatedEffortHours}h
                    </span>
                  </div>
                  {expandedPhase === i ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                </div>
              </div>

              {expandedPhase === i && (
                <div className="phase-body animate-fade-in">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Algorithm</th>
                        <th>Service</th>
                        <th>Risk Score</th>
                        <th>Diff. Score</th>
                        <th>Recommended Target</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {phase.findings.map(f => (
                        <tr key={f.id}>
                          <td className="mono">{f.id}</td>
                          <td>
                            <span className={`badge badge-${f.severity}`}>{f.algorithm}</span>
                          </td>
                          <td>{f.service}</td>
                          <td>
                            <span style={{ color: scoreToColor(f.riskScore), fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                              {f.riskScore}
                            </span>
                          </td>
                          <td>
                            <span style={{ color: scoreToColor(f.riskBreakdown.migrationDifficulty), fontFamily: 'var(--font-mono)' }}>
                              {f.riskBreakdown.migrationDifficulty}
                            </span>
                          </td>
                          <td>
                            {f.recommendedAlgorithm ? (
                              <span className="badge badge-cyan">{f.recommendedAlgorithm}</span>
                            ) : (
                              <span className="text-secondary">—</span>
                            )}
                          </td>
                          <td>
                            <button className="btn btn-ghost btn-sm" onClick={() => setCurrentPage('ai')}>
                              <Bot size={14} /> AI Remediate
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Info Sidebar */}
        <div className="mp-sidebar">
          <div className="card info-card-pqc">
            <h4 className="ic-title">NIST PQC Standards Overview</h4>
            <div className="ic-content">
              <div className="ic-item">
                <span className="ic-name">FIPS 203 (ML-KEM)</span>
                <span className="ic-desc">Key Encapsulation Mechanism. Replaces RSA key transport & ECDH.</span>
              </div>
              <div className="ic-item">
                <span className="ic-name">FIPS 204 (ML-DSA)</span>
                <span className="ic-desc">Digital Signature Algorithm. Replaces RSA signatures, ECDSA. Primary signature standard.</span>
              </div>
              <div className="ic-item">
                <span className="ic-name">FIPS 205 (SLH-DSA)</span>
                <span className="ic-desc">Stateless Hash-based DSA. Fallback standard if lattice-based math is broken.</span>
              </div>
            </div>
          </div>
          
          <div className="card metrics-card">
             <h4>Migration Metrics</h4>
             <div className="metrics-grid">
               <div className="metric">
                 <span className="metric-val">{assessment.findings.length}</span>
                 <span className="metric-lbl">Total Tasks</span>
               </div>
               <div className="metric">
                 <span className="metric-val">{migrationRoadmap.reduce((acc, p) => acc + p.estimatedEffortHours, 0)}h</span>
                 <span className="metric-lbl">Total Effort</span>
               </div>
               <div className="metric">
                 <span className="metric-val">{migrationRoadmap.length}</span>
                 <span className="metric-lbl">Phases</span>
               </div>
             </div>
             <button className="btn btn-primary w-full mt-4">
               <GitBranch size={16} /> Export to Jira
             </button>
          </div>
        </div>
      </div>
    </div>
  );
}
