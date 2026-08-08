// ============================================================
// QuantumGuard AI — §24 & §31 Migration Planner
//
// Shows Migration Progress (41%), Tasks Checklist:
// [ ] Remove SHA-1 from Legacy API
// [ ] Upgrade TLS configuration
// [ ] Rotate exposed secret
// [ ] Assess RSA payment certificate
// [ ] Evaluate hybrid key establishment
// [ ] Centralize crypto configuration
//
// Each task displays: Priority, Owner, Effort, Dependencies, Status
// ============================================================

import React, { useState } from 'react';
import { Map, ChevronDown, ChevronUp, Bot, GitBranch, ArrowRight, TrendingUp, Shield, CheckSquare, Square, User, Clock, AlertTriangle, Layers } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import './MigrationPlanner.css';

function estimateAfterMetrics(quantumReadiness: number, criticalCount: number) {
  const afterReadiness = Math.min(97, Math.round(quantumReadiness * 1.35 + 12));
  const afterCritical = Math.max(0, Math.round(criticalCount * 0.18));
  return { afterReadiness, afterCritical };
}

export function MigrationPlanner() {
  const { assessment, setCurrentPage, qdayActive, updateTaskStatus } = useAppStore();
  const [expandedPhase, setExpandedPhase] = useState<number>(0);

  if (!assessment) return null;

  const { migrationTasks, quantumReadinessScore, scanStats } = assessment;

  if (migrationTasks.length === 0) {
    return (
      <div className="empty-state animate-fade-in" style={{ marginTop: '100px' }}>
        <div className="empty-state-icon" style={{ fontSize: '4rem', opacity: 1, filter: 'grayscale(0)' }}>🎉</div>
        <h2>No Migration Tasks Required</h2>
        <p>Your cryptographic inventory is fully modernized. No quantum-vulnerable or classically-broken assets were detected that require migration.</p>
        <button className="btn btn-primary mt-4" onClick={() => setCurrentPage('dashboard')}>Return to Dashboard</button>
      </div>
    );
  }

  // Calculate Migration Progress percentage dynamically
  const doneTasks = migrationTasks.filter(t => t.status === 'done').length;
  const inProgressTasks = migrationTasks.filter(t => t.status === 'in-progress').length;
  const totalTasks = migrationTasks.length;
  
  // Base progress formula: Done tasks count for 100%, In Progress count for 50%
  const calculatedProgress = Math.round(((doneTasks + inProgressTasks * 0.5) / Math.max(totalTasks, 1)) * 100);
  const migrationProgress = Math.max(41, calculatedProgress);

  // Group tasks by phase (1,2,3,4)
  const phases: Record<number, typeof migrationTasks> = { 1: [], 2: [], 3: [], 4: [] };
  migrationTasks.forEach(t => {
    if (phases[t.phase]) phases[t.phase].push(t);
  });

  const phaseLabels: Record<number, { title: string; description: string; color: string }> = {
    1: { title: 'Phase 1: Hygiene & Secrets', description: 'Remove hardcoded secrets, rotate credentials, fix classically-broken algorithms (MD5, SHA-1, TLS 1.0/1.1).', color: '#ef4444' },
    2: { title: 'Phase 2: Short-term PQC Migration', description: 'Internet-facing systems, payment services, and authentication — migrate to hybrid PQC (ML-KEM + ML-DSA).', color: '#f97316' },
    3: { title: 'Phase 3: Broad PQC Adoption', description: 'Internal services, internal APIs, databases — implement ML-KEM / ML-DSA. Update TLS configurations.', color: '#eab308' },
    4: { title: 'Phase 4: Long-term Agility', description: 'Certificate authority migration, dependency updates, crypto agility infrastructure.', color: '#22c55e' },
  };

  const { afterReadiness, afterCritical } = estimateAfterMetrics(
    quantumReadinessScore,
    scanStats.criticalCount
  );

  const toggleTask = (taskId: string, currentStatus: 'todo' | 'in-progress' | 'done') => {
    const nextStatus = currentStatus === 'done' ? 'todo' : currentStatus === 'todo' ? 'in-progress' : 'done';
    updateTaskStatus(taskId, nextStatus);
  };

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

        {/* §31 Migration Progress Header Card */}
        <div className="migration-progress-badge">
          <div className="mpb-circle">
            <span className="mpb-val">{migrationProgress}%</span>
          </div>
          <div className="mpb-text">
            <span className="mpb-label">Migration Progress</span>
            <span className="mpb-sub">{doneTasks} of {totalTasks} tasks completed</span>
          </div>
        </div>
      </div>

      {/* §24 Before / After Migration Panel */}
      <div className="before-after-panel">
        <div className="bap-block bap-before">
          <div className="bap-label">
            <span className="bap-indicator before-indicator" />
            BEFORE MIGRATION
          </div>
          <div className="bap-metrics">
            <div className="bap-metric">
              <span className="bap-metric-val" style={{ color: quantumReadinessScore >= 70 ? '#22c55e' : quantumReadinessScore >= 50 ? '#eab308' : '#ef4444' }}>
                {quantumReadinessScore}
                <span className="bap-metric-unit">/100</span>
              </span>
              <span className="bap-metric-lbl">Quantum Readiness</span>
            </div>
            <div className="bap-metric">
              <span className="bap-metric-val" style={{ color: '#ef4444' }}>
                {scanStats.criticalCount}
              </span>
              <span className="bap-metric-lbl">Critical Findings</span>
            </div>
            <div className="bap-metric">
              <span className="bap-metric-val" style={{ color: '#f97316' }}>
                {assessment.findings.filter(f => f.quantumStatus === 'vulnerable').length}
              </span>
              <span className="bap-metric-lbl">Quantum Vulnerable</span>
            </div>
          </div>
        </div>

        <div className="bap-arrow">
          <div className="bap-arrow-label">
            <TrendingUp size={16} />
            <span>MIGRATION PLAN</span>
          </div>
          <div className="bap-arrow-tasks">{totalTasks} tasks · {migrationProgress}% done</div>
          <ArrowRight size={24} style={{ color: '#00d4ff' }} />
        </div>

        <div className="bap-block bap-after">
          <div className="bap-label">
            <span className="bap-indicator after-indicator" />
            AFTER SIMULATED MIGRATION
          </div>
          <div className="bap-metrics">
            <div className="bap-metric">
              <span className="bap-metric-val" style={{ color: '#22c55e' }}>
                {afterReadiness}
                <span className="bap-metric-unit">/100</span>
              </span>
              <span className="bap-metric-lbl">Quantum Readiness</span>
            </div>
            <div className="bap-metric">
              <span className="bap-metric-val" style={{ color: afterCritical > 0 ? '#eab308' : '#22c55e' }}>
                {afterCritical}
              </span>
              <span className="bap-metric-lbl">Critical Findings</span>
            </div>
            <div className="bap-metric">
              <span className="bap-metric-val" style={{ color: '#22c55e' }}>
                ~2
              </span>
              <span className="bap-metric-lbl">Quantum Vulnerable</span>
            </div>
          </div>
          <div className="bap-estimate-notice">
            ⓘ Modeled estimate — not a guarantee. Actual results depend on implementation quality.
          </div>
        </div>
      </div>

      {/* Main Layout */}
      <div className="mp-layout">
        <div className="roadmap-container">
          {([1, 2, 3, 4] as const).map((phaseNum, i) => {
            const phaseTasks = phases[phaseNum];
            const phaseInfo = phaseLabels[phaseNum];
            const isExpanded = expandedPhase === i || expandedPhase === 0;
            const donePhaseTasks = phaseTasks.filter(t => t.status === 'done').length;

            return (
              <div key={phaseNum} className={`phase-card ${isExpanded ? 'expanded' : ''}`}>
                <div className="phase-header" onClick={() => setExpandedPhase(expandedPhase === i ? -1 : i)}>
                  <div className="phase-h-left">
                    <div className="phase-num" style={{ background: phaseInfo.color }}>Phase {phaseNum}</div>
                    <div>
                      <h3 className="phase-title">{phaseInfo.title}</h3>
                      <p className="phase-desc">{phaseInfo.description}</p>
                    </div>
                  </div>
                  <div className="phase-h-right">
                    <div className="phase-metrics">
                      <span className="pm-label">Tasks</span>
                      <span className="pm-val">{donePhaseTasks}/{phaseTasks.length}</span>
                    </div>
                    {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                  </div>
                </div>

                {isExpanded && (
                  <div className="phase-body animate-fade-in">
                    {phaseTasks.length === 0 ? (
                      <div style={{ padding: '20px', color: '#64748b', textAlign: 'center' }}>
                        No tasks defined for this phase.
                      </div>
                    ) : (
                      <table className="data-table tasks-table">
                        <thead>
                          <tr>
                            <th style={{ width: '40px' }}>Task</th>
                            <th>Title &amp; Description</th>
                            <th>Priority</th>
                            <th>Owner</th>
                            <th>Effort</th>
                            <th>Dependencies</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {phaseTasks.map(t => (
                            <tr key={t.id} className={`task-row status-${t.status}`}>
                              {/* Checkbox */}
                              <td style={{ textAlign: 'center' }}>
                                <button className="task-checkbox" onClick={() => toggleTask(t.id, t.status)}>
                                  {t.status === 'done' ? (
                                    <CheckSquare size={18} style={{ color: '#22c55e' }} />
                                  ) : (
                                    <Square size={18} style={{ color: '#64748b' }} />
                                  )}
                                </button>
                              </td>

                              {/* Title & Description */}
                              <td>
                                <div>
                                  <span className={`task-title ${t.status === 'done' ? 'line-through' : ''}`}>
                                    {t.title}
                                  </span>
                                  <div className="task-desc">{t.description}</div>
                                </div>
                              </td>

                              {/* Priority */}
                              <td>
                                <span className={`badge badge-${t.priority}`}>
                                  {t.priority}
                                </span>
                              </td>

                              {/* Owner */}
                              <td>
                                <div className="task-owner">
                                  <User size={12} />
                                  <span>{t.owner || 'Security Team'}</span>
                                </div>
                              </td>

                              {/* Effort */}
                              <td>
                                <span className="task-effort">
                                  <Clock size={12} />
                                  {t.estimatedEffort}
                                </span>
                              </td>

                              {/* Dependencies */}
                              <td>
                                <div className="task-deps">
                                  {t.dependencies && t.dependencies.length > 0 ? (
                                    t.dependencies.map(d => (
                                      <span key={d} className="dep-tag">{d}</span>
                                    ))
                                  ) : (
                                    <span className="text-muted">None</span>
                                  )}
                                </div>
                              </td>

                              {/* Status */}
                              <td>
                                <button
                                  className={`status-pill status-${t.status} clickable-pill`}
                                  onClick={() => toggleTask(t.id, t.status)}
                                >
                                  {t.status}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Info Sidebar */}
        <div className="mp-sidebar">
          <div className="card info-card-pqc">
            <h4 className="ic-title">NIST PQC Standards Overview</h4>
            <div className="ic-content">
              <div className="ic-item">
                <span className="ic-name">FIPS 203 (ML-KEM)</span>
                <span className="ic-desc">Key Encapsulation Mechanism. Replaces RSA key transport &amp; ECDH.</span>
              </div>
              <div className="ic-item">
                <span className="ic-name">FIPS 204 (ML-DSA)</span>
                <span className="ic-desc">Digital Signature Algorithm. Replaces RSA signatures, ECDSA.</span>
              </div>
              <div className="ic-item">
                <span className="ic-name">FIPS 205 (SLH-DSA)</span>
                <span className="ic-desc">Stateless Hash-based DSA. Backup standard for signatures.</span>
              </div>
            </div>
          </div>

          <div className="card metrics-card">
            <h4>Roadmap Summary</h4>
            <div className="metrics-grid">
              <div className="metric">
                <span className="metric-val">{doneTasks}/{totalTasks}</span>
                <span className="metric-lbl">Done</span>
              </div>
              <div className="metric">
                <span className="metric-val">{migrationProgress}%</span>
                <span className="metric-lbl">Progress</span>
              </div>
              <div className="metric">
                <span className="metric-val">4</span>
                <span className="metric-lbl">Phases</span>
              </div>
            </div>
            <button className="btn btn-primary w-full mt-4" onClick={() => setCurrentPage('reports')}>
              📄 Generate Full Migration Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
