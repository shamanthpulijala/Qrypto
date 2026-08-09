// ============================================================
// QuantumGuard AI — §31 Migration Page
//
// Shows overall migration progress and an interactive task list:
//   Priority · Owner · Effort · Dependencies · Status
// ============================================================

import React, { useState } from 'react';
import { useAppStore } from '../../store/assessmentStore';
import {
  ListChecks, TrendingUp, Filter, AlertTriangle, CheckCircle2,
  Clock, CheckSquare, Square, User, Network
} from 'lucide-react';
import type { MigrationTask } from '../../types';
import './Migration.css';

export function MigrationPlanner() {
  const { assessment, updateTaskStatus } = useAppStore();
  const [filterPhase, setFilterPhase] = useState<number | 'all'>('all');
  const [filterStatus, setFilterStatus] = useState<'all' | 'todo' | 'in-progress' | 'done'>('all');

  if (!assessment) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">📋</div>
        <h2>No Migration Plan Available</h2>
        <p>Run a cryptographic scan to generate a Post-Quantum migration roadmap.</p>
      </div>
    );
  }

  const { migrationTasks } = assessment;

  // Compute progress
  const totalTasks = migrationTasks.length;
  const doneTasks = migrationTasks.filter(t => t.status === 'done').length;
  const inProgressTasks = migrationTasks.filter(t => t.status === 'in-progress').length;
  const progressPercent = totalTasks > 0
    ? Math.round(((doneTasks + inProgressTasks * 0.5) / totalTasks) * 100)
    : 0;

  // Filter tasks
  const filteredTasks = migrationTasks.filter(t => {
    if (filterPhase !== 'all' && t.phase !== filterPhase) return false;
    if (filterStatus !== 'all' && t.status !== filterStatus) return false;
    return true;
  });

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#3b82f6';
      default: return '#64748b';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'done': return <CheckSquare size={16} className="text-green-500" />;
      case 'in-progress': return <Clock size={16} className="text-yellow-500" />;
      default: return <Square size={16} className="text-slate-400" />;
    }
  };

  return (
    <div className="migration-page animate-fade-in">
      <div className="mig-header">
        <div className="mig-header-left">
          <div className="mig-icon-container">
            <TrendingUp size={24} />
          </div>
          <div>
            <h2>Post-Quantum Migration Roadmap</h2>
            <p>Track your transition to quantum-resistant cryptography (NIST FIPS 203/204/205).</p>
          </div>
        </div>
        <div className="mig-progress-widget">
          <div className="mpw-val">{progressPercent}%</div>
          <div className="mpw-lbl">Overall Progress</div>
          <div className="mpw-bar-container">
            <div className="mpw-bar-fill" style={{ width: `${progressPercent}%` }} />
          </div>
        </div>
      </div>

      {/* System Transformation §40 */}
      <div className="card mb-4" style={{ background: 'var(--glass-bg)', padding: '1.25rem' }}>
        <div style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-violet)', marginBottom: '0.75rem' }}>
          SYSTEM ALGORITHM TRANSFORMATION (RSA-2048 → HYBRID → ML-KEM)
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
            <span style={{ color: '#ef4444' }}>RSA-2048 (Legacy)</span>
            <span style={{ color: '#eab308' }}>HYBRID MODE</span>
            <span style={{ color: '#22c55e' }}>ML-KEM FIPS 203</span>
          </div>
          <div style={{ height: '8px', background: 'var(--border-subtle)', borderRadius: 'var(--radius-full)', overflow: 'hidden', display: 'flex' }}>
            <div style={{ width: `${Math.max(10, 100 - progressPercent)}%`, background: '#ef4444', transition: 'width 0.8s ease' }} />
            <div style={{ width: `${inProgressTasks > 0 ? 25 : 10}%`, background: '#eab308', transition: 'width 0.8s ease' }} />
            <div style={{ width: `${progressPercent}%`, background: '#22c55e', transition: 'width 0.8s ease' }} />
          </div>
        </div>
      </div>

      <div className="mig-controls">
        <div className="mig-filters">
          <div className="filter-group">
            <Filter size={14} />
            <select
              className="input select-sm"
              value={filterPhase}
              onChange={(e) => setFilterPhase(e.target.value === 'all' ? 'all' : Number(e.target.value))}
            >
              <option value="all">All Phases</option>
              <option value="1">Phase 1: Immediate</option>
              <option value="2">Phase 2: Short-Term</option>
              <option value="3">Phase 3: Medium-Term</option>
              <option value="4">Phase 4: Long-Term</option>
            </select>
          </div>
          <div className="filter-group">
            <ListChecks size={14} />
            <select
              className="input select-sm"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value as any)}
            >
              <option value="all">All Statuses</option>
              <option value="todo">To Do</option>
              <option value="in-progress">In Progress</option>
              <option value="done">Completed</option>
            </select>
          </div>
        </div>
        <div className="mig-stats-small">
          {filteredTasks.length} tasks matching criteria
        </div>
      </div>

      <div className="mig-task-list">
        {filteredTasks.map(task => (
          <div key={task.id} className={`card task-card status-${task.status}`}>
            <div className="task-left">
              <button
                className="task-status-btn"
                onClick={() => {
                  const nextStatus = task.status === 'todo' ? 'in-progress' :
                                     task.status === 'in-progress' ? 'done' : 'todo';
                  updateTaskStatus(task.id, nextStatus as any);
                }}
              >
                {getStatusIcon(task.status)}
              </button>
              <div className="task-content">
                <div className="task-header">
                  <h4>{task.title}</h4>
                  <span className={`task-badge priority-${task.priority}`} style={{ borderColor: getPriorityColor(task.priority), color: getPriorityColor(task.priority) }}>
                    {task.priority}
                  </span>
                  <span className="task-badge phase-badge">Phase {task.phase}</span>
                </div>
                <p className="task-desc">{task.description}</p>
                
                <div className="task-meta">
                  <div className="tm-item">
                    <User size={12} />
                    <span>Owner: {task.owner || 'Unassigned'}</span>
                  </div>
                  <div className="tm-item">
                    <Clock size={12} />
                    <span>Effort: {task.estimatedEffort}</span>
                  </div>
                  {task.dependencies && task.dependencies.length > 0 && (
                    <div className="tm-item tm-deps">
                      <Network size={12} />
                      <span>{task.dependencies.length} Dep(s)</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
            <div className="task-right">
              {task.affectedServices && task.affectedServices.length > 0 && (
                <div className="task-services">
                  {task.affectedServices.slice(0, 2).map((svc, i) => (
                    <span key={i} className="task-svc-badge">{svc}</span>
                  ))}
                  {task.affectedServices.length > 2 && (
                    <span className="task-svc-badge">+{task.affectedServices.length - 2}</span>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}

        {filteredTasks.length === 0 && (
          <div className="empty-state" style={{ padding: '40px 0' }}>
            <div className="empty-state-icon" style={{ opacity: 0.5 }}>✓</div>
            <h3>No tasks found</h3>
            <p>Try adjusting your filters.</p>
          </div>
        )}
      </div>
    </div>
  );
}
