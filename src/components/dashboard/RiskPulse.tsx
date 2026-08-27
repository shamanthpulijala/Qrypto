// ============================================================
// QuantumGuard AI — Risk Pulse Component §33
// Activity stream derived from actual scan findings
// ============================================================

import React from 'react';
import { Activity } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './RiskPulse.css';

export function RiskPulse() {
  const { assessment } = useAppStore();

  if (!assessment) return null;

  // Derive events from actual findings instead of fabricating them
  const events: { type: string; text: string; time: string }[] = [];

  // Critical findings first
  const critical = assessment.findings.filter(f => f.severity === 'critical');
  critical.slice(0, 2).forEach(f => {
    events.push({
      type: 'critical',
      text: `${f.algorithm} detected in ${f.service} (${f.file}:${f.line})`,
      time: f.detectedAt ? new Date(f.detectedAt).toLocaleTimeString() : 'just now',
    });
  });

  // High-severity findings
  const high = assessment.findings.filter(f => f.severity === 'high');
  high.slice(0, 2).forEach(f => {
    events.push({
      type: 'warning',
      text: `${f.algorithm} quantum-vulnerable in ${f.service}`,
      time: f.detectedAt ? new Date(f.detectedAt).toLocaleTimeString() : 'just now',
    });
  });

  // PQC/adequate findings (positive signal)
  const safe = assessment.findings.filter(f => f.quantumStatus === 'quantum-resistant' || f.quantumStatus === 'adequate');
  if (safe.length > 0) {
    events.push({
      type: 'success',
      text: `${safe.length} quantum-safe algorithm(s) verified in inventory`,
      time: 'scan complete',
    });
  }

  // Summary event
  events.push({
    type: 'info',
    text: `Scan complete: ${assessment.findings.length} findings across ${assessment.scanStats?.affectedServices || 0} services`,
    time: 'just now',
  });

  // Cap at 5 events
  const displayEvents = events.slice(0, 5);

  return (
    <div className="risk-pulse-card">
      <div className="rp-header">
        <span className="rp-title">
          <Activity size={14} style={{ color: 'var(--accent-cyan)' }} /> RISK PULSE
        </span>
      </div>

      <div className="rp-stream">
        {displayEvents.map((e, idx) => (
          <div key={idx} className="rp-item">
            <span className={`rp-bullet ${e.type}`} />
            <div>
              <div style={{ color: 'var(--text-primary)' }}>{e.text}</div>
              <div className="rp-time">{e.time}</div>
            </div>
          </div>
        ))}
        {displayEvents.length === 0 && (
          <div className="rp-item">
            <span className="rp-bullet info" />
            <div>
              <div style={{ color: 'var(--text-primary)' }}>No findings detected</div>
              <div className="rp-time">scan complete</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
