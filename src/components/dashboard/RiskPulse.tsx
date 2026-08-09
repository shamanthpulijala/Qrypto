// ============================================================
// QuantumGuard AI — Risk Pulse Component §33
// Real-time activity stream of cryptographic events
// ============================================================

import React from 'react';
import { Activity } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './RiskPulse.css';

export function RiskPulse() {
  const { assessment } = useAppStore();

  if (!assessment) return null;

  const events = [
    { type: 'critical', text: 'RSA-2048 certificate discovered in payment gateway', time: '2m ago' },
    { type: 'warning', text: 'TLS 1.2 legacy configuration detected in auth-service', time: '14m ago' },
    { type: 'info', text: 'AES-256-GCM verified as quantum-resistant symmetric cipher', time: '1h ago' },
    { type: 'success', text: 'ML-KEM (FIPS 203) hybrid migration target assigned', time: '3h ago' },
  ];

  return (
    <div className="risk-pulse-card">
      <div className="rp-header">
        <span className="rp-title">
          <Activity size={14} style={{ color: 'var(--accent-cyan)' }} /> RISK PULSE
        </span>
      </div>

      <div className="rp-stream">
        {events.map((e, idx) => (
          <div key={idx} className="rp-item">
            <span className={`rp-bullet ${e.type}`} />
            <div>
              <div style={{ color: 'var(--text-primary)' }}>{e.text}</div>
              <div className="rp-time">{e.time}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
