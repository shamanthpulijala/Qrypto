// ============================================================
// Qrypto — P0-12: Per-Asset Context Override Panel
// Allows users to override inferred context (criticality, exposure, lifetime)
// for individual findings or entire services.
// ============================================================

import React, { useState } from 'react';
import { Settings, X, Check, AlertTriangle } from 'lucide-react';
import { useAppStore, type ContextOverride } from '../../store/assessmentStore';
import type { Finding } from '../../types';

interface ContextOverridePanelProps {
  finding?: Finding;
  serviceName?: string;
  onClose: () => void;
}

export function ContextOverridePanel({ finding, serviceName, onClose }: ContextOverridePanelProps) {
  const { contextOverrides, setContextOverride, removeContextOverride, recalculateFindingsWithContext } = useAppStore();
  
  // Find existing override
  const existingOverride = contextOverrides.find(o => 
    (finding?.fingerprint && o.fingerprint === finding.fingerprint) ||
    (serviceName && o.service === serviceName && !o.fingerprint)
  );

  const [internetFacing, setInternetFacing] = useState<boolean>(
    existingOverride?.internetFacing ?? finding?.internetFacing ?? false
  );
  const [dataSensitivity, setDataSensitivity] = useState<string>(
    existingOverride?.dataSensitivity ?? finding?.dataSensitivity ?? 'medium'
  );
  const [dataLifetimeYears, setDataLifetimeYears] = useState<number>(
    existingOverride?.dataLifetimeYears ?? finding?.dataLifetimeYears ?? 5
  );
  const [businessCriticality, setBusinessCriticality] = useState<number>(
    existingOverride?.businessCriticality ?? 60
  );

  const handleSave = () => {
    const override: ContextOverride = {
      fingerprint: finding?.fingerprint,
      service: serviceName || finding?.service,
      internetFacing,
      dataSensitivity: dataSensitivity as any,
      dataLifetimeYears,
      businessCriticality,
    };
    setContextOverride(override);
    recalculateFindingsWithContext();
    onClose();
  };

  const handleRemove = () => {
    if (finding?.fingerprint) {
      removeContextOverride(finding.fingerprint);
    } else if (serviceName) {
      removeContextOverride(serviceName);
    }
    recalculateFindingsWithContext();
    onClose();
  };

  const targetName = finding ? `${finding.algorithm} in ${finding.file}:${finding.line}` : serviceName || 'Unknown';

  return (
    <div className="context-override-panel" style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-default)',
      borderRadius: 12,
      padding: 20,
      marginBottom: 16,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Settings size={16} style={{ color: 'var(--accent-cyan)' }} />
          <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Override Context</h3>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <X size={16} />
        </button>
      </div>

      <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 16 }}>
        <AlertTriangle size={14} style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }} />
        Override inferred values for: <strong>{targetName}</strong>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Internet Facing */}
        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
            Internet Facing
          </label>
          <select
            className="input"
            value={internetFacing ? 'true' : 'false'}
            onChange={e => setInternetFacing(e.target.value === 'true')}
            style={{ width: '100%' }}
          >
            <option value="true">Yes — Exposed to internet</option>
            <option value="false">No — Internal only</option>
          </select>
        </div>

        {/* Data Sensitivity */}
        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
            Data Sensitivity
          </label>
          <select
            className="input"
            value={dataSensitivity}
            onChange={e => setDataSensitivity(e.target.value)}
            style={{ width: '100%' }}
          >
            <option value="critical">Critical — PII, financial, healthcare</option>
            <option value="high">High — Business-sensitive data</option>
            <option value="medium">Medium — Internal data</option>
            <option value="low">Low — Public/non-sensitive data</option>
          </select>
        </div>

        {/* Data Lifetime */}
        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
            Data Lifetime (years)
          </label>
          <input
            type="number"
            className="input"
            value={dataLifetimeYears}
            onChange={e => setDataLifetimeYears(Math.max(1, parseInt(e.target.value) || 1))}
            min={1}
            max={100}
            style={{ width: '100%' }}
          />
          <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: 4 }}>
            How long must this data remain confidential?
          </div>
        </div>

        {/* Business Criticality */}
        <div>
          <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
            Business Criticality (0-100)
          </label>
          <input
            type="range"
            min={0}
            max={100}
            value={businessCriticality}
            onChange={e => setBusinessCriticality(parseInt(e.target.value))}
            style={{ width: '100%' }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
            <span>Low (0)</span>
            <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{businessCriticality}</span>
            <span>Critical (100)</span>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 8, marginTop: 20, justifyContent: 'flex-end' }}>
        {existingOverride && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={handleRemove}
            style={{ color: 'var(--status-critical)' }}
          >
            Remove Override
          </button>
        )}
        <button className="btn btn-ghost btn-sm" onClick={onClose}>
          Cancel
        </button>
        <button className="btn btn-primary btn-sm" onClick={handleSave}>
          <Check size={14} /> Apply Override
        </button>
      </div>

      {/* Current inferred values */}
      {finding && (
        <div style={{ marginTop: 16, padding: 12, background: 'var(--bg-elevated)', borderRadius: 8, fontSize: '0.8rem' }}>
          <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>Current Inferred Values</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, color: 'var(--text-tertiary)' }}>
            <div>Internet: {finding.internetFacing ? 'Yes' : 'No'}</div>
            <div>Sensitivity: {finding.dataSensitivity}</div>
            <div>Lifetime: {finding.dataLifetimeYears} years</div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================
// Service-Level Override Button (for use in service cards/lists)
// ============================================================

interface ServiceOverrideButtonProps {
  serviceName: string;
}

export function ServiceOverrideButton({ serviceName }: ServiceOverrideButtonProps) {
  const [showPanel, setShowPanel] = useState(false);
  const { contextOverrides } = useAppStore();
  
  const hasOverride = contextOverrides.some(o => o.service === serviceName && !o.fingerprint);

  if (showPanel) {
    return (
      <ContextOverridePanel
        serviceName={serviceName}
        onClose={() => setShowPanel(false)}
      />
    );
  }

  return (
    <button
      className="btn btn-ghost btn-sm"
      onClick={() => setShowPanel(true)}
      style={{ fontSize: '0.75rem' }}
      title="Override context for this service"
    >
      <Settings size={12} />
      {hasOverride && <span style={{ color: 'var(--accent-cyan)' }}>●</span>}
    </button>
  );
}

// ============================================================
// Finding-Level Override Button (for use in finding detail rows)
// ============================================================

interface FindingOverrideButtonProps {
  finding: Finding;
}

export function FindingOverrideButton({ finding }: FindingOverrideButtonProps) {
  const [showPanel, setShowPanel] = useState(false);
  const { contextOverrides } = useAppStore();
  
  const hasOverride = contextOverrides.some(o => o.fingerprint === finding.fingerprint);

  if (showPanel) {
    return (
      <ContextOverridePanel
        finding={finding}
        onClose={() => setShowPanel(false)}
      />
    );
  }

  return (
    <button
      className="btn btn-ghost btn-sm"
      onClick={() => setShowPanel(true)}
      style={{ fontSize: '0.75rem' }}
      title="Override context for this finding"
    >
      <Settings size={12} />
      {hasOverride && <span style={{ color: 'var(--accent-cyan)' }}>●</span>}
      <span>Override</span>
    </button>
  );
}
