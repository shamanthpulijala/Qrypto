import React from 'react';
import { Clock, ShieldAlert, Database, Lock, AlertTriangle } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, Cell, ReferenceLine } from 'recharts';
import './HNDLAnalyzer.css';

export function HNDLAnalyzer() {
  const { assessment } = useAppStore();

  if (!assessment) return null;

  const hndlFindings = assessment.findings.filter(f => f.category !== 'hash' && f.category !== 'secret');

  const scatterData = hndlFindings.map(f => {
    const lifetimeVal = f.dataLifetimeYears;
    let lifetimeStr = 'long';
    if (lifetimeVal <= 1) lifetimeStr = 'ephemeral';
    else if (lifetimeVal <= 2) lifetimeStr = 'short';
    else if (lifetimeVal <= 5) lifetimeStr = 'medium';

    let sensVal = 0;
    if (f.dataSensitivity === 'low') sensVal = 100;
    else if (f.dataSensitivity === 'medium') sensVal = 300;
    else if (f.dataSensitivity === 'high') sensVal = 600;
    else if (f.dataSensitivity === 'critical') sensVal = 1200;

    const hndlScore = (f.riskBreakdown.dataLifetime + f.riskBreakdown.dataSensitivity) / 2;

    let color = '#22c55e'; // low exposure
    if (hndlScore > 60) color = '#ef4444'; // critical exposure
    else if (hndlScore > 30) color = '#f97316'; // high
    else if (hndlScore > 15) color = '#eab308'; // medium

    return {
      id: f.id,
      algorithm: f.algorithm,
      service: f.service,
      lifetime: lifetimeStr,
      lifetimeVal,
      sensitivity: f.dataSensitivity,
      sensVal,
      risk: f.riskScore,
      hndlScore,
      color,
    };
  });

  const highHNDL = scatterData.filter(d => d.hndlScore > 30).sort((a,b) => b.hndlScore - a.hndlScore).slice(0, 5);

  return (
    <div className="hndl-analyzer animate-fade-in">
      <div className="hndl-header">
        <div className="hh-left">
          <Clock size={24} className="hh-icon" />
          <div>
            <h2>Harvest Now, Decrypt Later (HNDL) Analysis</h2>
            <p>Identify data at risk of being intercepted today for decryption by future quantum computers.</p>
          </div>
        </div>
      </div>

      <div className="hndl-grid">
        {/* Info Card */}
        <div className="card hndl-info-card">
          <h4><ShieldAlert size={16} /> What is HNDL?</h4>
          <p>
            Adversaries are currently intercepting and storing encrypted data traffic. When cryptographically relevant quantum computers (CRQCs) become available, they will retroactively decrypt this data. 
          </p>
          <p style={{ marginTop: '8px' }}>
            <strong>Risk Factors:</strong> Data Lifetime (how long the data remains valuable) vs. Quantum Timeline (when CRQCs are expected). If Lifetime &gt; Time-to-CRQC, the data is highly vulnerable today.
          </p>
        </div>

        {/* Chart */}
        <div className="card hndl-chart-card">
          <h4 style={{ marginBottom: '16px' }}>HNDL Exposure Matrix</h4>
          <ResponsiveContainer width="100%" height={400}>
            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
              <XAxis type="number" dataKey="lifetimeVal" name="Lifetime (years)" tickFormatter={(val) => `${val}y`} stroke="#64748b" />
              <YAxis type="number" dataKey="risk" name="Risk Score" stroke="#64748b" />
              <ZAxis type="number" dataKey="sensVal" range={[50, 600]} name="Sensitivity" />
              <Tooltip 
                cursor={{ strokeDasharray: '3 3' }}
                contentStyle={{ background: '#111827', borderColor: '#1e2d4a', borderRadius: '8px' }}
                formatter={(value, name, props) => {
                  if (name === 'Lifetime (years)') return [props.payload.lifetime, 'Data Lifetime'];
                  if (name === 'Risk Score') return [value, 'Overall Risk'];
                  if (name === 'Sensitivity') return [props.payload.sensitivity, 'Sensitivity'];
                  return [value, name];
                }}
                labelFormatter={() => ''}
              />
              <ReferenceLine x={5} stroke="#ef4444" strokeDasharray="3 3" label={{ position: 'top', value: 'High Danger Zone', fill: '#ef4444', fontSize: 12 }} />
              <Scatter name="Findings" data={scatterData}>
                {scatterData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
          <div style={{ textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-tertiary)', marginTop: '8px' }}>
            Bubble size indicates Data Sensitivity. Red zones indicate high HNDL exposure.
          </div>
        </div>

        {/* Top Risks Table */}
        <div className="card hndl-table-card">
          <h4 style={{ marginBottom: '16px' }}>Highest HNDL Exposure Assets</h4>
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Algorithm</th>
                <th>Service</th>
                <th>Lifetime</th>
                <th>Sensitivity</th>
                <th>HNDL Score</th>
              </tr>
            </thead>
            <tbody>
              {highHNDL.map(f => (
                <tr key={f.id}>
                  <td className="mono">{f.id}</td>
                  <td><strong>{f.algorithm}</strong></td>
                  <td>{f.service}</td>
                  <td><span className="badge badge-info">{f.lifetime}</span></td>
                  <td><span className={`badge badge-${f.sensitivity === 'critical' ? 'critical' : 'high'}`}>{f.sensitivity}</span></td>
                  <td>
                    <strong style={{ color: f.color }}>{Math.round(f.hndlScore)}/100</strong>
                  </td>
                </tr>
              ))}
              {highHNDL.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: '24px' }}>No high HNDL exposure detected.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
