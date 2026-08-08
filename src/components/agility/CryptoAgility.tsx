import React from 'react';
import { BarChart3, Shuffle, Lock, Shield } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import './CryptoAgility.css';

export function CryptoAgility() {
  const { assessment } = useAppStore();

  if (!assessment) return null;

  const agilityFindings = assessment.findings.filter(f => f.cryptoAgilityScore !== undefined);
  const avgAgility = Math.round(
    agilityFindings.reduce((sum, f) => sum + (f.cryptoAgilityScore || 0), 0) / (agilityFindings.length || 1)
  );

  return (
    <div className="agility-page animate-fade-in">
      <div className="ap-header">
        <div className="aph-left">
          <BarChart3 size={24} className="aph-icon" />
          <div>
            <h2>Cryptographic Agility Assessment</h2>
            <p>Measure your architecture's ability to seamlessly swap cryptographic primitives without breaking downstream systems.</p>
          </div>
        </div>
      </div>

      <div className="agility-grid">
        {/* Main Score Card */}
        <div className="card agility-main-card">
          <div className="agility-gauge">
            <svg viewBox="0 0 100 100" className="ag-svg">
              <circle cx="50" cy="50" r="40" fill="none" stroke="#1e2d4a" strokeWidth="10" strokeLinecap="round" />
              <circle cx="50" cy="50" r="40" fill="none" stroke={scoreToColor(avgAgility)} strokeWidth="10"
                strokeDasharray={`${(avgAgility / 100) * (2 * Math.PI * 40)} ${2 * Math.PI * 40}`}
                strokeLinecap="round" transform="rotate(-90 50 50)"
                style={{ filter: `drop-shadow(0 0 10px ${scoreToColor(avgAgility)}88)` }}
              />
            </svg>
            <div className="ag-content">
              <span className="ag-score" style={{ color: scoreToColor(avgAgility) }}>{avgAgility}</span>
              <span className="ag-label">AGILITY SCORE</span>
            </div>
          </div>
          <div className="agility-desc">
            <h4>{avgAgility >= 70 ? 'High Agility' : avgAgility >= 40 ? 'Moderate Agility' : 'Low Agility'}</h4>
            <p>
              {avgAgility >= 70
                ? "Your architecture abstracts cryptography well. Upgrading to PQC standards should be relatively straightforward."
                : "Your architecture has heavily hardcoded cryptography. Upgrading to PQC standards will require significant refactoring."}
            </p>
          </div>
        </div>

        {/* Factors */}
        <div className="card agility-factors">
          <h4>Agility Anti-Patterns Detected</h4>
          <div className="af-list">
            <div className="af-item">
              <div className="af-icon"><Lock size={16} /></div>
              <div className="af-text">
                <span className="af-name">Hardcoded Keys/Secrets</span>
                <span className="af-val">{agilityFindings.filter(f => f.isHardcoded).length} instances</span>
              </div>
            </div>
            <div className="af-item">
              <div className="af-icon"><Shuffle size={16} /></div>
              <div className="af-text">
                <span className="af-name">Low-Level Crypto Calls</span>
                <span className="af-val">{agilityFindings.filter(f => f.isCentralized === false).length} instances</span>
              </div>
            </div>
            <div className="af-item">
              <div className="af-icon"><Shield size={16} /></div>
              <div className="af-text">
                <span className="af-name">Lack of Provider Abstraction</span>
                <span className="af-val">Widespread across 3 services</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="card mt-6">
        <h4 style={{ marginBottom: '16px' }}>Lowest Agility Assets</h4>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Algorithm</th>
              <th>File</th>
              <th>Agility Score</th>
              <th>Reasoning</th>
            </tr>
          </thead>
          <tbody>
            {agilityFindings.sort((a,b) => (a.cryptoAgilityScore || 100) - (b.cryptoAgilityScore || 100)).slice(0, 10).map(f => (
              <tr key={f.id}>
                <td className="mono">{f.id}</td>
                <td>{f.algorithm}</td>
                <td className="mono" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.file.split('/').slice(-2).join('/')}
                </td>
                <td>
                  <strong style={{ color: scoreToColor(f.cryptoAgilityScore || 0) }}>{f.cryptoAgilityScore}/100</strong>
                </td>
                <td>
                  <span className="text-secondary" style={{ fontSize: '0.8rem' }}>
                    {f.isHardcoded ? 'Hardcoded configuration. ' : ''}
                    {!f.isCentralized ? 'Direct primitive call instead of provider API.' : ''}
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
