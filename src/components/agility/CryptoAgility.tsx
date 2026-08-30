// ============================================================
// Qrypto AI Advisor — §32 Crypto Agility Page
//
// Shows overall agility score, category breakdown, positives/negatives,
// and concrete evidence mapped from findings (hardcoded calls, etc).
// ============================================================

import React from 'react';
import { useAppStore } from '../../store/assessmentStore';
import {
  Activity, CheckCircle2, XCircle, Code, Settings, Unlock, RefreshCw, Box
} from 'lucide-react';
import { readinessScoreToColor } from '../../engine/riskEngine';
import './CryptoAgility.css';

export function CryptoAgility() {
  const { assessment } = useAppStore();

  if (!assessment || !assessment.cryptoAgilityScore) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⚡</div>
        <h2>Crypto-Agility Not Assessed</h2>
        <p>Run a cryptographic scan to generate the crypto-agility assessment.</p>
      </div>
    );
  }

  const { cryptoAgilityScore } = assessment;
  const { breakdown, evidence, positives, negatives } = cryptoAgilityScore;

  const scoreColor = readinessScoreToColor(cryptoAgilityScore.score);

  const breakdownItems = [
    { label: 'Algorithm Abstraction', value: breakdown.algorithmAbstraction, icon: Box },
    { label: 'Configuration Centralization', value: breakdown.configurationCentralization, icon: Settings },
    { label: 'Hardcoded Algorithms', value: breakdown.hardcodedAlgorithms, icon: Code },
    { label: 'Migration Flexibility', value: breakdown.migrationFlexibility, icon: RefreshCw },
    { label: 'Dependency Management', value: breakdown.dependencyManagement, icon: Unlock },
  ];

  return (
    <div className="agility-page animate-fade-in">
      <div className="agility-header">
        <div className="ah-left">
          <div className="ah-icon-container">
            <Activity size={24} />
          </div>
          <div>
            <h2>Crypto-Agility Assessment</h2>
            <p>Evaluate your architecture's readiness to substitute cryptographic primitives without major refactoring.</p>
          </div>
        </div>
      </div>

      <div className="agility-top-section">
        <div className="card agility-main-score">
          <div className="ams-circle" style={{ borderColor: scoreColor, color: scoreColor }}>
            {cryptoAgilityScore.score}
          </div>
          <div className="ams-labels">
            <h3>Overall Agility Score</h3>
            <p>
              {cryptoAgilityScore.score >= 80 ? 'Highly Agile architecture. Ready for PQC transition.' :
               cryptoAgilityScore.score >= 50 ? 'Moderate Agility. Some refactoring required for PQC.' :
               'Rigid architecture. Significant refactoring needed before PQC migration.'}
            </p>
          </div>
        </div>

        <div className="card agility-breakdown">
          <h3>Score Breakdown</h3>
          <div className="ab-list">
            {breakdownItems.map((item, i) => {
              const Icon = item.icon;
              return (
                <div key={i} className="ab-item">
                  <div className="ab-label">
                    <Icon size={14} className="ab-icon" />
                    <span>{item.label}</span>
                  </div>
                  <div className="ab-track">
                    <div className="ab-fill" style={{ width: `${item.value}%`, background: readinessScoreToColor(item.value) }} />
                  </div>
                  <div className="ab-value" style={{ color: readinessScoreToColor(item.value) }}>
                    {item.value}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="agility-insights-section">
        <div className="card ai-card ai-positives">
          <h3><CheckCircle2 size={16} className="text-green-500" /> Strengths</h3>
          <ul>
            {positives.length > 0 ? (
              positives.map((p, i) => <li key={i}>{p}</li>)
            ) : (
              <li className="empty-li">No significant strengths identified.</li>
            )}
          </ul>
        </div>
        <div className="card ai-card ai-negatives">
          <h3><XCircle size={16} className="text-red-500" /> Gaps & Vulnerabilities</h3>
          <ul>
            {negatives.length > 0 ? (
              negatives.map((n, i) => <li key={i}>{n}</li>)
            ) : (
              <li className="empty-li">No major gaps identified.</li>
            )}
          </ul>
        </div>
      </div>

      {evidence && evidence.length > 0 && (
        <div className="agility-evidence-section">
          <h3>Evidence & Findings</h3>
          <div className="evidence-grid">
            {evidence.map((ev, i) => (
              <div key={i} className="card evidence-card">
                <div className="ec-header">
                  <div>
                    <span className="ec-category">{ev.category}</span>
                    <h4 className="ec-title">{ev.scoreName}</h4>
                  </div>
                  <div className="ec-score" style={{ color: readinessScoreToColor(ev.scoreValue) }}>
                    {ev.scoreValue}/100
                  </div>
                </div>
                <p className="ec-desc">{ev.description}</p>
                <div className="ec-code-box">
                  <div className="ec-code-header">
                    <span>{ev.filePath}</span>
                    <span>Line {ev.lineNumber}</span>
                  </div>
                  <code>{ev.evidenceSnippet}</code>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
