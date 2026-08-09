import React, { useState } from 'react';
import { Zap, Shield, ShieldAlert, ArrowRight, Activity, Clock, ShieldCheck, ChevronRight, Network } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { scoreToColor } from '../../engine/riskEngine';
import type { Finding } from '../../types';
import './QDaySimulator.css';

export function QDaySimulator() {
  const { assessment, qdayActive, runQDaySimulation, resetQDaySimulation, qdayYear, setQDayYear, setCurrentPage } = useAppStore();

  const [simulating, setSimulating] = useState(false);

  if (!assessment) return null;

  const handleSimulate = () => {
    if (qdayActive) {
      resetQDaySimulation();
      return;
    }
    setSimulating(true);
    setTimeout(() => {
      runQDaySimulation();
      setSimulating(false);
    }, 1500);
  };

  // Dynamic calculation based on scanned repository findings & 2000-2050 timeline
  const getExposure = (year: number) => {
    if (!assessment) return { value: 0, risk: 'Low', color: '#22c55e', era: 'Pre-Quantum Era' };
    const vuln = assessment.findings.filter(
      f => f.quantumStatus === 'vulnerable' || f.classicalStatus === 'broken' || f.classicalStatus === 'weak'
    );

    // If repo is 100% PQC clean (0 vulnerable algorithms)
    if (vuln.length === 0) {
      return {
        value: 0,
        risk: 'Verified Clean',
        color: '#22c55e',
        era: year < 2010 ? 'Pre-Quantum Era (2000s)' :
             year < 2020 ? 'HNDL Discovery (2010s)' :
             year < 2030 ? 'PQC Transition (2020s)' :
             year < 2040 ? 'CRQC Window (2030s)' : 'Post-RSA Era (2040s+)',
      };
    }

    const basePct = Math.round((vuln.length / Math.max(1, assessment.findings.length)) * 100);
    const decadeProgress = (year - 2000) / 50; // 0.0 at 2000, 1.0 at 2050
    const multiplier = 0.15 + decadeProgress * 1.35;
    const value = Math.min(100, Math.round(basePct * multiplier));

    let risk = 'Low';
    let color = '#22c55e';
    if (value >= 70) { risk = 'Critical'; color = '#ef4444'; }
    else if (value >= 45) { risk = 'High'; color = '#f97316'; }
    else if (value >= 20) { risk = 'Moderate'; color = '#eab308'; }

    let era = '';
    if (year < 2010) era = 'Pre-Quantum Legacy (2000s)';
    else if (year < 2020) era = 'HNDL Exposure (2010s)';
    else if (year < 2030) era = 'PQC Migration Era (2020s)';
    else if (year < 2040) era = 'CRQC Threat Window (2030s)';
    else era = 'Post-RSA Deprecation (2040s+)';

    return { value, risk, color, era };
  };

  const currentExposure = getExposure(qdayYear);
  const qday = assessment.qDaySimulation;

  return (
    <div className="qday-page animate-fade-in">
      <div className="qday-header">
        <div className="qh-left">
          <div className="qh-icon"><Zap size={24} /></div>
          <div>
            <h2>Q-Day Scenario Simulator</h2>
            <p>Analyze how the sudden availability of cryptographically relevant quantum capabilities would impact your architecture.</p>
          </div>
        </div>
        <div className="qh-right">
          <div className="scenario-label">SCENARIO MODEL — 2000 TO 2050 TIMELINE</div>
        </div>
      </div>

      <div className="qday-main">
        {/* Left Column - Controls & Time Machine */}
        <div className="qday-controls">
          <div className="card qm-card">
            <h3 className="qm-title">Quantum Time Machine</h3>
            <p className="qm-desc">Adjust the 2000–2050 timeline slider to observe decade-by-decade quantum risk evolution.</p>

            <div className="timeline-slider">
              <div className="tl-labels">
                <span>2000</span>
                <span>2010</span>
                <span>2020</span>
                <span>2030</span>
                <span>2040</span>
                <span>2050</span>
              </div>
              <input
                type="range"
                min="2000"
                max="2050"
                step="1"
                value={qdayYear}
                onChange={e => setQDayYear(Number(e.target.value))}
                className="slider"
              />
              <div className="tl-current" style={{ left: `${((qdayYear - 2000) / 50) * 100}%` }}>
                {qdayYear}
              </div>
            </div>

            <div className="exposure-box" style={{ borderColor: currentExposure.color }}>
              <div className="eb-left">
                <span className="eb-label">Potential Exposure ({qdayYear})</span>
                <span className="eb-era-tag">{currentExposure.era}</span>
                <span className="eb-risk" style={{ color: currentExposure.color }}>{currentExposure.risk}</span>
              </div>
              <div className="eb-right">
                <span className="eb-value" style={{ color: currentExposure.color }}>{currentExposure.value}%</span>
              </div>
            </div>

            <div className="qm-actions">
              <button
                className={`btn btn-qday btn-lg w-full ${qdayActive ? 'active' : ''}`}
                onClick={handleSimulate}
                disabled={simulating}
              >
                {simulating ? 'ANALYZING IMPACT...' : qdayActive ? '🔴 RESET SIMULATION' : '⚡ SIMULATE Q-DAY'}
              </button>
            </div>
          </div>

          <div className="card info-card">
            <h4><Activity size={16} /> What does this simulate?</h4>
            <p>
              This simulation identifies all <strong>RSA, ECC, ECDH, ECDSA, and DSA</strong> algorithms in your cryptographic inventory.
              It assumes these algorithms are practically broken, and propagates that risk through your service dependency graph to identify affected downstream data and services.
            </p>
          </div>
        </div>

        {/* Right Column - Results */}
        <div className="qday-results-area">
          {!qdayActive && !simulating && (
            <div className="qday-empty">
              <Zap size={48} className="qe-icon" />
              <h3>Ready to simulate</h3>
              <p>Click "Simulate Q-Day" to run the impact analysis against your current cryptographic inventory.</p>
            </div>
          )}

          {simulating && (
            <div className="qday-empty simulating">
              <div className="spinner-large" />
              <h3>Calculating blast radius...</h3>
              <p>Analyzing dependency graph and vulnerable cryptographic assets...</p>
            </div>
          )}

          {qdayActive && qday && (
            <div className="qday-report animate-slide-in">
              {/* Readiness Comparison */}
              <div className="readiness-comparison">
                <div className="rc-box before">
                  <span className="rc-label">CURRENT READINESS</span>
                  <div className="rc-score" style={{ color: scoreToColor(qday.beforeReadiness) }}>
                    {qday.beforeReadiness}
                  </div>
                </div>
                <div className="rc-arrow"><ArrowRight size={24} /></div>
                <div className="rc-box after">
                  <span className="rc-label">SIMULATED Q-DAY READINESS</span>
                  <div className="rc-score" style={{ color: scoreToColor(qday.afterReadiness) }}>
                    {qday.afterReadiness}
                  </div>
                </div>
              </div>

              {/* Impact Grid */}
              <div className="impact-stats">
                <div className="istat critical">
                  <div className="istat-icon"><ShieldAlert size={20} /></div>
                  <span className="istat-val">{qday.vulnerableFindings.length}</span>
                  <span className="istat-lbl">Vulnerable Assets</span>
                </div>
                <div className="istat warn">
                  <div className="istat-icon"><Network size={20} /></div>
                  <span className="istat-val">{qday.affectedServices.length}</span>
                  <span className="istat-lbl">Affected Services</span>
                </div>
                <div className="istat danger">
                  <div className="istat-icon"><Clock size={20} /></div>
                  <span className="istat-val">{qday.hndlExposure.toUpperCase()}</span>
                  <span className="istat-lbl">HNDL Exposure</span>
                </div>
              </div>

              {/* Narrative */}
              <div className="impact-narrative">
                <h4>Business Impact Summary</h4>
                <p>{qday.simulatedBusinessImpact}</p>
                <div className="narrative-actions">
                  <button className="btn btn-ghost" onClick={() => setCurrentPage('attackmap')}>
                    View Attack Path Graph <ChevronRight size={16} />
                  </button>
                  <button className="btn btn-primary" onClick={() => setCurrentPage('migration')}>
                    Generate Migration Plan <ChevronRight size={16} />
                  </button>
                </div>
              </div>

              {/* Affected Services List */}
              <div className="affected-services">
                <h4>Affected Services ({qday.affectedServices.length})</h4>
                <div className="as-grid">
                  {qday.affectedServices.map(svc => {
                    const svcFindings = qday.vulnerableFindings.filter(f => f.service === svc.name);
                    return (
                      <div key={svc.id} className="as-card">
                        <div className="as-header">
                          <span className="as-name">{svc.name}</span>
                          <span className="badge badge-critical">{svcFindings.length} Vuln</span>
                        </div>
                        <div className="as-algos">
                          {[...new Set(svcFindings.map(f => f.algorithm))].join(', ')}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

            </div>
          )}
        </div>
      </div>
    </div>
  );
}
