import React, { useState, useMemo } from 'react';
import { Network, ArrowRight, Shield, Zap, Lock, Cpu, Server, Activity } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { PQC_TRADEOFFS } from '../../../shared/engine/pqcTradeoffs';
import './PQCRecommendations.css';

export function PQCRecommendations() {
  const { assessment } = useAppStore();
  const [selectedAlgo, setSelectedAlgo] = useState<string | null>(null);

  // Extract unique classical algorithms from findings that need migration
  const classicalTargets = useMemo(() => {
    if (!assessment) return [];
    const vulnerable = assessment.findings.filter(f => 
      f.quantumStatus === 'vulnerable' || f.quantumStatus === 'classical-weak'
    );
    const unique = new Set(vulnerable.map(f => f.algorithm));
    
    // Sort them and pick the first as default
    const arr = Array.from(unique);
    if (arr.length > 0 && !selectedAlgo) {
      setSelectedAlgo(arr[0]);
    }
    return arr;
  }, [assessment]);

  // Find the matching PQC algorithm
  const pqcMatch = useMemo(() => {
    if (!selectedAlgo) return null;
    const s = selectedAlgo.toLowerCase();
    
    // Simple heuristic matcher
    if (s.includes('rsa') || s.includes('ecdh') || s.includes('25519')) {
      if (s.includes('sign') || s.includes('rsa-sig')) {
        return PQC_TRADEOFFS.find(t => t.algorithm === 'ML-DSA-65');
      }
      return PQC_TRADEOFFS.find(t => t.algorithm === 'ML-KEM-768');
    }
    if (s.includes('ecdsa') || s.includes('ed25519')) {
      return PQC_TRADEOFFS.find(t => t.algorithm === 'ML-DSA-44');
    }
    
    // Fallback based on usage context in the findings
    const finding = assessment?.findings.find(f => f.algorithm === selectedAlgo);
    if (finding?.category === 'certificate' || finding?.category === 'signature') {
      return PQC_TRADEOFFS.find(t => t.algorithm === 'ML-DSA-65');
    }
    return PQC_TRADEOFFS.find(t => t.algorithm === 'ML-KEM-768'); // default KEM
  }, [selectedAlgo, assessment]);

  if (!assessment || classicalTargets.length === 0) {
    return (
      <div className="pqc-empty-state">
        <Shield size={48} className="opacity-20 mb-4" />
        <h2>No Vulnerable Algorithms Found</h2>
        <p>Your scan did not detect any classical algorithms requiring PQC migration.</p>
      </div>
    );
  }

  // Visualization multipliers for relative sizing (RSA 2048 is approx 256 bytes)
  const classicalSize = 256; 
  const pqcSize = pqcMatch?.publicKeySizeBytes || 1184;
  const sizeRatio = Math.min((pqcSize / classicalSize), 5); // cap visual scale at 5x

  return (
    <div className="pqc-matrix-page animate-fade-in">
      <div className="pqc-header">
        <Cpu size={24} className="text-accent-cyan" />
        <h2>The Quantum Convergence Matrix</h2>
        <p>Interactive Post-Quantum Cryptography transition visualizer based on NIST FIPS 203/204 standards.</p>
      </div>

      <div className="pqc-matrix-layout">
        {/* LEFT: Target Selector */}
        <div className="pqc-selector card">
          <div className="card-header">
            <h3>Classical Targets</h3>
            <span className="text-xs text-text-tertiary">Discovered in scan</span>
          </div>
          <div className="target-list">
            {classicalTargets.map(algo => (
              <button
                key={algo}
                className={`target-btn ${selectedAlgo === algo ? 'active' : ''}`}
                onClick={() => setSelectedAlgo(algo)}
              >
                <Lock size={16} />
                <span>{algo}</span>
              </button>
            ))}
          </div>
        </div>

        {/* RIGHT: Visualizer */}
        <div className="pqc-visualizer card">
          {pqcMatch && (
            <div className="convergence-arena">
              
              {/* Top: The Node Transformation */}
              <div className="transformation-stage">
                <div className="node-box classical-node">
                  <div className="node-icon"><Lock size={32} /></div>
                  <div className="node-label">{selectedAlgo}</div>
                  <div className="node-sub">Legacy Protocol</div>
                </div>

                <div className="transformation-flow">
                  <div className="flow-line">
                    <div className="data-packet p1"></div>
                    <div className="data-packet p2"></div>
                    <div className="data-packet p3"></div>
                  </div>
                  <div className="flow-badge">
                    <Zap size={14} /> Migration
                  </div>
                </div>

                <div className="node-box pqc-node quantum-glow">
                  <div className="node-icon"><Shield size={32} /></div>
                  <div className="node-label">{pqcMatch.algorithm}</div>
                  <div className="node-sub">{pqcMatch.nistStandard}</div>
                </div>
              </div>

              {/* Bottom: Tradeoff Analytics */}
              <div className="tradeoff-analytics">
                <h3 className="analytics-title"><Activity size={16} /> Payload Scaling Analysis</h3>
                
                <div className="bar-chart-container">
                  <div className="bar-row">
                    <div className="bar-label">
                      <span>Classical Key</span>
                      <span className="bar-val">~{classicalSize} Bytes</span>
                    </div>
                    <div className="bar-track">
                      <div className="bar-fill classical-fill" style={{ width: '20%' }}></div>
                    </div>
                  </div>

                  <div className="bar-row">
                    <div className="bar-label">
                      <span>{pqcMatch.algorithm} Key</span>
                      <span className="bar-val pqc-val">{pqcMatch.publicKeySizeBytes} Bytes</span>
                    </div>
                    <div className="bar-track">
                      <div className="bar-fill pqc-fill" style={{ width: `${20 * sizeRatio}%` }}></div>
                    </div>
                  </div>

                  {pqcMatch.ciphertextSizeBytes && (
                    <div className="bar-row">
                      <div className="bar-label">
                        <span>Ciphertext Size</span>
                        <span className="bar-val pqc-val">{pqcMatch.ciphertextSizeBytes} Bytes</span>
                      </div>
                      <div className="bar-track">
                        <div className="bar-fill pqc-alt-fill" style={{ width: `${20 * (pqcMatch.ciphertextSizeBytes / classicalSize)}%` }}></div>
                      </div>
                    </div>
                  )}

                  {pqcMatch.signatureSizeBytes && (
                    <div className="bar-row">
                      <div className="bar-label">
                        <span>Signature Size</span>
                        <span className="bar-val pqc-val">{pqcMatch.signatureSizeBytes} Bytes</span>
                      </div>
                      <div className="bar-track">
                        <div className="bar-fill pqc-alt-fill" style={{ width: `${20 * (pqcMatch.signatureSizeBytes / classicalSize)}%` }}></div>
                      </div>
                    </div>
                  )}
                </div>

                <div className="pqc-spec-details">
                  <div className="spec-card">
                    <h4>Security Level</h4>
                    <span className="spec-big">NIST L{pqcMatch.securityLevel}</span>
                  </div>
                  <div className="spec-card">
                    <h4>Compatibility</h4>
                    <span className={`spec-badge comp-${pqcMatch.deploymentCompatibility.toLowerCase()}`}>
                      {pqcMatch.deploymentCompatibility}
                    </span>
                  </div>
                  <div className="spec-card">
                    <h4>Implementation</h4>
                    <span className="spec-std">{pqcMatch.implementationStatus}</span>
                  </div>
                </div>

                <div className="pqc-note">
                  <strong>Architectural Note:</strong> {pqcMatch.deploymentCompatibilityNote}
                </div>
              </div>

            </div>
          )}
        </div>
      </div>
    </div>
  );
}
