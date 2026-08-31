// ============================================================
// Qrypto AI Advisor — §28 Finding Detail Page / Modal
//
// Shows:
// - Header (Algorithm, Risk Score, Quantum Status, Detected At, Evidence)
// - Why this matters
// - Business impact
// - Recommended migration
// - Code context
// - Generate remediation (code example generator)
// ============================================================

import React, { useState } from 'react';
import { X, ShieldAlert, Code2, Sparkles, Copy, Check, ArrowRight, ExternalLink, Zap } from 'lucide-react';
import type { Finding } from '../../types';
import { scoreToColor } from '../../engine/riskEngine';
import { getCodeRemediationGuide } from '../../api';
import './FindingDetailModal.css';

interface Props {
  finding: Finding;
  onClose: () => void;
}

export function FindingDetailModal({ finding, onClose }: Props) {
  const [copied, setCopied] = useState(false);
  const [remediationCode, setRemediationCode] = useState<string | null>(null);

  const handleGenerateRemediation = () => {
    const res = getCodeRemediationGuide(finding.algorithm, finding.language);
    if (res.data) {
      setRemediationCode(res.data.example);
    }
  };

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getWhyItMatters = (f: Finding): string => {
    const alg = f.algorithm.toUpperCase();
    if (alg.includes('RSA') || alg.includes('ECC') || alg === 'ECDH' || alg === 'ECDSA') {
      return `${f.algorithm} relies on mathematical problems (integer factorization or discrete logarithms) that can be solved in polynomial time by Shor's algorithm running on a Cryptographically-Relevant Quantum Computer (CRQC). Long-lived ciphertexts protected by this algorithm are vulnerable to Harvest-Now-Decrypt-Later (HNDL) attacks.`;
    }
    if (alg === 'MD5' || alg === 'SHA-1') {
      return `${f.algorithm} has known classical collision vulnerabilities. Adversaries can generate distinct inputs producing the exact same hash output. While quantum risk (Grover's algorithm) is minimal, the classical risk makes this algorithm obsolete for security-sensitive operations.`;
    }
    if (alg.includes('TLS 1.0') || alg.includes('TLS 1.1') || alg.includes('SSL')) {
      return `${f.algorithm} is deprecated by RFC 8996 and contains known classical vulnerabilities (BEAST, POODLE, LUCKY13). Transport layer encryption using obsolete TLS versions fails regulatory compliance requirements (PCI DSS, NIST CSF) and exposes data in transit.`;
    }
    if (f.category === 'secret') {
      return `Hardcoded credentials in source code pose an immediate operational security threat. Secret material checked into source control can be extracted by any user or system with repository read access, enabling unauthorized lateral movement.`;
    }
    return `${f.algorithm} usage has been identified for review. Evaluating cryptographic posture ensures long-term security resilience.`;
  };

  const getBusinessImpact = (f: Finding): string => {
    if (f.service.includes('Payment')) {
      return `Potential compromise of payment transaction channels, PCI DSS non-compliance audit findings, and retroactive exposure of stored financial records (data confidentiality requirement: ${f.dataLifetimeYears} years).`;
    }
    if (f.service.includes('Auth')) {
      return `Impersonation risk for internal and customer identities. If authentication keys are compromised, adversaries could forge session tokens, bypass MFA, and gain persistent administrative access across all downstream systems.`;
    }
    if (f.category === 'secret') {
      return `Immediate potential system compromise. Hardcoded secrets in production code could lead to unauthorized API access, data breach notifications, and immediate mandatory credential revocation.`;
    }
    return `Potential compliance audit findings (NIST CSF 2.0, ISO 27001), increased migration cost if deferred, and potential data exposure under harvest-now-decrypt-later scenarios.`;
  };

  return (
    <div className="modal-backdrop animate-fade-in" onClick={onClose}>
      <div className="modal-content finding-detail-modal" onClick={e => e.stopPropagation()}>

        {/* Modal Header */}
        <div className="fdm-header">
          <div className="fdm-title-area">
            <span className={`badge badge-${finding.severity}`}>{finding.severity.toUpperCase()}</span>
            <h2>{finding.algorithm}</h2>
            <span className="fdm-id">[{finding.id}]</span>
          </div>
          <button className="modal-close-btn" onClick={onClose} title="Close">
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="fdm-body">

          {/* Quick Metrics Bar — Section 25 */}
          <div className="fdm-metrics-bar">
            <div className="fdm-metric">
              <span className="fdm-m-label">Risk Score</span>
              <span className="fdm-m-val" style={{ color: scoreToColor(finding.riskScore) }}>
                {finding.riskScore} / 100
              </span>
            </div>
            <div className="fdm-metric">
              <span className="fdm-m-label">Algorithm Severity</span>
              <span className={`badge badge-${finding.algorithmSeverity ?? finding.severity}`}>
                {(finding.algorithmSeverity ?? finding.severity).toUpperCase()}
              </span>
            </div>
            <div className="fdm-metric">
              <span className="fdm-m-label">Quantum Status</span>
              <span className={`quantum-badge qb-${finding.quantumStatus}`}>
                {finding.quantumStatus.toUpperCase()}
              </span>
            </div>
            <div className="fdm-metric">
              <span className="fdm-m-label">Classical Status</span>
              <span className={`classical-badge cb-${finding.classicalStatus}`}>
                {finding.classicalStatus.toUpperCase()}
              </span>
            </div>
            <div className="fdm-metric">
              <span className="fdm-m-label">Confidence</span>
              <span className="fdm-m-val">
                {finding.confidence !== undefined ? `${Math.round(finding.confidence * 100)}%` : 'N/A'}
              </span>
            </div>
            <div className="fdm-metric">
              <span className="fdm-m-label">Context Source</span>
              <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                {finding.contextSource ?? 'UNKNOWN'}
              </span>
            </div>
            <div className="fdm-metric">
              <span className="fdm-m-label">Detection Layer</span>
              <span style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                {finding.evidence?.detectionLayers?.join(', ') ?? 'regex'}
              </span>
            </div>
            <div className="fdm-metric">
              <span className="fdm-m-label">Detected Location</span>
              <span className="fdm-m-loc" title={finding.file}>
                {finding.file}:{finding.line}
              </span>
            </div>
            {finding.fingerprint && (
              <div className="fdm-metric" style={{ gridColumn: 'span 2' }}>
                <span className="fdm-m-label">Fingerprint</span>
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)', wordBreak: 'break-all' }}>
                  {finding.fingerprint}
                </span>
              </div>
            )}
          </div>

          {/* Evidence Card */}
          <div className="fdm-section evidence-card">
            <h4><Code2 size={15} /> Evidence Snippet</h4>
            <div className="code-box">
              <code>{finding.detectedPattern}</code>
            </div>
          </div>

          {/* Section 1: Why This Matters (§28) */}
          <div className="fdm-section">
            <h3>1. Why This Matters</h3>
            <p>{getWhyItMatters(finding)}</p>
          </div>

          {/* Section 2: Business Impact (§28) */}
          <div className="fdm-section">
            <h3>2. Business Impact</h3>
            <p>{getBusinessImpact(finding)}</p>
          </div>

          {/* Section 3: Quantum Migration (§03) */}
          <div className="fdm-section quantum-migration-section">
            <h3><Zap size={15} style={{ display: 'inline', verticalAlign: 'middle', marginRight: 6 }} />3. Quantum Migration</h3>
            <div className="qm-grid">
              <div className="qm-card">
                <span className="qm-label">Current Algorithm</span>
                <span className="qm-value mono">{finding.algorithm}</span>
              </div>
              <div className="qm-card">
                <span className="qm-label">Current Usage</span>
                <span className="qm-value">{finding.service}{finding.category ? ` (${finding.category})` : ''}</span>
              </div>
              <div className="qm-card">
                <span className="qm-label">Quantum Status</span>
                <span className={`quantum-badge qb-${finding.quantumStatus}`}>{finding.quantumStatus.replace(/-/g, ' ').toUpperCase()}</span>
              </div>
              <div className="qm-card qm-wide">
                <span className="qm-label">Threat</span>
                <span className="qm-value">
                  {finding.quantumStatus === 'vulnerable'
                    ? `${finding.algorithm} is vulnerable to Shor's algorithm on a Cryptographically-Relevant Quantum Computer (CRQC). ${
                        finding.algorithm.toUpperCase().includes('RSA') || finding.algorithm.toUpperCase().includes('ECC') || finding.algorithm.toUpperCase().includes('ECDH')
                          ? 'Integer factorization / discrete logarithm can be solved in polynomial time.'
                          : finding.algorithm.toUpperCase().includes('MD5') || finding.algorithm.toUpperCase().includes('SHA-1')
                          ? 'Grover\'s algorithm reduces effective hash security by half, though classical collision attacks already exist.'
                          : 'Classical security assumptions may not hold under quantum computation.'
                      }`
                    : finding.quantumStatus === 'classical-weak'
                    ? `${finding.algorithm} has known classical vulnerabilities. While not directly broken by quantum algorithms, it should be replaced with modern, quantum-resistant alternatives.`
                    : finding.quantumStatus === 'quantum-resistant'
                    ? `${finding.algorithm} is considered quantum-resistant under current cryptographic analysis.`
                    : `${finding.algorithm} quantum status requires evaluation.`
                  }
                </span>
              </div>
              <div className="qm-card">
                <span className="qm-label">Recommended PQC Target</span>
                <span className="qm-value highlight-text">{
                  finding.recommendedAlgorithm || (
                    // Usage-aware recommendation based on algorithm category
                    finding.category === 'certificate' || finding.category === 'signature'
                      ? 'ML-DSA-65 (FIPS 204)'
                      : finding.category === 'secret'
                      ? 'N/A — Rotate and use secrets manager'
                      : finding.category === 'tls'
                      ? 'Hybrid ML-KEM-768 + X25519 (TLS 1.3)'
                      : 'ML-KEM-768 (FIPS 203)'
                  )
                }</span>
              </div>
              <div className="qm-card qm-wide">
                <span className="qm-label">Reason</span>
                <span className="qm-value">
                  {finding.recommendedAlgorithm
                    ? `Recommended based on detected usage pattern: ${finding.algorithm} used for ${finding.service || finding.category || 'general purpose'}.`
                    : finding.category === 'certificate' || finding.category === 'signature'
                    ? `ML-DSA-65 selected because ${finding.algorithm} is used for digital signatures. ML-DSA (CRYSTALS-Dilithium) is NIST's primary standard for post-quantum digital signatures (FIPS 204).`
                    : finding.category === 'tls'
                    ? `Hybrid ML-KEM-768 + X25519 selected because ${finding.algorithm} is used in TLS key exchange. Hybrid mode provides defense-in-depth: if either algorithm is broken, the other maintains security.`
                    : finding.category === 'secret'
                    ? 'Secret material must be rotated and stored in a centralized secrets manager. No PQC replacement needed — the issue is secret exposure, not algorithm weakness.'
                    : `ML-KEM-768 (CRYSTALS-Kyber) selected as NIST's primary standard for post-quantum key encapsulation (FIPS 203), providing NIST Level 3 security (approximately equivalent to AES-192).`
                  }
                </span>
              </div>
              {finding.confidence !== undefined && (
                <div className="qm-card">
                  <span className="qm-label">Confidence</span>
                  <span className="qm-value">{Math.round(finding.confidence * 100)}%</span>
                </div>
              )}
              {finding.evidence?.detectionLayers && (
                <div className="qm-card">
                  <span className="qm-label">Evidence</span>
                  <span className="qm-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{finding.evidence.detectionLayers.join(', ')}</span>
                </div>
              )}
            </div>
          </div>

          {/* Section 4: Recommended Migration (§28) */}
          <div className="fdm-section">
            <h3>4. Migration Strategy</h3>
            <div className="rec-box">
              <div className="rec-row">
                <strong>Recommended Target:</strong>
                <span className="highlight-text">{finding.recommendedAlgorithm || 'ML-KEM-768 / ML-DSA-65 (NIST PQC Standard)'}</span>
              </div>
              <div className="rec-row">
                <strong>Migration Strategy:</strong>
                <span>{finding.migrationStrategy || 'Phased hybrid adoption followed by full classical algorithm deprecation.'}</span>
              </div>
            </div>
          </div>

          {/* Section 5: Code Context (§28) */}
          <div className="fdm-section">
            <h3>5. Code Context</h3>
            <div className="code-context-box">
              <div className="cc-header">
                <span>{finding.file}</span>
                <span className="cc-lang">{finding.language.toUpperCase()}</span>
              </div>
              <div className="cc-body">
                <div className="cc-line highlighted">
                  <span className="cc-num">{finding.line}</span>
                  <span className="cc-code">{finding.detectedPattern}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Section 6: Generate Remediation (§28) */}
          <div className="fdm-section remediation-section">
            <div className="rem-header">
              <h3>6. Code Remediation Example</h3>
              {!remediationCode && (
                <button className="btn btn-primary btn-sm" onClick={handleGenerateRemediation}>
                  <Sparkles size={14} /> Generate Code Example
                </button>
              )}
            </div>

            {remediationCode && (
              <div className="remediation-output animate-slide-in">
                <div className="rem-code-bar">
                  <span>Remediation Example ({finding.language})</span>
                  <button className="btn-copy" onClick={() => copyCode(remediationCode)}>
                    {copied ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy Code</>}
                  </button>
                </div>
                <pre className="rem-code-block">
                  <code>{remediationCode}</code>
                </pre>
                <div className="rem-disclaimer">
                  ⚠️ <em>Example code for demonstration purposes only. Validate all cryptographic logic before deploying to production.</em>
                </div>
              </div>
            )}
          </div>

        </div>

        {/* Modal Footer */}
        <div className="fdm-footer">
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>

      </div>
    </div>
  );
}
