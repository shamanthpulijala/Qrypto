// ============================================================
// Qrypto — Hybrid Migration: Dual-Encapsulation Circuit
//
// Data-driven visualization of Hybrid Key Exchange combining
// classical + post-quantum KEM security.
//
// The component reads actual findings from the assessment and
// determines the correct hybrid combination to visualize.
// Only key-establishment (KEM) algorithms are shown in the circuit.
// Signature algorithms are handled separately with a message.
// ============================================================

import React, { useMemo, useState } from 'react';
import { Layers, Network, Lock, Zap, Shield, ChevronRight, Activity, AlertTriangle, Info } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import type { Finding } from '../../types';
import './HybridMigration.css';

// ─── KEM-compatible algorithm mappings ─────────────────────────
// Maps classical key-establishment algorithms to their PQC hybrid partners.

interface HybridPair {
  classical: string;
  classicalShort: string;
  classicalType: string;       // e.g., 'ECDH', 'DH', 'X25519'
  pqc: string;
  pqcShort: string;
  pqcType: string;             // e.g., 'ML-KEM-768'
  pqcCiphertext: string;       // e.g., '1088B'
  usage: string;               // description of how this is used
  note: string;                // why this combination is secure
}

const KEM_PAIRS: HybridPair[] = [
  {
    classical: 'X25519',
    classicalShort: 'X25519',
    classicalType: 'ECDH',
    pqc: 'ML-KEM-768',
    pqcShort: 'ML-KEM',
    pqcType: 'FIPS 203',
    pqcCiphertext: '1088B',
    usage: 'TLS 1.3 key exchange, WireGuard, Signal Protocol',
    note: 'X25519 provides classical ECDH security. ML-KEM-768 provides NIST Level 3 post-quantum security. Combined via HKDF for defense-in-depth.',
  },
  {
    classical: 'X25519',
    classicalShort: 'X25519',
    classicalType: 'ECDH',
    pqc: 'ML-KEM-1024',
    pqcShort: 'ML-KEM',
    pqcType: 'FIPS 203',
    pqcCiphertext: '1568B',
    usage: 'High-security TLS, government systems',
    note: 'Maximum post-quantum security (NIST Level 5). Larger key/ciphertext sizes but strongest protection.',
  },
  {
    classical: 'ECDH (P-256)',
    classicalShort: 'P-256',
    classicalType: 'ECDH',
    pqc: 'ML-KEM-768',
    pqcShort: 'ML-KEM',
    pqcType: 'FIPS 203',
    pqcCiphertext: '1088B',
    usage: 'Legacy TLS, payment systems, VPN',
    note: 'Common NIST P-256 curve combined with ML-KEM-768 for hybrid key exchange.',
  },
  {
    classical: 'ECDH (P-384)',
    classicalShort: 'P-384',
    classicalType: 'ECDH',
    pqc: 'ML-KEM-1024',
    pqcShort: 'ML-KEM',
    pqcType: 'FIPS 203',
    pqcCiphertext: '1568B',
    usage: 'High-security applications, government PKI',
    note: 'P-384 matched with ML-KEM-1024 for equivalent security levels.',
  },
  {
    classical: 'DH (2048-bit)',
    classicalShort: 'DH',
    classicalType: 'DH',
    pqc: 'ML-KEM-768',
    pqcShort: 'ML-KEM',
    pqcType: 'FIPS 203',
    pqcCiphertext: '1088B',
    usage: 'Legacy SSH, IKE/IPsec',
    note: 'Discrete logarithm-based DH combined with lattice KEM for hybrid key exchange.',
  },
  {
    classical: 'RSA (2048-bit)',
    classicalShort: 'RSA',
    classicalType: 'RSA-KEM',
    pqc: 'ML-KEM-768',
    pqcShort: 'ML-KEM',
    pqcType: 'FIPS 203',
    pqcCiphertext: '1088B',
    usage: 'RSA key transport (legacy), some TLS configs',
    note: 'RSA key transport is being deprecated. Hybrid with ML-KEM provides transitional security. Prefer ECDH+ML-KEM for new deployments.',
  },
];

// ─── Signature-only algorithms (not KEM-compatible) ───────────

const SIGNATURE_ONLY = ['ECDSA', 'Ed25519', 'RSA-SHA256', 'RSA-SHA512', 'ML-DSA', 'SLH-DSA'];

function isSignatureAlgorithm(algo: string): boolean {
  const upper = algo.toUpperCase();
  return SIGNATURE_ONLY.some(s => upper.includes(s)) ||
    upper.includes('SIGN') ||
    upper.includes('DSA') && !upper.includes('ML-KEM');
}

// ─── Find best hybrid pair for a finding ──────────────────────

function findHybridPair(finding: Finding): HybridPair | null {
  const algo = finding.algorithm.toUpperCase();

  // Direct matches
  if (algo.includes('X25519') || algo.includes('25519')) {
    if (algo.includes('1024')) return KEM_PAIRS[1];
    return KEM_PAIRS[0];
  }
  if (algo.includes('P-384') || algo.includes('P384')) {
    return KEM_PAIRS[3];
  }
  if (algo.includes('P-256') || algo.includes('P256') || algo.includes('ECDH') || algo.includes('ECC')) {
    return KEM_PAIRS[2];
  }
  if (algo.includes('DH') && !algo.includes('EDH')) {
    return KEM_PAIRS[4];
  }
  if (algo.includes('RSA') && (algo.includes('KEM') || finding.category === 'key-exchange')) {
    return KEM_PAIRS[5];
  }

  // Check if it's a key-exchange category
  if (finding.category === 'key-exchange' || finding.category === 'tls') {
    // Default to X25519 + ML-KEM-768 for generic key exchange
    return KEM_PAIRS[0];
  }

  return null;
}

// ─── Sub-components ────────────────────────────────────────────

function ServerIcon() {
  return (
    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="opacity-50">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
      <line x1="6" y1="6" x2="6.01" y2="6"></line>
      <line x1="6" y1="18" x2="6.01" y2="18"></line>
    </svg>
  );
}

// ─── Main Component ────────────────────────────────────────────

export function HybridMigration() {
  const { assessment } = useAppStore();

  // Extract hybrid pairs from actual findings
  const hybridData = useMemo(() => {
    if (!assessment) return { pairs: [], signatureFindings: [] as Finding[], noKEM: false };

    // Find key-establishment findings
    const keyExchangeFindings = assessment.findings.filter(f =>
      f.category === 'key-exchange' ||
      f.category === 'tls' ||
      f.algorithm.toUpperCase().includes('ECDH') ||
      f.algorithm.toUpperCase().includes('X25519') ||
      f.algorithm.toUpperCase().includes('RSA') ||
      (f.algorithm.toUpperCase().includes('DH') && !f.algorithm.toUpperCase().includes('EDH'))
    );

    const signatureFindings = assessment.findings.filter(f =>
      isSignatureAlgorithm(f.algorithm) && !keyExchangeFindings.includes(f)
    );

    // Find unique pairs
    const seenPairs = new Set<string>();
    const pairs: HybridPair[] = [];

    for (const f of keyExchangeFindings) {
      const pair = findHybridPair(f);
      if (pair && !seenPairs.has(pair.classical + pair.pqc)) {
        seenPairs.add(pair.classical + pair.pqc);
        pairs.push(pair);
      }
    }

    return {
      pairs,
      signatureFindings,
      noKEM: pairs.length === 0 && keyExchangeFindings.length === 0,
    };
  }, [assessment]);

  // Selected pair for detailed view
  const [selectedIdx, setSelectedIdx] = useState(0);
  const selectedPair = hybridData.pairs[selectedIdx] ?? hybridData.pairs[0] ?? null;

  if (!assessment) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">🔗</div>
        <h2>No Scan Loaded</h2>
        <p>Run a scan to visualize hybrid key exchange opportunities.</p>
      </div>
    );
  }

  // No KEM-compatible findings
  if (hybridData.noKEM) {
    return (
      <div className="hybrid-migration-page animate-fade-in">
        <div className="hybrid-header">
          <Layers size={24} className="text-accent-violet" />
          <h2>The Dual-Encapsulation Circuit</h2>
          <p>Interactive visualization of Hybrid Key Exchange combining classical and post-quantum security.</p>
        </div>

        <div className="card" style={{ padding: '48px', textAlign: 'center' }}>
          <AlertTriangle size={48} style={{ color: 'var(--text-tertiary)', marginBottom: 16 }} />
          <h3 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>No Key-Exchange Algorithms Detected</h3>
          <p style={{ color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto' }}>
            Your scan did not detect any key-establishment algorithms (ECDH, X25519, DH, RSA-KEM).
            Hybrid visualization requires key-exchange findings to generate the dual-encapsulation circuit.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="hybrid-migration-page animate-fade-in">
      <div className="hybrid-header">
        <Layers size={24} className="text-accent-violet" />
        <h2>The Dual-Encapsulation Circuit</h2>
        <p>Interactive visualization of Hybrid Key Exchange combining classical + post-quantum (PQC) security.
        Based on your scan's detected key-establishment algorithms.</p>
      </div>

      {/* Pair Selector (if multiple pairs found) */}
      {hybridData.pairs.length > 1 && (
        <div className="card" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <Info size={14} style={{ color: 'var(--accent-cyan)' }} />
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              {hybridData.pairs.length} hybrid key-exchange combinations detected — select one to visualize:
            </span>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {hybridData.pairs.map((pair, i) => (
              <button
                key={i}
                className={`btn ${selectedIdx === i ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                onClick={() => setSelectedIdx(i)}
              >
                {pair.classicalShort} + {pair.pqcShort}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Circuit Visualization */}
      {selectedPair && (
        <div className="circuit-board card">
          <div className="circuit-grid">

            {/* LEFT: Client */}
            <div className="circuit-side client-side">
              <div className="endpoint">
                <ServerIcon />
                <h4>Client (Initiator)</h4>
              </div>
            </div>

            {/* CENTER: The Hybrid KEM Flow */}
            <div className="circuit-core">

              {/* Layer 1: Classical */}
              <div className="kem-layer classical-layer">
                <div className="layer-title"><Lock size={14} /> Classical KEM ({selectedPair.classicalShort})</div>
                <div className="flow-track">
                  <div className="pulse-packet classical-packet right"></div>
                  <div className="pulse-packet classical-packet left"></div>
                  <span className="track-label">{selectedPair.classicalType} Share</span>
                </div>
                <div className="secret-node">
                  <div className="node-inner classical-secret">K1</div>
                </div>
              </div>

              {/* Layer 2: Post-Quantum */}
              <div className="kem-layer pqc-layer">
                <div className="layer-title"><Shield size={14} /> Post-Quantum KEM ({selectedPair.pqc} — {selectedPair.pqcType})</div>
                <div className="flow-track">
                  <div className="pulse-packet pqc-packet right"></div>
                  <div className="pulse-packet pqc-packet left"></div>
                  <span className="track-label">Ciphertext ({selectedPair.pqcCiphertext})</span>
                </div>
                <div className="secret-node">
                  <div className="node-inner pqc-secret">K2</div>
                </div>
              </div>

              {/* The Combiner */}
              <div className="combiner-stage">
                <div className="combiner-lines">
                  <div className="c-line c-top"></div>
                  <div className="c-line c-bottom"></div>
                </div>

                <div className="kdf-node">
                  <div className="kdf-core">
                    <Activity size={20} className="kdf-icon" />
                    <span>HKDF Combine</span>
                  </div>
                </div>

                <div className="final-secret">
                  <ChevronRight size={20} className="text-accent-cyan" />
                  <div className="quantum-safe-key">
                    <Zap size={16} />
                    <span>Quantum-Safe Shared Secret</span>
                  </div>
                </div>
              </div>

            </div>

            {/* RIGHT: Server */}
            <div className="circuit-side server-side">
              <div className="endpoint">
                <ServerIcon />
                <h4>Server (Responder)</h4>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* Algorithm Details */}
      {selectedPair && (
        <div className="card" style={{ padding: '20px 24px' }}>
          <h3 style={{ fontSize: '0.95rem', color: 'var(--text-primary)', marginBottom: 12 }}>
            Why This Combination Is Secure
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ background: 'rgba(99, 102, 241, 0.06)', borderRadius: 8, padding: 16, border: '1px solid rgba(99, 102, 241, 0.15)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#818cf8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
                Classical Layer
              </div>
              <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>{selectedPair.classical}</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Provides security against classical attacks. Even if the PQC algorithm has an undiscovered weakness, the classical layer maintains security.
              </div>
            </div>
            <div style={{ background: 'rgba(77, 208, 225, 0.06)', borderRadius: 8, padding: 16, border: '1px solid rgba(77, 208, 225, 0.15)' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
                Post-Quantum Layer
              </div>
              <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>{selectedPair.pqc} ({selectedPair.pqcType})</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Provides security against quantum computer attacks (Shor's algorithm). NIST-standardized lattice-based key encapsulation.
              </div>
            </div>
          </div>
          <div style={{ marginTop: 16, fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6, padding: '12px 16px', background: 'rgba(255,255,255,0.03)', borderRadius: 8 }}>
            <strong style={{ color: 'var(--text-primary)' }}>Usage:</strong> {selectedPair.usage}
            <br />
            <strong style={{ color: 'var(--text-primary)' }}>Security rationale:</strong> {selectedPair.note}
          </div>
        </div>
      )}

      {/* Signature-only notice */}
      {hybridData.signatureFindings.length > 0 && (
        <div className="card" style={{ padding: '16px 20px', borderLeft: '3px solid var(--accent-violet)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Info size={14} style={{ color: 'var(--accent-violet)' }} />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Signature Algorithms Detected (Not KEM-Compatible)
            </span>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Your scan found {hybridData.signatureFindings.length} signature-based algorithm(s):
            {' '}
            {Array.from(new Set(hybridData.signatureFindings.map(f => f.algorithm))).slice(0, 5).join(', ')}.
            These use <strong>ML-DSA</strong> or <strong>SLH-DSA</strong> for post-quantum migration,
            not the KEM circuit shown above. Signature migration is handled in the PQC Recommendations page.
          </p>
        </div>
      )}

      {/* Code Mapping Abstraction */}
      <div className="hybrid-code-mapping card">
        <div className="card-header" style={{ padding: '16px 24px', borderBottom: '1px solid var(--glass-border)' }}>
          <h3><Network size={16} style={{ display: 'inline', marginRight: 8, verticalAlign: 'middle' }} />
            Implementation Mapping (TLS 1.3)
          </h3>
        </div>
        <div className="mapping-grid">
          <div className="map-block">
            <h4>SupportedGroups Extension</h4>
            <code>{selectedPair ? `Hybrid(${selectedPair.classicalShort} + ${selectedPair.pqcShort})` : 'X25519_Kyber768Draft00 (0x6399)'}</code>
            <p>Signals support for hybrid key exchange in the TLS handshake.</p>
          </div>
          <div className="map-block">
            <h4>KeyShareEntry</h4>
            <code>{selectedPair ? `struct {\n  opaque classical_key[${selectedPair.classicalType === 'ECDH' ? '32' : '256'}];\n  opaque pqc_key_exchange[${selectedPair.pqcCiphertext.replace('B', '')}];\n}` : 'struct {\n  opaque x25519_key_exchange[32];\n  opaque kyber_key_exchange[1184];\n}'}</code>
            <p>Concatenated public keys sent in ClientHello.</p>
          </div>
          <div className="map-block">
            <h4>Key Derivation</h4>
            <code>{`Secret = HKDF-Extract(\n  salt,\n  concat(K_${selectedPair?.classicalShort?.toLowerCase() ?? 'x25519'}, K_${selectedPair?.pqcShort?.toLowerCase()?.replace('-', '') ?? 'kem'})\n)`}</code>
            <p>Ensures security if either algorithm remains unbroken.</p>
          </div>
        </div>
      </div>

    </div>
  );
}
