// ============================================================
// §13 — Detector: Post-Quantum Cryptography (PQC)
// ML-KEM, ML-DSA, SLH-DSA, FALCON — healthy findings
// These should be detected as quantum-resistant (positive indicator)
// ============================================================

import type { CryptoPattern } from './rsa';

export const PQC_PATTERNS: CryptoPattern[] = [
  // ML-KEM / CRYSTALS-Kyber (FIPS 203) — key encapsulation
  {
    regex: /ML-?KEM|CRYSTALS-?Kyber|kyber|Kyber(?:512|768|1024)/gi,
    algorithm: 'ML-KEM',
    category: 'pqc',
    quantumStatus: 'quantum-resistant',
    baseSeverity: 'info',
    usage: 'post-quantum key encapsulation',
    confidence: 0.96,
  },

  // ML-DSA / CRYSTALS-Dilithium (FIPS 204) — signatures
  {
    regex: /ML-?DSA|CRYSTALS-?Dilithium|dilithium/gi,
    algorithm: 'ML-DSA',
    category: 'pqc',
    quantumStatus: 'quantum-resistant',
    baseSeverity: 'info',
    usage: 'post-quantum digital signature',
    confidence: 0.96,
  },

  // SLH-DSA / SPHINCS+ (FIPS 205) — hash-based signatures
  {
    regex: /SLH-?DSA|SPHINCS\+?|sphincsplus/gi,
    algorithm: 'SLH-DSA',
    category: 'pqc',
    quantumStatus: 'quantum-resistant',
    baseSeverity: 'info',
    usage: 'post-quantum digital signature (hash-based)',
    confidence: 0.96,
  },

  // FALCON — lattice signature (NIST candidate)
  {
    regex: /FALCON|falcon-(?:512|1024)/gi,
    algorithm: 'FALCON',
    category: 'pqc',
    quantumStatus: 'quantum-resistant',
    baseSeverity: 'info',
    usage: 'post-quantum digital signature',
    confidence: 0.95,
  },

  // Hybrid key establishment (X25519 + ML-KEM)
  {
    regex: /X25519Kyber768|x25519kyber|hybrid.*kyber|kyber.*hybrid/gi,
    algorithm: 'Hybrid X25519+ML-KEM',
    category: 'pqc',
    quantumStatus: 'quantum-resistant',
    baseSeverity: 'info',
    usage: 'hybrid post-quantum key establishment',
    confidence: 0.93,
  },
];
