// ============================================================
// Qrypto — Algorithm Registry
//
// Canonical mapping from detected algorithm names to normalized
// properties. This is the single source of truth for:
//   - CycloneDX primitive/OID assignments (P0-5)
//   - NIST standardization status
//   - Quantum vulnerability classification
//   - PQC replacement recommendations
//
// Keyed by canonical lowercase name. The scanner normalizes
// algorithm strings before lookup; unknown algorithms pass
// through with sensible defaults.
// ============================================================

import type { QuantumStatus, Severity, AlgorithmCategory } from '../types';

export interface AlgorithmEntry {
  /** Canonical display name (e.g. "RSA-2048", "ML-KEM-768"). */
  canonicalName: string;
  /** CycloneDX 1.6 primitive type. */
  cycloneDxPrimitive: string;
  /** NIST OID if assigned, else undefined. */
  oid?: string;
  /** NIST standardization document. */
  nistStandard?: string;
  /** Quantum vulnerability status. */
  quantumStatus: QuantumStatus;
  /** Classical security status. */
  classicalStatus: 'broken' | 'weak' | 'adequate' | 'strong';
  /** Intrinsic severity (pre-context). */
  severity: Severity;
  /** Category. */
  category: AlgorithmCategory;
  /** Recommended PQC replacement if applicable. */
  pqcReplacement?: string;
  /** NIST PQC standard for the replacement. */
  pqcStandard?: string;
}

// ─── Registry ─────────────────────────────────────────────────

const REGISTRY: Record<string, AlgorithmEntry> = {
  // ── RSA family ──────────────────────────────────────────────
  'rsa': {
    canonicalName: 'RSA',
    cycloneDxPrimitive: 'public-key',
    oid: '1.2.840.113549.1.1.1',
    nistStandard: 'FIPS 186-5',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'public-key',
    pqcReplacement: 'ML-KEM (FIPS 203) for key exchange; ML-DSA (FIPS 204) for signatures',
    pqcStandard: 'FIPS 203 / FIPS 204',
  },
  'rsa-2048': {
    canonicalName: 'RSA-2048',
    cycloneDxPrimitive: 'public-key',
    oid: '1.2.840.113549.1.1.1',
    nistStandard: 'FIPS 186-5',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'public-key',
    pqcReplacement: 'ML-KEM-768 (FIPS 203) for key exchange; ML-DSA-65 (FIPS 204) for signatures',
    pqcStandard: 'FIPS 203 / FIPS 204',
  },
  'rsa-4096': {
    canonicalName: 'RSA-4096',
    cycloneDxPrimitive: 'public-key',
    oid: '1.2.840.113549.1.1.1',
    nistStandard: 'FIPS 186-5',
    quantumStatus: 'vulnerable',
    classicalStatus: 'strong',
    severity: 'medium',
    category: 'public-key',
    pqcReplacement: 'ML-KEM-1024 (FIPS 203) for key exchange',
    pqcStandard: 'FIPS 203',
  },

  // ── ECC family ──────────────────────────────────────────────
  'ecdsa': {
    canonicalName: 'ECDSA',
    cycloneDxPrimitive: 'public-key',
    oid: '1.2.840.10045.2.1',
    nistStandard: 'FIPS 186-5',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'signature',
    pqcReplacement: 'ML-DSA-65 (FIPS 204)',
    pqcStandard: 'FIPS 204',
  },
  'ecdh': {
    canonicalName: 'ECDH',
    cycloneDxPrimitive: 'key-exchange',
    oid: '1.2.840.10045.2.1',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'key-exchange',
    pqcReplacement: 'ML-KEM-768 (FIPS 203)',
    pqcStandard: 'FIPS 203',
  },
  'ecc': {
    canonicalName: 'ECC',
    cycloneDxPrimitive: 'public-key',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'public-key',
    pqcReplacement: 'ML-KEM (FIPS 203) or ML-DSA (FIPS 204) depending on usage',
    pqcStandard: 'FIPS 203 / FIPS 204',
  },
  'secp256r1': {
    canonicalName: 'secp256r1 (P-256)',
    cycloneDxPrimitive: 'public-key',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'public-key',
    pqcReplacement: 'ML-KEM-768 (FIPS 203)',
    pqcStandard: 'FIPS 203',
  },
  'x25519': {
    canonicalName: 'X25519',
    cycloneDxPrimitive: 'key-exchange',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'medium',
    category: 'key-exchange',
    pqcReplacement: 'ML-KEM-768 (FIPS 203) hybrid X25519+ML-KEM',
    pqcStandard: 'FIPS 203',
  },
  'ed25519': {
    canonicalName: 'Ed25519',
    cycloneDxPrimitive: 'public-key',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'medium',
    category: 'signature',
    pqcReplacement: 'ML-DSA-65 (FIPS 204)',
    pqcStandard: 'FIPS 204',
  },
  'dh': {
    canonicalName: 'DH',
    cycloneDxPrimitive: 'key-exchange',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'key-exchange',
    pqcReplacement: 'ML-KEM-768 (FIPS 203)',
    pqcStandard: 'FIPS 203',
  },
  'dsa': {
    canonicalName: 'DSA',
    cycloneDxPrimitive: 'public-key',
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    category: 'signature',
    pqcReplacement: 'ML-DSA-65 (FIPS 204)',
    pqcStandard: 'FIPS 204',
  },

  // ── Symmetric ───────────────────────────────────────────────
  'aes-256-gcm': {
    canonicalName: 'AES-256-GCM',
    cycloneDxPrimitive: 'cipher',
    oid: '2.16.840.1.101.3.4.1.46',
    nistStandard: 'FIPS 197',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'symmetric',
  },
  'aes-256': {
    canonicalName: 'AES-256',
    cycloneDxPrimitive: 'cipher',
    oid: '2.16.840.1.101.3.4.1.41',
    nistStandard: 'FIPS 197',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'symmetric',
  },
  'aes-128': {
    canonicalName: 'AES-128',
    cycloneDxPrimitive: 'cipher',
    oid: '2.16.840.1.101.3.4.1.2',
    nistStandard: 'FIPS 197',
    quantumStatus: 'adequate',
    classicalStatus: 'adequate',
    severity: 'low',
    category: 'symmetric',
  },
  'aes': {
    canonicalName: 'AES',
    cycloneDxPrimitive: 'cipher',
    nistStandard: 'FIPS 197',
    quantumStatus: 'adequate',
    classicalStatus: 'adequate',
    severity: 'info',
    category: 'symmetric',
  },
  'chacha20-poly1305': {
    canonicalName: 'ChaCha20-Poly1305',
    cycloneDxPrimitive: 'cipher',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'symmetric',
  },

  // ── Hash ─────────────────────────────────────────────────────
  'sha-256': {
    canonicalName: 'SHA-256',
    cycloneDxPrimitive: 'hash',
    oid: '2.16.840.1.101.3.4.2.1',
    nistStandard: 'FIPS 180-4',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'hash',
  },
  'sha-384': {
    canonicalName: 'SHA-384',
    cycloneDxPrimitive: 'hash',
    oid: '2.16.840.1.101.3.4.2.2',
    nistStandard: 'FIPS 180-4',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'hash',
  },
  'sha-512': {
    canonicalName: 'SHA-512',
    cycloneDxPrimitive: 'hash',
    oid: '2.16.840.1.101.3.4.2.3',
    nistStandard: 'FIPS 180-4',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'hash',
  },
  'sha-3': {
    canonicalName: 'SHA-3',
    cycloneDxPrimitive: 'hash',
    nistStandard: 'FIPS 202',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'hash',
  },
  'sha-1': {
    canonicalName: 'SHA-1',
    cycloneDxPrimitive: 'hash',
    oid: '1.3.14.3.2.26',
    nistStandard: 'NIST deprecated',
    quantumStatus: 'classical-weak',
    classicalStatus: 'weak',
    severity: 'high',
    category: 'hash',
  },
  'md5': {
    canonicalName: 'MD5',
    cycloneDxPrimitive: 'hash',
    oid: '1.2.840.113549.2.5',
    quantumStatus: 'classical-weak',
    classicalStatus: 'broken',
    severity: 'critical',
    category: 'hash',
  },

  // ── Broken / deprecated ─────────────────────────────────────
  'des': {
    canonicalName: 'DES',
    cycloneDxPrimitive: 'cipher',
    quantumStatus: 'classical-weak',
    classicalStatus: 'broken',
    severity: 'critical',
    category: 'symmetric',
  },
  '3des': {
    canonicalName: '3DES',
    cycloneDxPrimitive: 'cipher',
    quantumStatus: 'classical-weak',
    classicalStatus: 'broken',
    severity: 'critical',
    category: 'symmetric',
  },
  'rc4': {
    canonicalName: 'RC4',
    cycloneDxPrimitive: 'cipher',
    quantumStatus: 'classical-weak',
    classicalStatus: 'broken',
    severity: 'critical',
    category: 'symmetric',
  },

  // ── TLS ──────────────────────────────────────────────────────
  'tls 1.0': {
    canonicalName: 'TLS 1.0',
    cycloneDxPrimitive: 'protocol',
    quantumStatus: 'classical-weak',
    classicalStatus: 'weak',
    severity: 'high',
    category: 'tls',
  },
  'tls 1.1': {
    canonicalName: 'TLS 1.1',
    cycloneDxPrimitive: 'protocol',
    quantumStatus: 'classical-weak',
    classicalStatus: 'weak',
    severity: 'high',
    category: 'tls',
  },
  'tls 1.2': {
    canonicalName: 'TLS 1.2',
    cycloneDxPrimitive: 'protocol',
    quantumStatus: 'adequate',
    classicalStatus: 'adequate',
    severity: 'low',
    category: 'tls',
  },
  'tls 1.3': {
    canonicalName: 'TLS 1.3',
    cycloneDxPrimitive: 'protocol',
    nistStandard: 'RFC 8446',
    quantumStatus: 'adequate',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'tls',
  },

  // ── PQC (NIST FIPS 203/204/205) ────────────────────────────
  'ml-kem': {
    canonicalName: 'ML-KEM',
    cycloneDxPrimitive: 'key-exchange',
    nistStandard: 'FIPS 203',
    quantumStatus: 'quantum-resistant',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'pqc',
  },
  'ml-kem-768': {
    canonicalName: 'ML-KEM-768',
    cycloneDxPrimitive: 'key-exchange',
    nistStandard: 'FIPS 203',
    quantumStatus: 'quantum-resistant',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'pqc',
  },
  'ml-kem-1024': {
    canonicalName: 'ML-KEM-1024',
    cycloneDxPrimitive: 'key-exchange',
    nistStandard: 'FIPS 203',
    quantumStatus: 'quantum-resistant',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'pqc',
  },
  'ml-dsa': {
    canonicalName: 'ML-DSA',
    cycloneDxPrimitive: 'public-key',
    nistStandard: 'FIPS 204',
    quantumStatus: 'quantum-resistant',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'pqc',
  },
  'ml-dsa-65': {
    canonicalName: 'ML-DSA-65',
    cycloneDxPrimitive: 'public-key',
    nistStandard: 'FIPS 204',
    quantumStatus: 'quantum-resistant',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'pqc',
  },
  'slh-dsa': {
    canonicalName: 'SLH-DSA',
    cycloneDxPrimitive: 'public-key',
    nistStandard: 'FIPS 205',
    quantumStatus: 'quantum-resistant',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'pqc',
  },
  'falcon': {
    canonicalName: 'FALCON',
    cycloneDxPrimitive: 'public-key',
    quantumStatus: 'quantum-resistant',
    classicalStatus: 'strong',
    severity: 'info',
    category: 'pqc',
  },
};

// ─── Public API ───────────────────────────────────────────────

/**
 * Look up an algorithm by name (case-insensitive).
 * Returns the registry entry if found, or a sensible default.
 */
export function lookupAlgorithm(name: string): AlgorithmEntry {
  const normalized = name.toLowerCase().trim();

  // Exact match
  if (REGISTRY[normalized]) return REGISTRY[normalized];

  // Try to match without key size suffix (e.g. "rsa-2048" → "rsa")
  const base = normalized.replace(/[- ]?\d+(-bit)?$/, '').trim();
  if (REGISTRY[base]) return REGISTRY[base];

  // Try partial match
  for (const [key, entry] of Object.entries(REGISTRY)) {
    if (normalized.includes(key) || key.includes(normalized)) return entry;
  }

  // Default: unknown algorithm — pass through with neutral defaults
  return {
    canonicalName: name,
    cycloneDxPrimitive: 'unknown',
    quantumStatus: 'unknown',
    classicalStatus: 'adequate',
    severity: 'medium',
    category: 'public-key',
  };
}

/**
 * Normalize an algorithm name to its canonical form.
 */
export function normalizeAlgorithm(name: string): string {
  return lookupAlgorithm(name).canonicalName;
}

/**
 * Get all registry entries (for UI dropdowns, reports, etc.).
 */
export function getAllAlgorithms(): AlgorithmEntry[] {
  return Object.values(REGISTRY);
}
