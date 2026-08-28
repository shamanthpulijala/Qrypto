// ============================================================
// Qrypto — PQC Trade-Off Model
//
// Evidence-based, honest PQC trade-off information.
// Uses authoritative NIST specification data for known parameters.
//
// CRITICAL HONESTY RULE:
//   - Do NOT hardcode performance/cost claims without evidence
//   - Use qualitative categories where quantitative data is unavailable
//   - Use MEASURED label when data comes from local benchmarks
//   - Use SPECIFICATION label when data comes from NIST specs
//   - Never fabricate latency, cost, or percentage claims
// ============================================================

// ─── Types ──────────────────────────────────────────────────

export interface PqcTradeOff {
  /** Algorithm name */
  algorithm: string;
  /** NIST standard */
  nistStandard: string;
  /** Security category (NIST security levels 1-5) */
  securityLevel: number;
  /** What it replaces */
  replaces: string;
  /** Usage context */
  usageContext: 'key-establishment' | 'digital-signatures' | 'hash' | 'symmetric' | 'general';

  // ── Key/Signature Sizes (from NIST specifications) ──
  publicKeySizeBytes: number;
  secretKeySizeBytes?: number;    // for KEMs
  privateKeySizeBytes?: number;   // for signature schemes
  ciphertextSizeBytes?: number;   // for KEMs
  signatureSizeBytes?: number;    // for signature schemes

  // ── Deployment Compatibility (qualitative) ──
  deploymentCompatibility: 'LOW' | 'MEDIUM' | 'HIGH';
  deploymentCompatibilityNote: string;

  // ── Migration Complexity (qualitative) ──
  migrationComplexity: 'LOW' | 'MEDIUM' | 'HIGH';
  migrationComplexityNote: string;

  // ── Protocol Applicability ──
  protocolApplicability: string[];

  // ── Implementation Availability ──
  implementationStatus: 'standardized' | 'draft' | 'experimental';
  referenceImplementations: string[];

  // ── Data Source ──
  dataSource: 'specification' | 'measured' | 'estimated';
  /** If measured: the benchmark environment */
  benchmarkEnvironment?: string;
  /** If measured: number of samples */
  benchmarkSamples?: number;
}

// ─── Trade-Off Data (from NIST FIPS specifications) ─────────

export const PQC_TRADEOFFS: PqcTradeOff[] = [
  // ── ML-KEM (FIPS 203) — Key Encapsulation Mechanisms ──
  {
    algorithm: 'ML-KEM-512',
    nistStandard: 'FIPS 203',
    securityLevel: 1,
    replaces: 'RSA-2048 key exchange, ECDH, X25519',
    usageContext: 'key-establishment',
    publicKeySizeBytes: 800,
    secretKeySizeBytes: 1632,
    ciphertextSizeBytes: 768,
    deploymentCompatibility: 'MEDIUM',
    deploymentCompatibilityNote: 'Requires protocol changes; larger key/ciphertext sizes than classical alternatives',
    migrationComplexity: 'MEDIUM',
    migrationComplexityNote: 'Hybrid X25519+ML-KEM-512 recommended for transition period',
    protocolApplicability: ['TLS 1.3', 'SSH', 'IPsec', 'Signal Protocol'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto', 'BoringSSL', 'OpenSSL 3.x'],
    dataSource: 'specification',
  },
  {
    algorithm: 'ML-KEM-768',
    nistStandard: 'FIPS 203',
    securityLevel: 3,
    replaces: 'RSA-3072 key exchange, ECDH, X25519',
    usageContext: 'key-establishment',
    publicKeySizeBytes: 1184,
    secretKeySizeBytes: 2400,
    ciphertextSizeBytes: 1088,
    deploymentCompatibility: 'MEDIUM',
    deploymentCompatibilityNote: 'Recommended default for general-purpose key establishment',
    migrationComplexity: 'MEDIUM',
    migrationComplexityNote: 'Hybrid deployment recommended; protocol negotiation needed',
    protocolApplicability: ['TLS 1.3', 'SSH', 'IPsec', 'Signal Protocol', 'WireGuard'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto', 'BoringSSL', 'OpenSSL 3.x', 'libgcrypt'],
    dataSource: 'specification',
  },
  {
    algorithm: 'ML-KEM-1024',
    nistStandard: 'FIPS 203',
    securityLevel: 5,
    replaces: 'RSA-4096 key exchange',
    usageContext: 'key-establishment',
    publicKeySizeBytes: 1568,
    secretKeySizeBytes: 3168,
    ciphertextSizeBytes: 1568,
    deploymentCompatibility: 'LOW',
    deploymentCompatibilityNote: 'Largest parameter set; use when highest security level required',
    migrationComplexity: 'HIGH',
    migrationComplexityNote: 'Significantly larger than classical alternatives; careful protocol design required',
    protocolApplicability: ['TLS 1.3', 'SSH', 'IPsec'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto', 'BoringSSL'],
    dataSource: 'specification',
  },

  // ── ML-DSA (FIPS 204) — Digital Signature Algorithms ──
  {
    algorithm: 'ML-DSA-44',
    nistStandard: 'FIPS 204',
    securityLevel: 2,
    replaces: 'ECDSA P-256, Ed25519, RSA-2048 signatures',
    usageContext: 'digital-signatures',
    publicKeySizeBytes: 1312,
    privateKeySizeBytes: 2560,
    signatureSizeBytes: 2420,
    deploymentCompatibility: 'MEDIUM',
    deploymentCompatibilityNote: 'Larger signatures; certificate size increases significantly',
    migrationComplexity: 'MEDIUM',
    migrationComplexityNote: 'PKI infrastructure changes needed for certificate issuance',
    protocolApplicability: ['X.509 Certificates', 'Code Signing', 'Document Signing', 'SSH'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto', 'OpenSSL 3.x'],
    dataSource: 'specification',
  },
  {
    algorithm: 'ML-DSA-65',
    nistStandard: 'FIPS 204',
    securityLevel: 3,
    replaces: 'ECDSA P-384, RSA-3072 signatures',
    usageContext: 'digital-signatures',
    publicKeySizeBytes: 1952,
    privateKeySizeBytes: 4032,
    signatureSizeBytes: 3293,
    deploymentCompatibility: 'MEDIUM',
    deploymentCompatibilityNote: 'Recommended for general-purpose signatures',
    migrationComplexity: 'MEDIUM',
    migrationComplexityNote: 'Hybrid signatures recommended during transition',
    protocolApplicability: ['X.509 Certificates', 'Code Signing', 'Document Signing', 'SSH'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto', 'OpenSSL 3.x', 'BoringSSL'],
    dataSource: 'specification',
  },
  {
    algorithm: 'ML-DSA-87',
    nistStandard: 'FIPS 204',
    securityLevel: 5,
    replaces: 'RSA-4096 signatures',
    usageContext: 'digital-signatures',
    publicKeySizeBytes: 2592,
    privateKeySizeBytes: 4896,
    signatureSizeBytes: 4595,
    deploymentCompatibility: 'LOW',
    deploymentCompatibilityNote: 'Largest signature size; use for highest security requirements only',
    migrationComplexity: 'HIGH',
    migrationComplexityNote: 'Certificate chains become significantly larger; bandwidth implications',
    protocolApplicability: ['X.509 Certificates', 'Code Signing'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto'],
    dataSource: 'specification',
  },

  // ── SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures ──
  {
    algorithm: 'SLH-DSA-SHA2-128s',
    nistStandard: 'FIPS 205',
    securityLevel: 1,
    replaces: 'ECDSA P-256, Ed25519 signatures',
    usageContext: 'digital-signatures',
    publicKeySizeBytes: 32,
    privateKeySizeBytes: 64,
    signatureSizeBytes: 7856,
    deploymentCompatibility: 'LOW',
    deploymentCompatibilityNote: 'Very large signatures; limited to scenarios where hash-based security is preferred',
    migrationComplexity: 'HIGH',
    migrationComplexityNote: 'Large signature size impacts storage and bandwidth significantly',
    protocolApplicability: ['Code Signing', 'Firmware Signing', 'Blockchain'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto'],
    dataSource: 'specification',
  },
  {
    algorithm: 'SLH-DSA-SHA2-128f',
    nistStandard: 'FIPS 205',
    securityLevel: 1,
    replaces: 'ECDSA P-256, Ed25519 signatures',
    usageContext: 'digital-signatures',
    publicKeySizeBytes: 32,
    privateKeySizeBytes: 64,
    signatureSizeBytes: 17088,
    deploymentCompatibility: 'LOW',
    deploymentCompatibilityNote: 'Fast signing but very large signatures',
    migrationComplexity: 'HIGH',
    migrationComplexityNote: 'Signature size may be prohibitive for some protocols',
    protocolApplicability: ['Code Signing', 'Firmware Signing'],
    implementationStatus: 'standardized',
    referenceImplementations: ['liboqs', 'pqcrypto'],
    dataSource: 'specification',
  },
];

// ─── Public API ─────────────────────────────────────────────

/**
 * Get trade-off information for a specific PQC algorithm.
 * Returns undefined if no data is available (honest — no fabricated data).
 */
export function getPqcTradeOff(algorithm: string): PqcTradeOff | undefined {
  const normalized = algorithm.toUpperCase().replace(/[\s-]/g, '-').trim();
  return PQC_TRADEOFFS.find(t =>
    t.algorithm.toUpperCase() === normalized ||
    t.algorithm.toUpperCase().replace(/-/g, '') === normalized.replace(/-/g, '')
  );
}

/**
 * Get all PQC trade-offs for a given usage context.
 */
export function getPqcTradeOffsForContext(
  context: 'key-establishment' | 'digital-signatures' | 'hash' | 'symmetric' | 'general'
): PqcTradeOff[] {
  return PQC_TRADEOFFS.filter(t => t.usageContext === context);
}

/**
 * Compare two PQC algorithms on key metrics.
 * Returns honest comparison without fabricated performance numbers.
 */
export function comparePqcAlgorithms(
  algo1: string,
  algo2: string
): { algo1: PqcTradeOff | undefined; algo2: PqcTradeOff | undefined; comparison: string } {
  const a1 = getPqcTradeOff(algo1);
  const a2 = getPqcTradeOff(algo2);

  if (!a1 || !a2) {
    return {
      algo1: a1,
      algo2: a2,
      comparison: 'One or both algorithms not found in trade-off database.',
    };
  }

  const parts: string[] = [];

  // Key/signature sizes
  parts.push(`Public key: ${a1.algorithm}=${a1.publicKeySizeBytes}B vs ${a2.algorithm}=${a2.publicKeySizeBytes}B`);

  if (a1.ciphertextSizeBytes && a2.ciphertextSizeBytes) {
    parts.push(`Ciphertext: ${a1.algorithm}=${a1.ciphertextSizeBytes}B vs ${a2.algorithm}=${a2.ciphertextSizeBytes}B`);
  }

  if (a1.signatureSizeBytes && a2.signatureSizeBytes) {
    parts.push(`Signature: ${a1.algorithm}=${a1.signatureSizeBytes}B vs ${a2.algorithm}=${a2.signatureSizeBytes}B`);
  }

  // Security levels
  parts.push(`Security level: ${a1.algorithm}=L${a1.securityLevel} vs ${a2.algorithm}=L${a2.securityLevel}`);

  // Compatibility
  parts.push(`Deployment compatibility: ${a1.algorithm}=${a1.deploymentCompatibility} vs ${a2.algorithm}=${a2.deploymentCompatibility}`);

  // Protocol support
  const common = a1.protocolApplicability.filter(p => a2.protocolApplicability.includes(p));
  parts.push(`Common protocol support: ${common.length > 0 ? common.join(', ') : 'none'}`);

  return {
    algo1: a1,
    algo2: a2,
    comparison: parts.join('. ') + '.',
  };
}

/**
 * Generate a migration comparison between a classical algorithm and
 * its PQC replacement. Returns honest, evidence-based trade-off info.
 */
export function generateMigrationComparison(
  classicalAlgorithm: string,
  pqcAlgorithm: string
): string {
  const classical = classicalAlgorithm.toUpperCase();
  const pqc = getPqcTradeOff(pqcAlgorithm);

  if (!pqc) {
    return `No trade-off data available for ${pqcAlgorithm}. Manual evaluation required.`;
  }

  const parts: string[] = [
    `Migration: ${classicalAlgorithm} → ${pqcAlgorithm}`,
    `NIST Standard: ${pqc.nistStandard}`,
    `Security Level: ${pqc.securityLevel}`,
    `Public key size: ${pqc.publicKeySizeBytes} bytes`,
  ];

  if (pqc.ciphertextSizeBytes) parts.push(`Ciphertext: ${pqc.ciphertextSizeBytes} bytes`);
  if (pqc.signatureSizeBytes) parts.push(`Signature: ${pqc.signatureSizeBytes} bytes`);
  if (pqc.secretKeySizeBytes) parts.push(`Secret key: ${pqc.secretKeySizeBytes} bytes`);
  if (pqc.privateKeySizeBytes) parts.push(`Private key: ${pqc.privateKeySizeBytes} bytes`);

  parts.push(`Deployment compatibility: ${pqc.deploymentCompatibility} — ${pqc.deploymentCompatibilityNote}`);
  parts.push(`Migration complexity: ${pqc.migrationComplexity} — ${pqc.migrationComplexityNote}`);
  parts.push(`Protocol support: ${pqc.protocolApplicability.join(', ')}`);
  parts.push(`Data source: ${pqc.dataSource.toUpperCase()} (from ${pqc.dataSource === 'specification' ? 'NIST FIPS specification' : 'local benchmark'})`);

  return parts.join('\n');
}
