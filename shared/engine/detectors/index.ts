// ============================================================
// §13 — Detector Index
// Aggregates all modular detectors into a unified pattern set
// ============================================================

import { RSA_PATTERNS } from './rsa';
import { ECC_PATTERNS } from './ecc';
import { HASH_PATTERNS } from './hashes';
import { TLS_PATTERNS } from './tls';
import { SYMMETRIC_PATTERNS } from './signatures'; // symmetric + signatures
import { SECRET_PATTERNS } from './secrets';
import { CERTIFICATE_PATTERNS } from './certificates';
import { PQC_PATTERNS } from './pqc';

export type { CryptoPattern } from './rsa';

/**
 * All crypto patterns, ordered so that more specific patterns (e.g., AES-256)
 * are matched before generic ones (e.g., AES) to avoid duplication.
 * Detectors are applied in this priority order.
 */
export const ALL_PATTERNS = [
  // Secrets first (highest priority, always mask)
  ...SECRET_PATTERNS,
  // PQC next (positive indicators)
  ...PQC_PATTERNS,
  // Certificates
  ...CERTIFICATE_PATTERNS,
  // RSA (specific key sizes before generic)
  ...RSA_PATTERNS,
  // ECC / ECDH / ECDSA
  ...ECC_PATTERNS,
  // Hashes (SHA1withRSA before SHA-1 to avoid partial match)
  ...HASH_PATTERNS,
  // TLS
  ...TLS_PATTERNS,
  // Symmetric (AES-256 before AES-128 before generic AES)
  ...SYMMETRIC_PATTERNS,
];

export {
  RSA_PATTERNS,
  ECC_PATTERNS,
  HASH_PATTERNS,
  TLS_PATTERNS,
  SYMMETRIC_PATTERNS,
  SECRET_PATTERNS,
  CERTIFICATE_PATTERNS,
  PQC_PATTERNS,
};
