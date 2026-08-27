// ============================================================
// §13 — Detector: Hash Functions
// MD5, SHA-1 (problematic) vs SHA-2, SHA-3, bcrypt (healthy)
// §14: Scanner correctly distinguishes problematic from healthy
// ============================================================

import type { CryptoPattern } from './rsa';

export const HASH_PATTERNS: CryptoPattern[] = [
  // ── Broken (classically compromised) ─────────────────────

  // MD5 — §14 sample: hashlib.md5(data)
  {
    regex: /hashlib\.md5\s*\(|crypto\.createHash\s*\(\s*[\"']md5[\"']|md5\.Sum\s*\(|MD5|MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']/gi,
    algorithm: 'MD5',
    category: 'hash',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'hash function (broken)',
    confidence: 0.95,
  },

  // SHA-1 — §14 sample: hashlib.sha1(data)
  {
    regex: /hashlib\.sha1\s*\(|crypto\.createHash\s*\(\s*[\"']sha1[\"']|sha1\.Sum\s*\(|SHA-?1(?!\d)|SHA1(?!_)|[\"']SHA-1[\"']|[\"']SHA1[\"']|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']|crypto\.subtle\.digest\s*\(\s*[\"']SHA-1[\"']/gi,
    algorithm: 'SHA-1',
    category: 'hash',
    quantumStatus: 'classical-weak',
    baseSeverity: 'high',
    usage: 'hash function (weak collision resistance)',
    confidence: 0.94,
  },

  // SHA1withRSA — especially in certificates
  {
    regex: /SHA1withRSA|sha1WithRSA|sha1WithRSAEncryption/g,
    algorithm: 'SHA1withRSA',
    category: 'signature',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'signature algorithm (weak)',
    confidence: 0.98,
  },

  // SHA256withRSA — still quantum-vulnerable (RSA component)
  {
    regex: /SHA256withRSA|SHA256withECDSA/g,
    algorithm: 'SHA256withRSA',
    category: 'signature',
    quantumStatus: 'vulnerable',
    baseSeverity: 'high',
    usage: 'signature algorithm',
    confidence: 0.97,
  },

  // ── Adequate / Healthy ────────────────────────────────────

  // SHA-256 — §14: adequate
  {
    regex: /SHA-?256|[\"']SHA-256[\"']|[\"']SHA256[\"']|hashlib\.sha256|crypto\.createHash\s*\(\s*[\"']sha256[\"']|sha256\.Sum256|crypto\.subtle\.digest\s*\(\s*[\"']SHA-256[\"']/gi,
    algorithm: 'SHA-256',
    category: 'hash',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'hash function',
    confidence: 0.93,
  },

  // SHA-384
  {
    regex: /SHA-?384|[\"']SHA-384[\"']/gi,
    algorithm: 'SHA-384',
    category: 'hash',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'hash function',
    confidence: 0.93,
  },

  // SHA-512
  {
    regex: /SHA-?512|[\"']SHA-512[\"']|hashlib\.sha512/gi,
    algorithm: 'SHA-512',
    category: 'hash',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'hash function',
    confidence: 0.93,
  },

  // SHA-3
  {
    regex: /SHA-?3[-_]?(?:256|384|512)|[\"']SHA3-/gi,
    algorithm: 'SHA-3',
    category: 'hash',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'hash function',
    confidence: 0.92,
  },

  // Password hashing — bcrypt, argon2, scrypt (healthy)
  {
    regex: /bcrypt|argon2|scrypt|pbkdf2/gi,
    algorithm: 'Password Hash',
    category: 'hash',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'password hashing',
    confidence: 0.90,
  },
];
