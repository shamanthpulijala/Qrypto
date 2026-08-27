// ============================================================
// §13 — Detector: Symmetric Cryptography
// AES-256 healthy; DES/3DES/RC4 broken
// §14: AES-256 is a healthy example — scanner must report 'adequate'
// ============================================================

import type { CryptoPattern } from './rsa';

export const SYMMETRIC_PATTERNS: CryptoPattern[] = [
  // ── Healthy / Adequate ────────────────────────────────────

  // AES-256 — §14 sample: healthy, should be classified as 'adequate'
  {
    regex: /AES[_-]?256|AES\.new.*256|Cipher\.getInstance\s*\(\s*[\"']AES\/[^\"']*[\"']|algorithms\.AES|crypto\.createCipheriv\s*\(\s*[\"']aes-256|aes\.NewCipher|crypto\.subtle\.encrypt\s*\(\s*\{[^}]*name:\s*[\"']AES/gi,
    algorithm: 'AES-256',
    category: 'symmetric',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'symmetric encryption',
    keySize: 256,
    confidence: 0.93,
  },

  // AES-192
  {
    regex: /AES[_-]?192/gi,
    algorithm: 'AES-192',
    category: 'symmetric',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'symmetric encryption',
    keySize: 192,
    confidence: 0.93,
  },

  // AES-128
  {
    regex: /AES[_-]?128|AES\.new.*128/gi,
    algorithm: 'AES-128',
    category: 'symmetric',
    quantumStatus: 'adequate',
    baseSeverity: 'low',
    usage: 'symmetric encryption',
    keySize: 128,
    confidence: 0.92,
  },

  // AES (generic)
  {
    regex: /[\"']AES[\"'](?!-)/g,
    algorithm: 'AES',
    category: 'symmetric',
    quantumStatus: 'adequate',
    baseSeverity: 'low',
    usage: 'symmetric encryption',
    confidence: 0.88,
  },

  // ChaCha20 — stream cipher, adequate
  {
    regex: /ChaCha20|chacha20/g,
    algorithm: 'ChaCha20',
    category: 'symmetric',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'symmetric encryption',
    confidence: 0.95,
  },

  // ── Broken / Weak ─────────────────────────────────────────

  // DES — 56-bit, classically broken
  {
    regex: /DES\.(?:encrypt|decrypt|new)|Cipher\.getInstance\s*\(\s*[\"']DES[\"']/gi,
    algorithm: 'DES',
    category: 'symmetric',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'symmetric encryption (broken)',
    keySize: 56,
    confidence: 0.97,
  },

  // 3DES — Sweet32 attack
  {
    regex: /3DES|TripleDES|DESede|TDES/gi,
    algorithm: '3DES',
    category: 'symmetric',
    quantumStatus: 'classical-weak',
    baseSeverity: 'high',
    usage: 'symmetric encryption (weak)',
    confidence: 0.95,
  },

  // RC4 — stream cipher, completely broken
  {
    regex: /RC4|Arcfour|arcfour/gi,
    algorithm: 'RC4',
    category: 'symmetric',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'symmetric encryption (broken)',
    confidence: 0.96,
  },
];
