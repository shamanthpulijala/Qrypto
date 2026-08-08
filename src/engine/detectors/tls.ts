// ============================================================
// §13 — Detector: TLS / SSL Versions
// §14: ssl.PROTOCOL_TLSv1 is problematic; TLS 1.2/1.3 adequate
// ============================================================

import type { CryptoPattern } from './rsa';

export const TLS_PATTERNS: CryptoPattern[] = [
  // ── Obsolete / Broken ─────────────────────────────────────

  // TLS 1.0 — §14 sample: ssl.PROTOCOL_TLSv1
  {
    regex: /ssl\.PROTOCOL_TLSv1(?!_)|TLSv?1\.?0|TLS_1_0/gi,
    algorithm: 'TLS 1.0',
    category: 'tls',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'transport layer security (obsolete)',
    confidence: 0.95,
  },

  // TLS 1.1
  {
    regex: /TLSv?1\.?1|TLS_1_1|ssl\.PROTOCOL_TLSv1_1/gi,
    algorithm: 'TLS 1.1',
    category: 'tls',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'transport layer security (obsolete)',
    confidence: 0.95,
  },

  // SSLv2 — completely broken
  {
    regex: /SSLv?2|ssl\.PROTOCOL_SSLv2/gi,
    algorithm: 'SSLv2',
    category: 'tls',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'transport layer security (broken)',
    confidence: 0.98,
  },

  // SSLv3 — POODLE vulnerable
  {
    regex: /SSLv?3|ssl\.PROTOCOL_SSLv3/gi,
    algorithm: 'SSLv3',
    category: 'tls',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'transport layer security (broken)',
    confidence: 0.98,
  },

  // ── Adequate ─────────────────────────────────────────────

  // TLS 1.2 — acceptable but recommend 1.3
  {
    regex: /TLSv?1\.?2|TLS_1_2/gi,
    algorithm: 'TLS 1.2',
    category: 'tls',
    quantumStatus: 'adequate',
    baseSeverity: 'medium',
    usage: 'transport layer security',
    confidence: 0.93,
  },

  // TLS 1.3 — current best
  {
    regex: /TLSv?1\.?3|TLS_1_3/gi,
    algorithm: 'TLS 1.3',
    category: 'tls',
    quantumStatus: 'adequate',
    baseSeverity: 'info',
    usage: 'transport layer security (current)',
    confidence: 0.95,
  },
];
