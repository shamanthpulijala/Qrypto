// ============================================================
// §13 — Detector: Certificates
// X.509 cert generation, openssl commands, cert loading
// ============================================================

import type { CryptoPattern } from './rsa';

export const CERTIFICATE_PATTERNS: CryptoPattern[] = [
  // openssl genrsa (RSA cert key generation)
  {
    regex: /openssl\s+genrsa\s+.*?(\d{3,4})/g,
    algorithm: 'RSA',
    category: 'certificate',
    quantumStatus: 'vulnerable',
    baseSeverity: 'high',
    usage: 'certificate key generation',
    keySize: 2048,
    confidence: 0.94,
  },

  // openssl req / x509 with sha1
  {
    regex: /openssl\s+(?:req|x509).*?-sha1/gi,
    algorithm: 'SHA1withRSA',
    category: 'certificate',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'certificate signature algorithm (weak)',
    confidence: 0.92,
  },

  // openssl req / x509 with sha256 (ok)
  {
    regex: /openssl\s+(?:req|x509).*?-sha256/gi,
    algorithm: 'SHA256withRSA',
    category: 'certificate',
    quantumStatus: 'vulnerable',
    baseSeverity: 'medium',
    usage: 'certificate signature algorithm',
    confidence: 0.92,
  },

  // sha1WithRSAEncryption in certificate templates
  {
    regex: /sha1WithRSAEncryption/g,
    algorithm: 'SHA1withRSA',
    category: 'certificate',
    quantumStatus: 'classical-weak',
    baseSeverity: 'critical',
    usage: 'certificate signature algorithm (weak)',
    confidence: 0.98,
  },

  // Python x509 / cryptography library cert building
  {
    regex: /x509\.CertificateBuilder\s*\(\s*\)/g,
    algorithm: 'X.509 Certificate',
    category: 'certificate',
    quantumStatus: 'unknown',
    baseSeverity: 'info',
    usage: 'certificate generation',
    languages: ['python'],
    confidence: 0.88,
  },

  // Java KeyStore cert operations
  {
    regex: /KeyStore\.getInstance\s*\(\s*[\"'](?:JKS|PKCS12)[\"']/g,
    algorithm: 'KeyStore',
    category: 'certificate',
    quantumStatus: 'unknown',
    baseSeverity: 'info',
    usage: 'certificate storage (Java KeyStore)',
    languages: ['java'],
    confidence: 0.85,
  },

  // PEM certificate loading
  {
    regex: /-----BEGIN CERTIFICATE-----/g,
    algorithm: 'X.509 Certificate',
    category: 'certificate',
    quantumStatus: 'unknown',
    baseSeverity: 'info',
    usage: 'certificate material in source',
    confidence: 0.90,
  },
];
