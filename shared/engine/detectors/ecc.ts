// ============================================================
// §13 — Detector: ECC (Elliptic Curve Cryptography)
// Detects ECC, ECDH, ECDSA, EdDSA patterns
// ============================================================

import type { CryptoPattern } from './rsa';

export const ECC_PATTERNS: CryptoPattern[] = [
  // ECDSA
  { regex: /[\"']ECDSA[\"']/g, algorithm: 'ECDSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', confidence: 0.95 },
  { regex: /ec\.ECDSA\s*\(/gi, algorithm: 'ECDSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', confidence: 0.96 },
  { regex: /Signature\.getInstance\s*\(\s*[\"']SHA\d+withECDSA[\"']/g, algorithm: 'ECDSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', languages: ['java'], confidence: 0.97 },

  // ECDH — key exchange (§17: different PQC successor from ECDSA)
  { regex: /[\"']ECDH[\"']/g, algorithm: 'ECDH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key exchange', confidence: 0.95 },
  { regex: /ec\.ECDH\s*\(\s*\)/gi, algorithm: 'ECDH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key exchange', confidence: 0.96 },
  { regex: /ECDH\s*\(\s*\)|ecdh\.generate/gi, algorithm: 'ECDH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key exchange', confidence: 0.94 },
  { regex: /KeyAgreement\.getInstance\s*\(\s*[\"']ECDH[\"']/g, algorithm: 'ECDH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key exchange', languages: ['java'], confidence: 0.97 },
  { regex: /crypto\.createECDH\s*\(/g, algorithm: 'ECDH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key exchange', languages: ['javascript', 'typescript'], confidence: 0.97 },

  // Named curves / ECC general
  { regex: /secp256r1|prime256v1|secp384r1|P-256|P-384|P-521/gi, algorithm: 'ECC', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'elliptic curve', confidence: 0.94 },
  { regex: /curve25519|ed25519|x25519/gi, algorithm: 'EdDSA/X25519', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'medium', usage: 'elliptic curve signature/exchange', confidence: 0.92 },
  { regex: /EC\.generate_key|ec_key_new|EC_KEY_new/g, algorithm: 'ECC', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'ECC key generation', confidence: 0.93 },
  { regex: /ec\.generate_private_key\s*\(\s*ec\./gi, algorithm: 'ECC', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'ECC key generation', languages: ['python'], confidence: 0.96 },

  // DH / DSA
  { regex: /[\"']DH[\"']/g, algorithm: 'DH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'Diffie-Hellman key exchange', confidence: 0.90 },
  { regex: /[\"']DSA[\"']/g, algorithm: 'DSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', confidence: 0.90 },
  { regex: /KeyPairGenerator\.getInstance\s*\(\s*[\"']DSA[\"']/g, algorithm: 'DSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', languages: ['java'], confidence: 0.97 },
];
