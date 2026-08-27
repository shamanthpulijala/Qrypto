// ============================================================
// §13 — Detector: RSA
// Detects RSA public-key cryptography usages
// ============================================================

import type { AlgorithmCategory, QuantumStatus, Severity, Language } from '../../types';

export interface CryptoPattern {
  regex: RegExp;
  algorithm: string;
  category: AlgorithmCategory;
  quantumStatus: QuantumStatus;
  baseSeverity: Severity;
  usage: string;
  keySize?: number;
  languages?: Language[];
  confidence: number;
}

export const RSA_PATTERNS: CryptoPattern[] = [
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(4096)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', keySize: 4096, confidence: 0.97 },
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(3072)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', keySize: 3072, confidence: 0.97 },
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(2048)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', keySize: 2048, confidence: 0.97 },
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(1024)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'critical', usage: 'public-key cryptography (weak key size)', keySize: 1024, confidence: 0.99 },
  { regex: /[\"']RSA[\"']/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', confidence: 0.90 },
  { regex: /generate_private_key\s*\(\s*RSA\b/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key generation', confidence: 0.95 },
  // RSA.generate(N) — PyCryptodome style (§14 sample)
  { regex: /RSA\.generate\s*\(\s*(\d+)/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key generation', confidence: 0.97 },
  { regex: /KeyPairGenerator\.getInstance\s*\(\s*[\"']RSA[\"']/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key generation', languages: ['java'], confidence: 0.97 },
  { regex: /crypto\.createSign\s*\(\s*[\"']RSA-/g, algorithm: 'RSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', languages: ['javascript', 'typescript'], confidence: 0.97 },
  { regex: /rsa\.encrypt|rsa\.decrypt|rsa\.sign|rsa\.verify/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key operation', confidence: 0.93 },
  { regex: /rsa\.generate_private_key\s*\([\s\S]*?\)/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key generation', languages: ['python'], confidence: 0.96 },
  // Go RSA
  { regex: /rsa\.GenerateKey\s*\(/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key generation', languages: ['go'], confidence: 0.96 },
  // Web Crypto RSA
  { regex: /RSA-OAEP|RSA-PSS|RSAES/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', confidence: 0.95 },
];
