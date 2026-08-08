// ============================================================
// §13 — Detector: Secrets & Credentials
// §14 samples: API_KEY = "DEMO_SECRET_DO_NOT_USE"
//              JWT_SECRET = "DEMO_JWT_SECRET"
// ============================================================

import type { CryptoPattern } from './rsa';

export const SECRET_PATTERNS: CryptoPattern[] = [
  // Private key material embedded in source
  {
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g,
    algorithm: 'Private Key',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'private key material (embedded in source)',
    confidence: 0.99,
  },

  // Stripe live API keys
  {
    regex: /(?:sk_live_|sk_test_)[a-zA-Z0-9]{20,}/g,
    algorithm: 'Stripe API Key',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'API credential (hardcoded)',
    confidence: 0.99,
  },

  // AWS IAM keys
  {
    regex: /(?:AKIA|ASIA|AIPA)[A-Z0-9]{16}/g,
    algorithm: 'AWS Access Key',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'AWS credential (hardcoded)',
    confidence: 0.99,
  },

  // JWT Secret — §14 sample: JWT_SECRET = "DEMO_JWT_SECRET"
  {
    regex: /(?:jwt_secret|JWT_SECRET|jwtSecret)\s*[=:]\s*[\"'][^\"']{4,}/gi,
    algorithm: 'JWT Secret',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'JWT signing secret (hardcoded)',
    confidence: 0.96,
  },

  // Generic API Key — §14 sample: API_KEY = "DEMO_SECRET_DO_NOT_USE"
  {
    regex: /(?:api_key|API_KEY|apiKey|APIKEY)\s*[=:]\s*[\"'][a-zA-Z0-9_\-!@#$%^&*]{8,}[\"']/gi,
    algorithm: 'API Key',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'API credential (hardcoded)',
    confidence: 0.85,
  },

  // Hardcoded passwords
  {
    regex: /(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{4,}[\"']/gi,
    algorithm: 'Hardcoded Password',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'high',
    usage: 'credential (hardcoded)',
    confidence: 0.80,
  },

  // GitHub personal access tokens
  {
    regex: /ghp_[a-zA-Z0-9]{36}/g,
    algorithm: 'GitHub PAT',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'GitHub personal access token (hardcoded)',
    confidence: 0.99,
  },

  // Database connection strings with passwords
  {
    regex: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]{4,}@/gi,
    algorithm: 'Database Credential',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'database credential (hardcoded in connection string)',
    confidence: 0.92,
  },

  // OAuth client secrets
  {
    regex: /(?:client_secret|CLIENT_SECRET|oauth_secret)\s*[=:]\s*[\"'][^\"']{8,}[\"']/gi,
    algorithm: 'OAuth Secret',
    category: 'secret',
    quantumStatus: 'unknown',
    baseSeverity: 'critical',
    usage: 'OAuth client secret (hardcoded)',
    confidence: 0.88,
  },
];
