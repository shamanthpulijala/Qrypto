// ============================================================
// QuantumGuard AI — Cryptographic Discovery Engine
// Deterministic scanner — source of truth, no LLM involved
// ============================================================

import type { Finding, Language, AlgorithmCategory, QuantumStatus, Severity } from '../types';
import { computeRiskScore } from './riskEngine';

// ─── Pattern Library ────────────────────────────────────────

interface CryptoPattern {
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

const PATTERNS: CryptoPattern[] = [
  // ── Public-Key Cryptography ──────────────────────────────

  // RSA variants
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(4096)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', keySize: 4096, confidence: 0.97 },
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(3072)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', keySize: 3072, confidence: 0.97 },
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(2048)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', keySize: 2048, confidence: 0.97 },
  { regex: /RSA[_-]?(?:PSS|PKCS|OAEP)?[-_]?(1024)/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'critical', usage: 'public-key cryptography (weak key size)', keySize: 1024, confidence: 0.99 },
  { regex: /["']RSA["']/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key cryptography', confidence: 0.90 },
  { regex: /generate_private_key\s*\(\s*RSA\b/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key generation', confidence: 0.95 },
  { regex: /KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']/g, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key generation', languages: ['java'], confidence: 0.97 },
  { regex: /crypto\.createSign\s*\(\s*["']RSA-/g, algorithm: 'RSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', languages: ['javascript', 'typescript'], confidence: 0.97 },
  { regex: /rsa\.encrypt|rsa\.decrypt|rsa\.sign|rsa\.verify/gi, algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'public-key operation', confidence: 0.93 },

  // ECDSA / ECDH / ECC
  { regex: /["']ECDSA["']/g, algorithm: 'ECDSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', confidence: 0.95 },
  { regex: /["']ECDH["']/g, algorithm: 'ECDH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key exchange', confidence: 0.95 },
  { regex: /ec\.ECDH|ECDH\(\)|ecdh\.generate/gi, algorithm: 'ECDH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'key exchange', confidence: 0.95 },
  { regex: /secp256r1|prime256v1|secp384r1|P-256|P-384|P-521/gi, algorithm: 'ECC', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'elliptic curve', confidence: 0.94 },
  { regex: /curve25519|ed25519|x25519/gi, algorithm: 'EdDSA/X25519', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'medium', usage: 'elliptic curve signature/exchange', confidence: 0.92 },
  { regex: /EC\.generate_key|ec_key_new|EC_KEY_new/g, algorithm: 'ECC', category: 'public-key', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'ECC key generation', confidence: 0.93 },

  // DH / DSA
  { regex: /["']DH["']/g, algorithm: 'DH', category: 'key-exchange', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'Diffie-Hellman key exchange', confidence: 0.90 },
  { regex: /["']DSA["']/g, algorithm: 'DSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', confidence: 0.90 },
  { regex: /KeyPairGenerator\.getInstance\s*\(\s*["']DSA["']/g, algorithm: 'DSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'digital signature', languages: ['java'], confidence: 0.97 },

  // ── Hash Functions ────────────────────────────────────────

  { regex: /MD5|md5|MessageDigest\.getInstance\s*\(\s*["']MD5["']/gi, algorithm: 'MD5', category: 'hash', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'hash function (broken)', confidence: 0.95 },
  { regex: /SHA-?1(?!\d)|SHA1(?!_)|["']SHA-1["']|["']SHA1["']|MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']/gi, algorithm: 'SHA-1', category: 'hash', quantumStatus: 'classical-weak', baseSeverity: 'high', usage: 'hash function (weak collision resistance)', confidence: 0.94 },
  { regex: /SHA-?256|["']SHA-256["']|["']SHA256["']|hashlib\.sha256/gi, algorithm: 'SHA-256', category: 'hash', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'hash function', confidence: 0.93 },
  { regex: /SHA-?384|["']SHA-384["']/gi, algorithm: 'SHA-384', category: 'hash', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'hash function', confidence: 0.93 },
  { regex: /SHA-?512|["']SHA-512["']|hashlib\.sha512/gi, algorithm: 'SHA-512', category: 'hash', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'hash function', confidence: 0.93 },
  { regex: /SHA-?3[-_]?(?:256|384|512)|["']SHA3-/gi, algorithm: 'SHA-3', category: 'hash', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'hash function', confidence: 0.92 },
  { regex: /SHA1withRSA|sha1WithRSA/g, algorithm: 'SHA1withRSA', category: 'signature', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'signature algorithm (weak)', confidence: 0.98 },
  { regex: /SHA256withRSA|SHA256withECDSA/g, algorithm: 'SHA256withRSA', category: 'signature', quantumStatus: 'vulnerable', baseSeverity: 'high', usage: 'signature algorithm', confidence: 0.97 },
  { regex: /bcrypt|argon2|scrypt|pbkdf2/gi, algorithm: 'Password Hash', category: 'hash', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'password hashing', confidence: 0.90 },

  // ── Symmetric Cryptography ───────────────────────────────

  { regex: /AES[_-]?256|AES\.new.*256|Cipher\.getInstance\s*\(\s*["']AES\/[^"']*["']/gi, algorithm: 'AES-256', category: 'symmetric', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'symmetric encryption', keySize: 256, confidence: 0.93 },
  { regex: /AES[_-]?192/gi, algorithm: 'AES-192', category: 'symmetric', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'symmetric encryption', keySize: 192, confidence: 0.93 },
  { regex: /AES[_-]?128|AES\.new.*128/gi, algorithm: 'AES-128', category: 'symmetric', quantumStatus: 'adequate', baseSeverity: 'low', usage: 'symmetric encryption', keySize: 128, confidence: 0.92 },
  { regex: /["']AES["'](?!-)/g, algorithm: 'AES', category: 'symmetric', quantumStatus: 'adequate', baseSeverity: 'low', usage: 'symmetric encryption', confidence: 0.88 },
  { regex: /DES\.(?:encrypt|decrypt|new)|Cipher\.getInstance\s*\(\s*["']DES["']/gi, algorithm: 'DES', category: 'symmetric', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'symmetric encryption (broken)', keySize: 56, confidence: 0.97 },
  { regex: /3DES|TripleDES|DESede|TDES/gi, algorithm: '3DES', category: 'symmetric', quantumStatus: 'classical-weak', baseSeverity: 'high', usage: 'symmetric encryption (weak)', confidence: 0.95 },
  { regex: /ChaCha20|chacha20/g, algorithm: 'ChaCha20', category: 'symmetric', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'symmetric encryption', confidence: 0.95 },
  { regex: /RC4|Arcfour|arcfour/gi, algorithm: 'RC4', category: 'symmetric', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'symmetric encryption (broken)', confidence: 0.96 },

  // ── TLS / SSL ─────────────────────────────────────────────

  { regex: /TLSv?1\.?0|TLS_1_0|ssl\.PROTOCOL_TLSv1(?!_)/gi, algorithm: 'TLS 1.0', category: 'tls', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'transport layer security (obsolete)', confidence: 0.95 },
  { regex: /TLSv?1\.?1|TLS_1_1|ssl\.PROTOCOL_TLSv1_1/gi, algorithm: 'TLS 1.1', category: 'tls', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'transport layer security (obsolete)', confidence: 0.95 },
  { regex: /TLSv?1\.?2|TLS_1_2/gi, algorithm: 'TLS 1.2', category: 'tls', quantumStatus: 'adequate', baseSeverity: 'medium', usage: 'transport layer security', confidence: 0.93 },
  { regex: /TLSv?1\.?3|TLS_1_3/gi, algorithm: 'TLS 1.3', category: 'tls', quantumStatus: 'adequate', baseSeverity: 'info', usage: 'transport layer security (current)', confidence: 0.95 },
  { regex: /SSLv?2|ssl\.PROTOCOL_SSLv2/gi, algorithm: 'SSLv2', category: 'tls', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'transport layer security (broken)', confidence: 0.98 },
  { regex: /SSLv?3|ssl\.PROTOCOL_SSLv3/gi, algorithm: 'SSLv3', category: 'tls', quantumStatus: 'classical-weak', baseSeverity: 'critical', usage: 'transport layer security (broken)', confidence: 0.98 },

  // ── Secrets / Credentials ─────────────────────────────────

  { regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g, algorithm: 'Private Key', category: 'secret', quantumStatus: 'unknown', baseSeverity: 'critical', usage: 'private key material (embedded in source)', confidence: 0.99 },
  { regex: /(?:sk_live_|sk_test_)[a-zA-Z0-9]{20,}/g, algorithm: 'Stripe API Key', category: 'secret', quantumStatus: 'unknown', baseSeverity: 'critical', usage: 'API credential (hardcoded)', confidence: 0.99 },
  { regex: /(?:AKIA|ASIA|AIPA)[A-Z0-9]{16}/g, algorithm: 'AWS Access Key', category: 'secret', quantumStatus: 'unknown', baseSeverity: 'critical', usage: 'AWS credential (hardcoded)', confidence: 0.99 },
  { regex: /(?:jwt_secret|JWT_SECRET|jwtSecret)\s*[=:]\s*["'][^"']{8,}/gi, algorithm: 'JWT Secret', category: 'secret', quantumStatus: 'unknown', baseSeverity: 'critical', usage: 'JWT signing secret (hardcoded)', confidence: 0.96 },
  { regex: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi, algorithm: 'Hardcoded Password', category: 'secret', quantumStatus: 'unknown', baseSeverity: 'high', usage: 'credential (hardcoded)', confidence: 0.80 },
  { regex: /(?:api_key|API_KEY|apiKey)\s*[=:]\s*["'][a-zA-Z0-9_\-]{16,}["']/gi, algorithm: 'API Key', category: 'secret', quantumStatus: 'unknown', baseSeverity: 'critical', usage: 'API credential (hardcoded)', confidence: 0.85 },
  { regex: /ghp_[a-zA-Z0-9]{36}/g, algorithm: 'GitHub PAT', category: 'secret', quantumStatus: 'unknown', baseSeverity: 'critical', usage: 'GitHub personal access token (hardcoded)', confidence: 0.99 },

  // ── PQC Algorithms (good findings) ──────────────────────

  { regex: /ML-?KEM|CRYSTALS-?Kyber|kyber|Kyber(?:512|768|1024)/gi, algorithm: 'ML-KEM', category: 'pqc', quantumStatus: 'quantum-resistant', baseSeverity: 'info', usage: 'post-quantum key encapsulation', confidence: 0.96 },
  { regex: /ML-?DSA|CRYSTALS-?Dilithium|dilithium/gi, algorithm: 'ML-DSA', category: 'pqc', quantumStatus: 'quantum-resistant', baseSeverity: 'info', usage: 'post-quantum digital signature', confidence: 0.96 },
  { regex: /SLH-?DSA|SPHINCS\+?|sphincsplus/gi, algorithm: 'SLH-DSA', category: 'pqc', quantumStatus: 'quantum-resistant', baseSeverity: 'info', usage: 'post-quantum digital signature (hash-based)', confidence: 0.96 },
  { regex: /FALCON|falcon-(?:512|1024)/gi, algorithm: 'FALCON', category: 'pqc', quantumStatus: 'quantum-resistant', baseSeverity: 'info', usage: 'post-quantum digital signature', confidence: 0.95 },
];

// ─── Language Detection ──────────────────────────────────────

function detectLanguage(filename: string): Language {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, Language> = {
    py: 'python', java: 'java', js: 'javascript', ts: 'typescript',
    jsx: 'javascript', tsx: 'typescript', go: 'go',
    yml: 'yaml', yaml: 'yaml', json: 'json', xml: 'xml',
  };
  return map[ext] ?? 'unknown';
}

// ─── Secret Masking ──────────────────────────────────────────

function maskSecret(value: string): string {
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

function shouldMask(category: AlgorithmCategory): boolean {
  return category === 'secret';
}

// ─── Finding ID Generator ─────────────────────────────────────

let findingCounter = 0;
function generateId(): string {
  return `QG-${String(++findingCounter).padStart(4, '0')}`;
}

// ─── Context Inference ────────────────────────────────────────

function inferService(filePath: string): string {
  const lower = filePath.toLowerCase();
  if (lower.includes('payment') || lower.includes('billing') || lower.includes('stripe')) return 'Payment Service';
  if (lower.includes('auth') || lower.includes('login') || lower.includes('oauth') || lower.includes('jwt')) return 'Authentication Service';
  if (lower.includes('api') || lower.includes('gateway') || lower.includes('router')) return 'API Gateway';
  if (lower.includes('user') || lower.includes('profile') || lower.includes('account')) return 'User Service';
  if (lower.includes('order') || lower.includes('transaction') || lower.includes('trade')) return 'Transaction Service';
  if (lower.includes('crypto') || lower.includes('cipher') || lower.includes('encrypt')) return 'Crypto Library';
  if (lower.includes('cert') || lower.includes('pki') || lower.includes('tls')) return 'PKI/TLS Layer';
  if (lower.includes('db') || lower.includes('database') || lower.includes('repository') || lower.includes('store')) return 'Data Layer';
  if (lower.includes('config') || lower.includes('setting')) return 'Configuration';
  if (lower.includes('test')) return 'Test Suite';
  return 'Core Services';
}

function inferInternetFacing(filePath: string, service: string): boolean {
  const lower = filePath.toLowerCase();
  const internetServices = ['Payment Service', 'API Gateway', 'Authentication Service'];
  return internetServices.includes(service) ||
    lower.includes('public') || lower.includes('external') || lower.includes('api');
}

function inferDataSensitivity(service: string, algorithm: string): 'critical' | 'high' | 'medium' | 'low' {
  const criticalServices = ['Payment Service', 'Authentication Service', 'Data Layer'];
  if (criticalServices.includes(service)) return 'critical';
  if (algorithm === 'Private Key' || algorithm.includes('AWS') || algorithm.includes('JWT')) return 'critical';
  if (service.includes('User') || service.includes('Transaction')) return 'high';
  return 'medium';
}

function inferDataLifetime(service: string, category: AlgorithmCategory): number {
  if (service === 'Payment Service') return 15; // financial data
  if (service === 'Authentication Service') return 1;
  if (category === 'secret') return 1;
  if (service === 'Data Layer') return 25;
  return 5;
}

// ─── Main Scanner ─────────────────────────────────────────────

export interface ScanFile {
  path: string;
  content: string;
  repository?: string;
  project?: string;
}

export function scanFile(file: ScanFile): Finding[] {
  const findings: Finding[] = [];
  const { path: filePath, content, repository = 'unknown', project = 'unknown' } = file;
  const language = detectLanguage(filePath);
  const lines = content.split('\n');
  const service = inferService(filePath);
  const internetFacing = inferInternetFacing(filePath, service);

  const seenPositions = new Set<string>();

  for (const pattern of PATTERNS) {
    // Skip language-specific patterns for wrong language
    if (pattern.languages && language !== 'unknown' && !pattern.languages.includes(language)) {
      // still apply if unknown
      if (language !== 'unknown') continue;
    }

    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(content)) !== null) {
      // Find line number
      const textBefore = content.slice(0, match.index);
      const lineNumber = textBefore.split('\n').length;

      const posKey = `${filePath}:${lineNumber}:${pattern.algorithm}`;
      if (seenPositions.has(posKey)) continue;
      seenPositions.add(posKey);

      // Extract matched snippet
      let detectedPattern = match[0].slice(0, 100);
      if (shouldMask(pattern.category) && detectedPattern.length > 16) {
        detectedPattern = maskSecret(detectedPattern);
      }

      const dataSensitivity = inferDataSensitivity(service, pattern.algorithm);
      const dataLifetimeYears = inferDataLifetime(service, pattern.category);

      // Extract key size from match groups if present
      let keySize = pattern.keySize;
      if (!keySize && match[1]) {
        const parsed = parseInt(match[1]);
        if (!isNaN(parsed)) keySize = parsed;
      }

      const riskBreakdown = computeRiskScore({
        quantumStatus: pattern.quantumStatus,
        baseSeverity: pattern.baseSeverity,
        internetFacing,
        dataSensitivity,
        dataLifetimeYears,
        isHardcoded: content.slice(Math.max(0, match.index - 50), match.index + match[0].length).includes('='),
        service,
      });

      const finding: Finding = {
        id: generateId(),
        file: filePath,
        line: lineNumber,
        repository,
        project,
        service,
        language,
        algorithm: pattern.algorithm,
        keySize,
        category: pattern.category,
        usage: pattern.usage,
        detectedPattern,
        confidence: pattern.confidence,
        quantumStatus: pattern.quantumStatus,
        severity: riskBreakdown.totalScore >= 80 ? 'critical' :
                  riskBreakdown.totalScore >= 60 ? 'high' :
                  riskBreakdown.totalScore >= 40 ? 'medium' :
                  riskBreakdown.totalScore >= 20 ? 'low' : 'info',
        internetFacing,
        dataSensitivity,
        dataLifetimeYears,
        isCryptoAgile: false,
        isHardcoded: pattern.category === 'secret' ||
          lines[lineNumber - 1]?.includes('=') === true,
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        remediationStatus: 'open',
        migrationPriority: 0, // set after all findings
        recommendedAlgorithm: getRecommendation(pattern.algorithm, pattern.category, pattern.usage),
        migrationStrategy: getMigrationStrategy(pattern.algorithm, pattern.category, pattern.usage),
        owner: undefined,
        tags: buildTags(pattern),
        detectedAt: new Date().toISOString(),
      };

      findings.push(finding);
    }
  }

  // Set migration priorities
  const sorted = [...findings].sort((a, b) => b.riskScore - a.riskScore);
  sorted.forEach((f, i) => { f.migrationPriority = i + 1; });

  return findings;
}

export function scanFiles(files: ScanFile[]): Finding[] {
  findingCounter = 0;
  const all: Finding[] = [];
  for (const file of files) {
    all.push(...scanFile(file));
  }
  // Re-assign global migration priorities
  all.sort((a, b) => b.riskScore - a.riskScore);
  all.forEach((f, i) => { f.migrationPriority = i + 1; });
  return all;
}

// ─── Recommendation Engine ────────────────────────────────────

function getRecommendation(algorithm: string, category: AlgorithmCategory, usage: string): string {
  const alg = algorithm.toUpperCase();
  const usageLower = usage.toLowerCase();

  if (alg === 'MD5') return 'SHA-256 or SHA-3-256 for non-security uses; Argon2 for password hashing';
  if (alg === 'SHA-1') return 'SHA-256 or SHA-3-256';
  if (alg === 'DES') return 'AES-256-GCM';
  if (alg === '3DES') return 'AES-256-GCM';
  if (alg === 'RC4') return 'ChaCha20-Poly1305 or AES-256-GCM';

  if (alg.startsWith('RSA')) {
    if (usageLower.includes('signature')) return 'ML-DSA (CRYSTALS-Dilithium) for post-quantum signatures';
    if (usageLower.includes('key')) return 'ML-KEM (CRYSTALS-Kyber) for post-quantum key establishment; hybrid approach recommended during transition';
    return 'ML-KEM for key encapsulation, ML-DSA for signatures — usage context determines exact strategy';
  }
  if (alg === 'ECDSA' || alg === 'DSA') return 'ML-DSA (CRYSTALS-Dilithium) or SLH-DSA for post-quantum digital signatures';
  if (alg === 'ECDH') return 'ML-KEM (CRYSTALS-Kyber) for post-quantum key encapsulation; hybrid X25519+ML-KEM during transition';
  if (alg === 'ECC') return 'ML-KEM (key exchange) or ML-DSA (signatures) depending on usage; evaluate hybrid approach';
  if (alg === 'DH') return 'ML-KEM for post-quantum key establishment';

  if (alg.includes('TLS 1.0') || alg.includes('TLS 1.1')) return 'TLS 1.3 (minimum TLS 1.2 with strong cipher suites)';
  if (alg.includes('SSL')) return 'TLS 1.3';
  if (alg.includes('SHA1WITH')) return 'SHA256withECDSA or ML-DSA for post-quantum';

  if (category === 'secret') return 'Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)';

  return 'Evaluate based on usage context and protocol constraints';
}

function getMigrationStrategy(algorithm: string, category: AlgorithmCategory, usage: string): string {
  const alg = algorithm.toUpperCase();
  const usageLower = usage.toLowerCase();

  if (category === 'secret') return 'Immediate rotation + secrets manager adoption';
  if (category === 'tls') return 'Protocol upgrade; enforce minimum TLS version in configuration';
  if (alg === 'MD5' || alg === 'SHA-1') return 'Hash function replacement — typically low-risk refactor; check for protocol constraints';

  if (alg.startsWith('RSA') || alg === 'ECC' || alg === 'ECDSA' || alg === 'ECDH' || alg === 'DH') {
    if (usageLower.includes('certificate')) return 'Plan certificate re-issuance with PQC or hybrid algorithm; coordinate with PKI team';
    return 'Phased hybrid migration: maintain classical algorithm + add ML-KEM/ML-DSA layer; full PQC migration in Phase 3';
  }

  return 'Assess compatibility requirements; plan migration with testing phase';
}

function buildTags(pattern: CryptoPattern): string[] {
  const tags: string[] = [pattern.category];
  if (pattern.quantumStatus === 'vulnerable') tags.push('quantum-vulnerable');
  if (pattern.quantumStatus === 'classical-weak') tags.push('classical-weak');
  if (pattern.quantumStatus === 'quantum-resistant') tags.push('pqc');
  if (pattern.category === 'secret') tags.push('secret', 'hardcoded');
  if (['MD5', 'SHA-1', 'DES', '3DES', 'RC4'].includes(pattern.algorithm)) tags.push('deprecated');
  return tags;
}
