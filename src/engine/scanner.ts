// ============================================================
// QuantumGuard AI — Cryptographic Discovery Engine
// Deterministic scanner — source of truth, no LLM involved
// ============================================================

import type { Finding, Language, AlgorithmCategory, QuantumStatus, Severity, ClassicalStatus } from '../types';
import { computeRiskScore } from './riskEngine';

import { ALL_PATTERNS, type CryptoPattern } from './detectors';

const PATTERNS = ALL_PATTERNS;


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

// ─── Classical Status Derivation ─────────────────────────────

function deriveClassicalStatus(algorithm: string, quantumStatus: QuantumStatus, category: AlgorithmCategory): ClassicalStatus {
  const a = algorithm.toUpperCase();
  // Classically broken algorithms
  if (['MD5', 'DES', 'RC4', 'SSLv2', 'SSLv3'].some(x => a.includes(x))) return 'broken';
  // Classically weak (deprecated)
  if (['SHA-1', 'SHA1', '3DES', 'TDES', 'DESEDE', 'TLS 1.0', 'TLS 1.1'].some(x => a.includes(x))) return 'weak';
  // Classically strong (quantum-vulnerable but classically fine)
  if (a.includes('RSA') || a.includes('ECDSA') || a.includes('ECDH') || a.includes('ECC') || a === 'DH') return 'adequate';
  // Classically strong symmetric/hash
  if (['AES-256', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-3', 'TLS 1.3', 'CHACHA20'].some(x => a.includes(x))) return 'strong';
  if (a.includes('AES-128')) return 'adequate';
  if (a.includes('TLS 1.2')) return 'adequate';
  if (category === 'pqc') return 'strong';
  if (quantumStatus === 'classical-weak') return 'weak';
  if (quantumStatus === 'adequate' || quantumStatus === 'quantum-resistant') return 'adequate';
  return 'unknown';
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
      continue;
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
        classicalStatus: deriveClassicalStatus(pattern.algorithm, pattern.quantumStatus, pattern.category),
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
