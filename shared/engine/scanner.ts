// ============================================================
// Qrypto AI Advisor — Cryptographic Discovery Engine
// Deterministic scanner — source of truth, no LLM involved
// ============================================================

import type { Finding, Language, AlgorithmCategory, QuantumStatus, Severity, ClassicalStatus, CryptoMode } from '../types';
import { computeRiskScore } from './riskEngine';
import { deriveAlgorithmSeverity, deriveEffectiveSeverity } from './severity';
import { lookupAlgorithm } from './registry';


import { ALL_PATTERNS, type CryptoPattern } from './detectors';

const PATTERNS = ALL_PATTERNS;

// ─── P0-4: Computed Confidence ─────────────────────────────
// Confidence is evidence-based, not a copy of the pattern constant.
// The pattern.confidence serves as a *base* that reflects regex specificity;
// then we add/subtract based on what evidence is available.
//
// Design: AST corroboration is structured so it can be added later when
// the AST layer is revived, but we do NOT fake it now.

interface ConfidenceInput {
  /** Pattern-defined base confidence (regex specificity). */
  baseConfidence: number;
  /** Whether a key size was successfully extracted from the match. */
  keySizeExtracted: boolean;
  /** Whether the match is in a comment or string literal (heuristic). */
  inCommentOrString: boolean;
  /** Whether the file path looks like a test, vendor, fixture, or node_modules. */
  inTestOrVendorPath: boolean;
  /** Whether AST corroboration is available (currently false — AST is dead). */
  astCorroborated: boolean;
  /** Whether a corroborating dependency was found (e.g. package.json lists the crypto lib). */
  dependencyCorroborated: boolean;
}

interface ConfidenceResult {
  confidence: number;
  derivation: string;
}

/**
 * Compute confidence from available evidence, clamped to [0, 1].
 * Every adjustment is documented in the derivation string so the value
 * is auditable rather than merely asserted.
 */
function computeConfidence(input: ConfidenceInput): ConfidenceResult {
  let score = input.baseConfidence;
  const reasons: string[] = [`base ${input.baseConfidence.toFixed(2)} from pattern specificity`];

  // Positive: key size extraction confirms this is a real cryptographic call,
  // not just a coincidental string match.
  if (input.keySizeExtracted) {
    score += 0.05;
    reasons.push('+0.05 key size extracted');
  }

  // Positive: AST corroboration (reserved for when AST layer is revived)
  if (input.astCorroborated) {
    score += 0.10;
    reasons.push('+0.10 AST confirms valid code node');
  }

  // Positive: corroborating dependency present
  if (input.dependencyCorroborated) {
    score += 0.05;
    reasons.push('+0.05 corroborating dependency found');
  }

  // Penalty: in a comment or string literal — likely documentation, not usage
  if (input.inCommentOrString) {
    score -= 0.30;
    reasons.push('-0.30 in comment or string literal');
  }

  // Penalty: test/vendor/fixture/node_modules path — less likely to be production crypto
  if (input.inTestOrVendorPath) {
    score -= 0.20;
    reasons.push('-0.20 in test/vendor/fixture path');
  }

  const confidence = Math.max(0, Math.min(1, Math.round(score * 100) / 100));
  const derivation = reasons.join('; ') + '.';

  return { confidence, derivation };
}

/** Heuristic: does this line look like a comment or string containing the match? */
function isInCommentOrString(content: string, matchIndex: number): boolean {
  const lineStart = content.lastIndexOf('\n', matchIndex);
  const line = content.slice(lineStart + 1, matchIndex + 200).split('\n')[0];
  const trimmed = line.trimStart();
  // Lines starting with //, #, /*, *, <!-- are comments
  if (/^(\/\/|#|\/\*|\*|<!--)/.test(trimmed)) return true;
  // Check if the match is inside quotes
  const beforeMatch = line.slice(0, matchIndex - lineStart - 1);
  const singleQuotes = (beforeMatch.match(/'/g) || []).length;
  const doubleQuotes = (beforeMatch.match(/"/g) || []).length;
  if (singleQuotes % 2 === 1 || doubleQuotes % 2 === 1) {
    // Inside a string — but is it a standalone string (documentation) or a
    // value in code? Strings used as API arguments (e.g. name: 'RSA-OAEP',
    // algorithm: 'AES-GCM') are genuine code, not documentation.
    // Heuristic: if the line contains a colon, equals, or opening paren before
    // the quote, the string is likely a value in code, not a standalone string.
    const codeIndicators = /[:=,\(]\s*['"]/.test(beforeMatch);
    if (codeIndicators) return false; // string value in code = real usage
    return true; // standalone string = likely documentation
  }
  return false;
}

/** Heuristic: does the file path suggest a test, vendor, fixture, or generated file? */
function isInTestOrVendorPath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return /(?:test|tests|__tests__|spec|specs|mock|mocks|fixture|fixtures|vendor|node_modules|__mocks__|\.test\.|\.spec\.|generated|dist\/)/.test(lower);
}

// ─── P0-10: Field Detection Helpers ──────────────────────────
// These extract mode, library, protocol, variant from the matched
// pattern and file context. Only populated when evidence exists;
// otherwise left undefined (never fabricated).

/** Detect cipher mode (GCM, CBC, ECB, etc.) from matched pattern. */
function detectMode(matchedText: string, algorithm: string): CryptoMode | undefined {
  const upper = matchedText.toUpperCase();
  if (upper.includes('GCM')) return 'GCM';
  if (upper.includes('CBC')) return 'CBC';
  if (upper.includes('ECB')) return 'ECB';
  if (upper.includes('CTR')) return 'CTR';
  if (upper.includes('CFB')) return 'CFB';
  if (upper.includes('OFB')) return 'OFB';
  if (upper.includes('CCM')) return 'CCM';
  // Only return a mode if the algorithm is a cipher type
  if (algorithm.toUpperCase().includes('AES') || algorithm.toUpperCase().includes('DES') ||
      algorithm.toUpperCase().includes('RC4') || algorithm.toUpperCase().includes('CHACHA')) {
    return undefined; // cipher detected but mode not found
  }
  return undefined;
}

/** Detect cryptographic library from import/dependency context. */
function detectLibrary(matchedText: string, filePath: string): string | undefined {
  const text = matchedText.toLowerCase();
  const path = filePath.toLowerCase();

  // Python libraries
  if (text.includes('from cryptography') || text.includes('import cryptography')) return 'cryptography';
  if (text.includes('from cryptography.hazmat')) return 'cryptography';
  if (text.includes('pycryptodome') || text.includes('Crypto.Cipher') || text.includes('Crypto.Hash')) return 'pycryptodome';
  if (text.includes('hashlib')) return 'hashlib';
  if (text.includes('ssl')) return 'ssl';

  // Node.js libraries
  if (text.includes('require(') && text.includes('crypto')) return 'node:crypto';
  if (text.includes('crypto.subtle')) return 'Web Crypto API';
  if (text.includes('crypto-js')) return 'crypto-js';
  if (text.includes('bcrypt')) return 'bcrypt';
  if (text.includes('jsonwebtoken')) return 'jsonwebtoken';

  // Java libraries
  if (text.includes('javax.crypto')) return 'JCE';
  if (text.includes('java.security')) return 'JCA';
  if (text.includes('bouncycastle') || text.includes('org.bouncycastle')) return 'Bouncy Castle';

  // Go libraries
  if (text.includes('crypto/')) return 'Go crypto';
  if (text.includes('tls')) return 'Go crypto/tls';

  // File path hints
  if (path.includes('nginx') || path.includes('apache')) return 'server-config';

  return undefined;
}

/** Detect protocol version from matched pattern. */
function detectProtocol(matchedText: string, category: AlgorithmCategory): string | undefined {
  if (category !== 'tls') return undefined;
  const upper = matchedText.toUpperCase();
  if (upper.includes('TLS 1.3') || upper.includes('TLSV1_3') || upper.includes('TLSV13')) return 'TLS 1.3';
  if (upper.includes('TLS 1.2') || upper.includes('TLSV1_2') || upper.includes('TLSV12')) return 'TLS 1.2';
  if (upper.includes('TLS 1.1') || upper.includes('TLSV1_1') || upper.includes('TLSV11')) return 'TLS 1.1';
  if (upper.includes('TLS 1.0') || upper.includes('TLSV1') || upper.includes('TLSV10')) return 'TLS 1.0';
  if (upper.includes('SSLV3') || upper.includes('SSL 3')) return 'SSL 3.0';
  if (upper.includes('SSLV2') || upper.includes('SSL 2')) return 'SSL 2.0';
  return undefined;
}

/** Detect algorithm variant from key size and match context. */
function detectVariant(algorithm: string, keySize: number | undefined, matchedText: string): string | undefined {
  const upper = algorithm.toUpperCase();
  // RSA variants by key size
  if (upper.includes('RSA') && typeof keySize === 'number') return `RSA-${keySize}`;
  // ECC curves
  if (matchedText.toUpperCase().includes('P-256') || matchedText.toUpperCase().includes('SECP256R1')) return 'secp256r1';
  if (matchedText.toUpperCase().includes('P-384') || matchedText.toUpperCase().includes('SECP384R1')) return 'secp384r1';
  if (matchedText.toUpperCase().includes('P-521') || matchedText.toUpperCase().includes('SECP521R1')) return 'secp521r1';
  if (matchedText.toUpperCase().includes('X25519')) return 'X25519';
  if (matchedText.toUpperCase().includes('ED25519')) return 'Ed25519';
  // AES variants
  if (upper.includes('AES') && typeof keySize === 'number') return `AES-${keySize}`;
  // ML-KEM variants
  if (upper.includes('ML-KEM-768') || upper.includes('KYBER-768')) return 'ML-KEM-768';
  if (upper.includes('ML-KEM-1024') || upper.includes('KYBER-1024')) return 'ML-KEM-1024';
  if (upper.includes('ML-KEM-512') || upper.includes('KYBER-512')) return 'ML-KEM-512';
  // ML-DSA variants
  if (upper.includes('ML-DSA-65') || upper.includes('DILITHIUM-65')) return 'ML-DSA-65';
  if (upper.includes('ML-DSA-87') || upper.includes('DILITHIUM-87')) return 'ML-DSA-87';
  return undefined;
}


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

// ─── P0-8: Finding Fingerprint ─────────────────────────────
// Fingerprint is deterministic and stable across rescans.
// It deliberately excludes line numbers so inserting a line above
// doesn't resurrect a suppressed finding.

function generateFingerprint(
  repository: string,
  filePath: string,
  algorithm: string,
  usage: string,
  detectedPattern: string
): string {
  // Normalize: lowercase, strip whitespace, normalize path separators
  const norm = (s: string) => s.toLowerCase().replace(/\s+/g, ' ').replace(/\\/g, '/').trim();
  const normalizedPath = norm(filePath);
  const normalizedPattern = norm(detectedPattern).slice(0, 80); // cap length
  const normalizedRepo = norm(repository);
  
  const payload = `${normalizedRepo}:${normalizedPath}:${norm(algorithm)}:${norm(usage)}:${normalizedPattern}`;
  
  // Deterministic string hash (cross-platform, no dependencies)
  let hash = 0;
  for (let i = 0; i < payload.length; i++) {
    const char = payload.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return `fp-${Math.abs(hash).toString(16).padStart(8, '0')}`;
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

      // Severity is derived on two independent axes and never collapsed into
      // the contextual risk score. See shared/engine/severity.ts.
      const algorithmSeverity = deriveAlgorithmSeverity({
        algorithm: pattern.algorithm,
        quantumStatus: pattern.quantumStatus,
        baseSeverity: pattern.baseSeverity,
        keySize,
        category: pattern.category,
      });

      const effective = deriveEffectiveSeverity({
        algorithmSeverity: algorithmSeverity.severity,
        quantumStatus: pattern.quantumStatus,
        contextualRisk: riskBreakdown.totalScore,
      });

      // Compute confidence from evidence, not from pattern constant.
      const confidenceResult = computeConfidence({
        baseConfidence: pattern.confidence,
        keySizeExtracted: typeof keySize === 'number' && keySize > 0,
        inCommentOrString: isInCommentOrString(content, match.index),
        inTestOrVendorPath: isInTestOrVendorPath(filePath),
        astCorroborated: false, // AST layer is currently dead; do not fabricate
        dependencyCorroborated: false, // would need cross-file analysis
      });

      const now = new Date().toISOString();
      const fingerprint = generateFingerprint(
        repository,
        filePath,
        pattern.algorithm,
        pattern.usage,
        detectedPattern
      );

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
        confidence: confidenceResult.confidence,
        quantumStatus: pattern.quantumStatus,
        classicalStatus: deriveClassicalStatus(pattern.algorithm, pattern.quantumStatus, pattern.category),
        algorithmSeverity: algorithmSeverity.severity,
        severity: effective.severity,
        severityRationale: `${algorithmSeverity.rationale}. ${effective.rationale}`,
        internetFacing,
        dataSensitivity,
        dataLifetimeYears,
        isCryptoAgile: false,
        isHardcoded: pattern.category === 'secret' ||
          lines[lineNumber - 1]?.includes('=') === true,
        contextSource: 'INFERRED', // all context fields derived from heuristics
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        remediationStatus: 'open',
        migrationPriority: 0, // set after all findings
        recommendedAlgorithm: getRecommendation(pattern.algorithm, pattern.category, pattern.usage),
        migrationStrategy: getMigrationStrategy(pattern.algorithm, pattern.category, pattern.usage),
        owner: undefined,
        // P0-10: Classification fields — populated when evidence exists, undefined otherwise
        mode: detectMode(detectedPattern, pattern.algorithm),
        library: detectLibrary(detectedPattern, filePath),
        protocol: detectProtocol(detectedPattern, pattern.category),
        variant: detectVariant(pattern.algorithm, keySize, detectedPattern),
        tags: buildTags(pattern),
        detectedAt: now,
        // P0-8: Fingerprint and temporal tracking
        fingerprint,
        firstSeen: now,
        lastSeen: now,
        evidence: {
          detectionLayers: ['regex'],
          matchedText: detectedPattern,
          confidenceDerivation: confidenceResult.derivation,
        },
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

/**
 * Get PQC recommendation for an algorithm.
 * Primary source: algorithm registry (canonical, maintained).
 * Fallback: context-aware if/else for algorithms not in registry.
 */
function getRecommendation(algorithm: string, category: AlgorithmCategory, usage: string): string {
  const usageLower = usage.toLowerCase();
  const alg = algorithm.toUpperCase();

  // 1. Context-specific recommendations based on category and usage
  //    These take priority because they are derived from actual evidence.
  if (category === 'secret') return 'Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)';
  if (category === 'tls') {
    if (alg.includes('TLS 1.0') || alg.includes('TLS 1.1') || alg.includes('SSL')) return 'TLS 1.3 (minimum TLS 1.2 with strong cipher suites)';
    return 'Monitor for deprecation updates';
  }

  // 2. Symmetric ciphers — NEVER recommend ML-KEM/ML-DSA for symmetric crypto
  if (category === 'symmetric') {
    if (alg.includes('DES') || alg.includes('3DES') || alg.includes('RC4')) {
      return 'Replace with AES-256-GCM or ChaCha20-Poly1305';
    }
    return 'Classically adequate symmetric algorithm. Monitor for key size recommendations.';
  }

  // 3. Hash functions — replace with modern hashes, NOT PQC key exchange
  if (category === 'hash') {
    if (alg.includes('MD5')) return 'Replace with SHA-256 (integrity) or Argon2id (password hashing)';
    if (alg.includes('SHA-1') || alg.includes('SHA1')) return 'Replace with SHA-256 or SHA-3-256';
    return 'Classically adequate hash. Monitor for deprecation.';
  }

  // 4. Public-key / signature / key-exchange — usage-aware PQC recommendations
  if (category === 'public-key' || category === 'signature' || category === 'key-exchange') {
    // Usage-aware: check actual usage context to pick the right PQC replacement
    const isSignature = usageLower.includes('sign') || usageLower.includes('auth') || usageLower.includes('cert') || usageLower.includes('verify');
    const isKeyExchange = usageLower.includes('key') || usageLower.includes('exchange') || usageLower.includes('encapsulat') || usageLower.includes('encrypt') || usageLower.includes('wrap') || usageLower.includes('establish');

    if (isSignature) {
      // Signature usage → ML-DSA (FIPS 204)
      if (alg.includes('ECDSA') || alg === 'DSA' || alg.includes('ED25519')) {
        return 'ML-DSA-65 (FIPS 204) for post-quantum digital signatures';
      }
      if (alg.startsWith('RSA')) {
        return 'ML-DSA-65 (FIPS 204) for post-quantum digital signatures';
      }
    }

    if (isKeyExchange) {
      // Key exchange / encapsulation usage → ML-KEM (FIPS 203)
      if (alg.includes('ECDH') || alg === 'DH' || alg.includes('X25519')) {
        return 'ML-KEM-768 (FIPS 203) for post-quantum key establishment';
      }
      if (alg.startsWith('RSA')) {
        return 'ML-KEM-768 (FIPS 203) for post-quantum key establishment';
      }
    }

    // Category-based fallback when usage context is ambiguous
    if (category === 'signature') {
      return 'ML-DSA-65 (FIPS 204) for post-quantum digital signatures';
    }
    if (category === 'key-exchange') {
      return 'ML-KEM-768 (FIPS 203) for post-quantum key establishment';
    }

    // For public-key category without clear usage context, check registry
    const entry = lookupAlgorithm(algorithm);
    if (entry.pqcReplacement) {
      return entry.pqcReplacement;
    }

    return 'Evaluate algorithm usage context and replace with appropriate NIST PQC standard (FIPS 203 for key exchange, FIPS 204 for signatures)';
  }

  // 5. PQC algorithms — already migrated
  const entry = lookupAlgorithm(algorithm);
  if (entry.quantumStatus === 'quantum-resistant') return 'Already quantum-resistant. No migration needed.';
  if (entry.quantumStatus === 'adequate') return 'Classically adequate. Monitor for deprecation updates.';

  // 6. Unknown algorithm — be honest
  if (entry.quantumStatus === 'unknown') {
    return 'Insufficient context for a definitive PQC recommendation. Manual review required — classify the algorithm and evaluate quantum vulnerability before migration planning.';
  }

  return 'Evaluate algorithm usage context and replace with appropriate NIST PQC standard';
}

function getMigrationStrategy(algorithm: string, category: AlgorithmCategory, usage: string): string {
  const entry = lookupAlgorithm(algorithm);
  const alg = algorithm.toUpperCase();
  const usageLower = usage.toLowerCase();

  if (category === 'secret') return 'Immediate rotation + secrets manager adoption';
  if (category === 'tls') return 'Protocol upgrade; enforce minimum TLS version in configuration';

  // PQC algorithms — already migrated
  if (entry.quantumStatus === 'quantum-resistant') return 'Already quantum-resistant. No migration needed.';

  // Adequate algorithms — monitor only
  if (entry.quantumStatus === 'adequate') return 'Classically adequate. Monitor for deprecation updates.';

  // Unknown — be honest
  if (entry.quantumStatus === 'unknown') return 'Algorithm not recognized. Manual classification required before migration planning.';

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
  // Flag algorithms not in the registry for manual review
  const entry = lookupAlgorithm(pattern.algorithm);
  if (entry.quantumStatus === 'unknown') tags.push('review-required');
  return tags;
}
