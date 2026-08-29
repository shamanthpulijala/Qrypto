// ============================================================
// Qrypto — Detector: Binary Crypto Artifact Discovery
//
// Implements SAFE STATIC binary inspection for ELF and PE files.
// Uses ASCII/UTF-8 string scanning only — no code execution,
// no native library loading, no dynamic analysis.
//
// SAFETY RULES (absolute):
//   - NEVER execute binaries
//   - NEVER load untrusted native code
//   - Treat all input as hostile
//   - Enforce hard limits on file size and strings processed
//   - detectionMethod = binary-static-analysis for all findings
// ============================================================

import type { Finding, Severity } from '../../types';
import { computeRiskScore } from '../riskEngine';
import { deriveAlgorithmSeverity, deriveEffectiveSeverity } from '../severity';

// ─── Safety Limits ──────────────────────────────────────────
const MAX_BINARY_SIZE = 500 * 1024 * 1024;  // 500 MB max
const MAX_STRINGS_SCANNED = 10000;          // max strings to process
const MAX_STRING_LENGTH = 200;              // max individual string length
const MIN_STRING_LENGTH = 4;                // minimum for meaningful detection

// ─── Crypto Library References (in binary strings) ──────────

interface BinaryCryptoPattern {
  regex: RegExp;
  algorithm: string;
  usage: string;
  severity: Severity;
  confidence: number;
  category: 'imported-library' | 'exported-symbol' | 'crypto-reference' | 'protocol-reference';
}

const BINARY_CRYPTO_PATTERNS: BinaryCryptoPattern[] = [
  // ── OpenSSL / libcrypto ──
  {
    regex: /libcrypto[.\-]?\d*(?:\.so|\.dll|\.dylib)?|libssl[.\-]?\d*(?:\.so|\.dll|\.dylib)?/gi,
    algorithm: 'OpenSSL',
    usage: 'OpenSSL library reference in binary',
    severity: 'low',
    confidence: 0.88,
    category: 'imported-library',
  },
  {
    regex: /EVP_[A-Z]{2,30}|RSA_[A-Z]{3,20}|AES_[A-Z]{3,20}|DES_[A-Z]{3,20}|SHA[125]_[A-Z]{3,20}/g,
    algorithm: 'OpenSSL',
    usage: 'OpenSSL API symbol reference',
    severity: 'info',
    confidence: 0.92,
    category: 'exported-symbol',
  },

  // ── Windows crypto DLLs ──
  {
    regex: /bcrypt\.dll|crypt32\.dll|wincrypt\.dll|ncrypt\.dll/gi,
    algorithm: 'Windows CryptoAPI',
    usage: 'Windows cryptography DLL reference',
    severity: 'info',
    confidence: 0.90,
    category: 'imported-library',
  },
  {
    regex: /BCrypt[A-Z]\w{5,30}|Crypt[A-Z]\w{5,30}/g,
    algorithm: 'Windows CryptoAPI',
    usage: 'Windows crypto API function reference',
    severity: 'info',
    confidence: 0.85,
    category: 'exported-symbol',
  },

  // ── Bouncy Castle ──
  {
    regex: /bouncycastle|bcprov|bcpkix|bctls/gi,
    algorithm: 'Bouncy Castle',
    usage: 'Bouncy Castle crypto library reference',
    severity: 'info',
    confidence: 0.88,
    category: 'imported-library',
  },

  // ── NSS (Mozilla) ──
  {
    regex: /libnss[3]?\.so|nss3\.dll|NSS_[A-Z]{3,20}/g,
    algorithm: 'NSS',
    usage: 'Mozilla NSS library reference',
    severity: 'info',
    confidence: 0.85,
    category: 'imported-library',
  },

  // ── GnuTLS ──
  {
    regex: /libgnutls[.\-]?\d*(?:\.so|\.dll|\.dylib)?|gnutls_[a-z_]{3,30}/gi,
    algorithm: 'GnuTLS',
    usage: 'GnuTLS library reference',
    severity: 'info',
    confidence: 0.85,
    category: 'imported-library',
  },

  // �─ Crypto protocol references ──
  {
    regex: /TLSv1\.[0-3]|SSLv[23]|TLS_[A-Z]+_WITH_[A-Z]+/g,
    algorithm: 'TLS Protocol',
    usage: 'TLS protocol version reference in binary',
    severity: 'info',
    confidence: 0.82,
    category: 'protocol-reference',
  },

  // ── Specific algorithm strings ──
  {
    regex: /AES(?:128|192|256)[A-Z]?|DES(?:3|_EDE3)?|RC4|CHACHA20|RSA[124]\d{3}|ECDSA|ECDH/g,
    algorithm: 'Crypto Algorithm String',
    usage: 'cryptographic algorithm string in binary',
    severity: 'info',
    confidence: 0.78,
    category: 'crypto-reference',
  },

  // ── Key/certificate file references ──
  {
    regex: /\.(?:pem|key|crt|p12|pfx|jks|keystore|truststore)\b/gi,
    algorithm: 'Certificate File Reference',
    usage: 'cryptographic file extension reference in binary',
    severity: 'low',
    confidence: 0.75,
    category: 'crypto-reference',
  },
];

// ─── Binary Detection ───────────────────────────────────────

function isLikelyBinary(content: string): boolean {
  // Check for ELF or PE magic bytes
  if (content.length < 4) return false;

  const b0 = content.charCodeAt(0) & 0xFF;
  const b1 = content.charCodeAt(1) & 0xFF;
  const b2 = content.charCodeAt(2) & 0xFF;
  const b3 = content.charCodeAt(3) & 0xFF;

  // ELF magic: 0x7F 'E' 'L' 'F'
  if (b0 === 0x7F && b1 === 0x45 && b2 === 0x4C && b3 === 0x46) return true;

  // PE magic: 'M' 'Z' (0x4D 0x5A)
  if (b0 === 0x4D && b1 === 0x5A) return true;

  // Check for high ratio of null bytes (binary indicator)
  const nullCount = (content.match(/\0/g) || []).length;
  if (nullCount > content.length * 0.05) return true;

  return false;
}

function extractStrings(content: string, maxStrings: number = MAX_STRINGS_SCANNED): string[] {
  const strings: string[] = [];
  // Extract printable ASCII strings of MIN_STRING_LENGTH or more
  const regex = new RegExp(`[\x20-\x7E]{${MIN_STRING_LENGTH},${MAX_STRING_LENGTH}}`, 'g');
  let match: RegExpExecArray | null;
  let count = 0;

  while ((match = regex.exec(content)) !== null && count < maxStrings) {
    strings.push(match[0]);
    count++;
  }

  return strings;
}

// ─── Main Detector ──────────────────────────────────────────

export function detectBinaryArtifacts(
  filePath: string,
  content: string,
  repository: string,
  project: string,
): Finding[] {
  const findings: Finding[] = [];

  // Size safety check
  if (content.length > MAX_BINARY_SIZE) return findings;

  // Check if content looks binary
  if (!isLikelyBinary(content)) return findings;

  const now = new Date().toISOString();

  // Extract strings for analysis
  const strings = extractStrings(content);

  // Search each string for crypto patterns
  for (const str of strings) {
    for (const pattern of BINARY_CRYPTO_PATTERNS) {
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(str);
      if (!match) continue;

      const detectedPattern = match[0];

      // Deduplicate: same algorithm + same file
      const posKey = `${filePath}:${pattern.algorithm}:${detectedPattern}`;
      if (findings.some(f => f.file === filePath && f.algorithm === pattern.algorithm && f.detectedPattern === detectedPattern)) continue;

      // For binaries, we can't determine line numbers accurately
      // Use string position as best approximation
      const stringIndex = content.indexOf(str);
      const lineNumber = stringIndex >= 0
        ? content.slice(0, stringIndex).split('\n').length
        : 1;

      const confidence = pattern.confidence;
      const reasons: string[] = [
        `base ${pattern.confidence} from ${pattern.category}`,
        'detectionMethod: binary-static-analysis',
      ];

      const riskBreakdown = computeRiskScore({
        quantumStatus: 'adequate',
        baseSeverity: pattern.severity,
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isHardcoded: false,
        service: 'Binary Artifact',
      });

      const algorithmSeverity = deriveAlgorithmSeverity({
        algorithm: pattern.algorithm,
        quantumStatus: 'adequate',
        baseSeverity: pattern.severity,
        category: 'public-key',
      });

      const effective = deriveEffectiveSeverity({
        algorithmSeverity: algorithmSeverity.severity,
        quantumStatus: 'adequate',
        contextualRisk: riskBreakdown.totalScore,
      });

      findings.push({
        id: `bin-${Math.random().toString(36).substr(2, 9)}`,
        file: filePath,
        line: lineNumber,
        repository,
        project,
        service: 'Binary Artifact',
        language: 'unknown',
        algorithm: pattern.algorithm,
        category: 'public-key',
        usage: pattern.usage,
        detectedPattern,
        confidence,
        quantumStatus: 'adequate',
        classicalStatus: 'adequate',
        algorithmSeverity: algorithmSeverity.severity,
        severity: effective.severity,
        severityRationale: `${algorithmSeverity.rationale}. ${effective.rationale}. Binary static analysis — limited to string extraction.`,
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isCryptoAgile: false,
        isHardcoded: false,
        contextSource: 'UNKNOWN', // Cannot determine context from binary
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        remediationStatus: 'open',
        migrationPriority: 0,
        recommendedAlgorithm: 'Binary contains crypto library references; source-level analysis required for full assessment',
        migrationStrategy: 'Identify source code and perform source-level scan for accurate crypto inventory',
        tags: ['binary', 'static-analysis', pattern.category],
        detectedAt: now,
        firstSeen: now,
        lastSeen: now,
        evidence: {
          detectionLayers: ['binary-static-analysis'],
          matchedText: detectedPattern,
          confidenceDerivation: reasons.join('; ') + '.',
        },
      });
    }
  }

  return findings;
}
