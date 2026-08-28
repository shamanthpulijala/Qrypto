// ============================================================
// Qrypto — Detector: Hardware Crypto Modules (HSM / PKCS#11 / TPM)
//
// Detects explicit evidence of hardware security module usage,
// PKCS#11 interfaces, TPM libraries, and related providers.
//
// Evidence hierarchy (highest → lowest confidence):
//   1. API invocation / import of PKCS#11 library
//   2. Provider configuration pointing to HSM
//   3. Package dependency (package.json, requirements.txt)
//   4. Documentation / comments mentioning HSM
//
// IMPORTANT: "HSM" in documentation alone has lower confidence
// than actual import or API call.
// ============================================================

import type { Finding, AlgorithmCategory, Severity } from '../../types';
import { computeRiskScore } from '../riskEngine';
import { deriveAlgorithmSeverity, deriveEffectiveSeverity } from '../severity';

interface HardwarePattern {
  regex: RegExp;
  algorithm: string;
  category: AlgorithmCategory;
  usage: string;
  severity: Severity;
  confidence: number;
  /** Evidence description for why this pattern indicates hardware crypto */
  evidenceType: 'api-invocation' | 'library-import' | 'provider-config' | 'package-dependency' | 'documentation';
}

// ─── Detection Patterns ─────────────────────────────────────

const HARDWARE_PATTERNS: HardwarePattern[] = [
  // ── PKCS#11 API / Library Imports (highest confidence) ──
  {
    regex: /pkcs11|PKCS11|pkcs#11|PKCS#11/g,
    algorithm: 'PKCS#11',
    category: 'public-key',
    usage: 'hardware security module interface',
    severity: 'info',
    confidence: 0.85,
    evidenceType: 'api-invocation',
  },
  {
    regex: /Cryptoki|cryptoki|CRYPTOKI/g,
    algorithm: 'PKCS#11',
    category: 'public-key',
    usage: 'hardware security module interface (Cryptoki)',
    severity: 'info',
    confidence: 0.90,
    evidenceType: 'api-invocation',
  },
  {
    regex: /\bp11[\-_]?kit\b|\bp11[\-_]?proxy\b/gi,
    algorithm: 'PKCS#11',
    category: 'public-key',
    usage: 'PKCS#11 module loader/proxy',
    severity: 'info',
    confidence: 0.80,
    evidenceType: 'provider-config',
  },

  // ── SoftHSM (software HSM emulation) ──
  {
    regex: /softhsm|SoftHSM|SOFTHSM/g,
    algorithm: 'SoftHSM',
    category: 'public-key',
    usage: 'software HSM emulation (non-hardware)',
    severity: 'low',
    confidence: 0.82,
    evidenceType: 'provider-config',
  },
  {
    regex: /SOFTHSM2?_MODULE|SOFTHSM2?_PIN|softhsm2?-util/g,
    algorithm: 'SoftHSM',
    category: 'public-key',
    usage: 'SoftHSM configuration',
    severity: 'low',
    confidence: 0.90,
    evidenceType: 'provider-config',
  },

  // ── YubiHSM ──
  {
    regex: /yubihsm|YubiHSM|yubihsm2?-client/g,
    algorithm: 'YubiHSM',
    category: 'public-key',
    usage: 'Yubico hardware security module',
    severity: 'info',
    confidence: 0.88,
    evidenceType: 'library-import',
  },

  // ── TPM 2.0 ──
  {
    regex: /tpm2[\-_]?tss|tpm2[_\-]?tools|tpm2[_\-]?abrmd/g,
    algorithm: 'TPM 2.0',
    category: 'public-key',
    usage: 'TPM 2.0 software stack',
    severity: 'info',
    confidence: 0.88,
    evidenceType: 'library-import',
  },
  {
    regex: /\btpm2?_[a-z]+\b|tpm2\.[a-z]+|trousers|trousersd/gi,
    algorithm: 'TPM 2.0',
    category: 'public-key',
    usage: 'TPM library API call',
    severity: 'info',
    confidence: 0.85,
    evidenceType: 'api-invocation',
  },
  {
    regex: /\/dev\/tpm[02]?|tpmrm[02]/g,
    algorithm: 'TPM 2.0',
    category: 'public-key',
    usage: 'TPM device node reference',
    severity: 'info',
    confidence: 0.92,
    evidenceType: 'provider-config',
  },

  // ── Generic HSM Provider References ──
  {
    regex: /hsm[_\-]?provider|hsm[_\-]?slot|hsm[_\-]?pin|HSM_PROVIDER|HSM_SLOT/g,
    algorithm: 'HSM Provider',
    category: 'public-key',
    usage: 'hardware security module provider configuration',
    severity: 'info',
    confidence: 0.80,
    evidenceType: 'provider-config',
  },
  {
    regex: /CK_SLOT_ID|CK_SESSION_HANDLE|C_Initialize|C_OpenSession|C_Login/g,
    algorithm: 'PKCS#11',
    category: 'public-key',
    usage: 'PKCS#11 Cryptoki API call',
    severity: 'info',
    confidence: 0.95,
    evidenceType: 'api-invocation',
  },

  // ── HSM-related package dependencies ──
  {
    regex: /node-hardware-security-module|python-pkcs11|pykcs11|pkcs11js|pkcs11-lib/gi,
    algorithm: 'PKCS#11',
    category: 'public-key',
    usage: 'PKCS#11 library dependency',
    severity: 'info',
    confidence: 0.90,
    evidenceType: 'package-dependency',
  },

  // ── Common cloud HSM integrations ──
  {
    regex: /awskms|aws.*hsm|cloudhsm|azure.*hsm|azure.*dedicated.*hsm/gi,
    algorithm: 'Cloud HSM',
    category: 'public-key',
    usage: 'cloud hardware security module',
    severity: 'info',
    confidence: 0.78,
    evidenceType: 'provider-config',
  },
];

// ─── Comment Detection ──────────────────────────────────────

function isCommentOrDoc(content: string, matchIndex: number): boolean {
  const lineStart = content.lastIndexOf('\n', matchIndex);
  const line = content.slice(lineStart + 1, content.indexOf('\n', matchIndex + 1) || content.length).trim();
  if (/^(\/\/|#|\/\*|\*|<!--|--\[\[|--|;|%)/.test(line)) return true;
  // Check if match is inside a string that looks like documentation
  const before = content.slice(Math.max(0, matchIndex - 200), matchIndex);
  const quoteCount = (before.match(/"/g) || []).length;
  if (quoteCount % 2 === 1) {
    // Inside a string — check if it looks like a standalone string (documentation)
    const lastLineBreak = before.lastIndexOf('\n');
    const currentLine = before.slice(lastLineBreak + 1);
    // If the line is just a string literal, it's likely documentation
    if (/^\s*["']/.test(currentLine) && !/[:=,({]/.test(currentLine)) return true;
  }
  return false;
}

function isTestOrVendorPath(filePath: string): boolean {
  return /(?:test|tests|__tests__|spec|fixture|vendor|node_modules|__mocks__|\.test\.|\.spec\.)/.test(filePath.toLowerCase());
}

// ─── Main Detector ──────────────────────────────────────────

export function detectHardwareModules(
  filePath: string,
  content: string,
  repository: string,
  project: string,
): Finding[] {
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  for (const pattern of HARDWARE_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(content)) !== null) {
      const textBefore = content.slice(0, match.index);
      const lineNumber = textBefore.split('\n').length;

      // Skip duplicates at same position
      const posKey = `${filePath}:${lineNumber}:${pattern.algorithm}`;
      if (findings.some(f => `${f.file}:${f.line}:${f.algorithm}` === posKey)) continue;

      const detectedPattern = match[0].slice(0, 100);
      const inComment = isCommentOrDoc(content, match.index);
      const inTestPath = isTestOrVendorPath(filePath);

      // Confidence adjustment
      let confidence = pattern.confidence;
      const confidenceReasons: string[] = [`base ${pattern.confidence} from ${pattern.evidenceType}`];

      if (inComment) {
        confidence -= 0.35;
        confidenceReasons.push('-0.35 in comment/documentation');
      }
      if (inTestPath) {
        confidence -= 0.20;
        confidenceReasons.push('-0.20 in test/vendor path');
      }

      confidence = Math.max(0.1, Math.min(1, Math.round(confidence * 100) / 100));

      // Skip findings below threshold
      if (confidence < 0.50) continue;

      const riskBreakdown = computeRiskScore({
        quantumStatus: 'adequate', // HSMs are quantum-agnostic hardware
        baseSeverity: 'info',
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isHardcoded: false,
        service: 'Hardware Crypto Module',
      });

      const algorithmSeverity = deriveAlgorithmSeverity({
        algorithm: pattern.algorithm,
        quantumStatus: 'adequate',
        baseSeverity: pattern.severity,
        category: pattern.category,
      });

      const effective = deriveEffectiveSeverity({
        algorithmSeverity: algorithmSeverity.severity,
        quantumStatus: 'adequate',
        contextualRisk: riskBreakdown.totalScore,
      });

      findings.push({
        id: `hw-${Math.random().toString(36).substr(2, 9)}`,
        file: filePath,
        line: lineNumber,
        repository,
        project,
        service: 'Hardware Crypto Module',
        language: 'unknown',
        algorithm: pattern.algorithm,
        category: pattern.category,
        usage: pattern.usage,
        detectedPattern,
        confidence,
        quantumStatus: 'adequate', // Hardware modules are quantum-agnostic
        classicalStatus: 'strong',
        algorithmSeverity: algorithmSeverity.severity,
        severity: effective.severity,
        severityRationale: `${algorithmSeverity.rationale}. ${effective.rationale}`,
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isCryptoAgile: true, // HSMs support algorithm agility
        isHardcoded: false,
        contextSource: 'EXPLICIT',
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        remediationStatus: 'open',
        migrationPriority: 0,
        recommendedAlgorithm: 'Ensure HSM supports PQC algorithms (FIPS 203/204/205) for future migration',
        migrationStrategy: 'Verify HSM firmware supports PQC; plan firmware upgrade path if needed',
        tags: ['hardware', 'hsm', pattern.evidenceType],
        detectedAt: now,
        firstSeen: now,
        lastSeen: now,
        evidence: {
          detectionLayers: ['regex', 'hardware-detection'],
          matchedText: detectedPattern,
          confidenceDerivation: confidenceReasons.join('; ') + '.',
        },
      });
    }
  }

  return findings;
}
