// ============================================================
// Qrypto — Detector: Cloud KMS (AWS KMS, Azure KV, GCP KMS, Vault)
//
// Detects SDK/library/configuration references for cloud KMS
// services. Distinguishes:
//   - DEPENDENCY ONLY (package.json lists AWS SDK)
//   - ACTUAL API USAGE (code calls KMS operations)
//
// Confidence reflects this distinction.
// ============================================================

import type { Finding, AlgorithmCategory, Severity } from '../../types';
import { computeRiskScore } from '../riskEngine';
import { deriveAlgorithmSeverity, deriveEffectiveSeverity } from '../severity';

interface CloudKmsPattern {
  regex: RegExp;
  algorithm: string;
  category: AlgorithmCategory;
  usage: string;
  severity: Severity;
  confidence: number;
  /** Whether this pattern indicates actual API usage vs dependency only */
  evidenceType: 'api-usage' | 'sdk-import' | 'package-dependency' | 'config-reference';
  /** Cloud provider */
  provider: string;
}

// ─── Detection Patterns ─────────────────────────────────────

const CLOUD_KMS_PATTERNS: CloudKmsPattern[] = [
  // ── AWS KMS: API Usage (highest confidence) ──
  {
    regex: /kms\.(?:generate_data_key|encrypt|decrypt|create_key|schedule_key_deletion|revoke_grant|sign|verify|get_public_key)\s*\(/g,
    algorithm: 'AWS KMS',
    category: 'public-key',
    usage: 'AWS KMS API operation',
    severity: 'info',
    confidence: 0.95,
    evidenceType: 'api-usage',
    provider: 'AWS',
  },
  {
    regex: /AWSKMS|aws[_-]?kms|AWS\.KMS|@aws-sdk\/client-kms/g,
    algorithm: 'AWS KMS',
    category: 'public-key',
    usage: 'AWS KMS SDK client',
    severity: 'info',
    confidence: 0.90,
    evidenceType: 'sdk-import',
    provider: 'AWS',
  },
  // AWS KMS key ARN patterns
  {
    regex: /arn:aws:kms:[a-z0-9-]+:\d{12}:key\/[a-f0-9-]+/g,
    algorithm: 'AWS KMS',
    category: 'public-key',
    usage: 'AWS KMS key reference (ARN)',
    severity: 'medium',
    confidence: 0.95,
    evidenceType: 'config-reference',
    provider: 'AWS',
  },
  // AWS dependency-only patterns
  {
    regex: /@aws-sdk\/client-kms|boto3.*kms|aws-sdk.*kms/gi,
    algorithm: 'AWS KMS',
    category: 'public-key',
    usage: 'AWS KMS SDK dependency',
    severity: 'info',
    confidence: 0.75,
    evidenceType: 'package-dependency',
    provider: 'AWS',
  },

  // ── Azure Key Vault ──
  {
    regex: /KeyVaultClient|KeyVaultKeys|@azure\/keyvault-keys|DefaultAzureCredential.*keyvault/g,
    algorithm: 'Azure Key Vault',
    category: 'public-key',
    usage: 'Azure Key Vault SDK',
    severity: 'info',
    confidence: 0.90,
    evidenceType: 'sdk-import',
    provider: 'Azure',
  },
  {
    regex: /\.vault\.azure\.net|https:\/\/[a-z0-9-]+\.vault\.azure\.net/gi,
    algorithm: 'Azure Key Vault',
    category: 'public-key',
    usage: 'Azure Key Vault endpoint',
    severity: 'medium',
    confidence: 0.88,
    evidenceType: 'config-reference',
    provider: 'Azure',
  },
  {
    regex: /(?:createKey|encrypt|decrypt|sign|verify|wrapKey|unwrapKey)\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]RSA|EC|RSA-HSM|EC-HSM/g,
    algorithm: 'Azure Key Vault',
    category: 'public-key',
    usage: 'Azure Key Vault key operation',
    severity: 'info',
    confidence: 0.92,
    evidenceType: 'api-usage',
    provider: 'Azure',
  },
  // Azure dependency-only
  {
    regex: /@azure\/keyvault|azure-keyvault|azure.*keyvault/gi,
    algorithm: 'Azure Key Vault',
    category: 'public-key',
    usage: 'Azure Key Vault SDK dependency',
    severity: 'info',
    confidence: 0.72,
    evidenceType: 'package-dependency',
    provider: 'Azure',
  },

  // ── Google Cloud KMS ──
  {
    regex: /CloudKMS|cloudkms|@google-cloud\/kms|google\.cloud\.kms/g,
    algorithm: 'Google Cloud KMS',
    category: 'public-key',
    usage: 'Google Cloud KMS SDK',
    severity: 'info',
    confidence: 0.90,
    evidenceType: 'sdk-import',
    provider: 'GCP',
  },
  {
    regex: /projects\/[a-z0-9-]+\/locations\/[a-z0-9-]+\/keyRings\/[a-z0-9-]+\/cryptoKeys\/[a-z0-9-]+/g,
    algorithm: 'Google Cloud KMS',
    category: 'public-key',
    usage: 'Google Cloud KMS resource path',
    severity: 'medium',
    confidence: 0.92,
    evidenceType: 'config-reference',
    provider: 'GCP',
  },
  {
    regex: /encrypt\s*\(\s*\{?\s*name:\s*['"].*\/cryptoKeys\//g,
    algorithm: 'Google Cloud KMS',
    category: 'public-key',
    usage: 'Google Cloud KMS encrypt operation',
    severity: 'info',
    confidence: 0.93,
    evidenceType: 'api-usage',
    provider: 'GCP',
  },
  // GCP dependency-only
  {
    regex: /@google-cloud\/kms|google-cloud-kms/gi,
    algorithm: 'Google Cloud KMS',
    category: 'public-key',
    usage: 'Google Cloud KMS SDK dependency',
    severity: 'info',
    confidence: 0.72,
    evidenceType: 'package-dependency',
    provider: 'GCP',
  },

  // ── HashiCorp Vault (Transit secrets engine) ──
  {
    regex: /vault\.secrets\.transit\.|transit\/encrypt|transit\/decrypt|transit\/sign|transit\/verify/g,
    algorithm: 'HashiCorp Vault',
    category: 'public-key',
    usage: 'HashiCorp Vault Transit engine API',
    severity: 'info',
    confidence: 0.92,
    evidenceType: 'api-usage',
    provider: 'HashiCorp',
  },
  {
    regex: /vault\.Client|vault\.NewClient|hvac\.|import.*vault/g,
    algorithm: 'HashiCorp Vault',
    category: 'public-key',
    usage: 'HashiCorp Vault SDK',
    severity: 'info',
    confidence: 0.85,
    evidenceType: 'sdk-import',
    provider: 'HashiCorp',
  },
  {
    regex: /VAULT_ADDR|VAULT_TOKEN|vault[_-]?address|vault[_-]?token/g,
    algorithm: 'HashiCorp Vault',
    category: 'public-key',
    usage: 'HashiCorp Vault configuration',
    severity: 'medium',
    confidence: 0.80,
    evidenceType: 'config-reference',
    provider: 'HashiCorp',
  },
  // Vault dependency-only
  {
    regex: /hvac|node-vault|python-vault|vault-client/gi,
    algorithm: 'HashiCorp Vault',
    category: 'public-key',
    usage: 'HashiCorp Vault SDK dependency',
    severity: 'info',
    confidence: 0.70,
    evidenceType: 'package-dependency',
    provider: 'HashiCorp',
  },
];

// ─── Helpers ────────────────────────────────────────────────

function isCommentOrDoc(content: string, matchIndex: number): boolean {
  const lineStart = content.lastIndexOf('\n', matchIndex);
  const lineEnd = content.indexOf('\n', matchIndex + 1);
  const line = content.slice(lineStart + 1, lineEnd === -1 ? content.length : lineEnd).trim();
  if (/^(\/\/|#|\/\*|\*|<!--)/.test(line)) return true;
  const before = content.slice(Math.max(0, matchIndex - 200), matchIndex);
  const quoteCount = (before.match(/"/g) || []).length;
  if (quoteCount % 2 === 1) {
    const lastLineBreak = before.lastIndexOf('\n');
    const currentLine = before.slice(lastLineBreak + 1);
    if (/^\s*["']/.test(currentLine) && !/[:=,({]/.test(currentLine)) return true;
  }
  return false;
}

function isTestOrVendorPath(filePath: string): boolean {
  return /(?:test|tests|__tests__|spec|fixture|vendor|node_modules|__mocks__|\.test\.|\.spec\.)/.test(filePath.toLowerCase());
}

function inferService(filePath: string): string {
  const lower = filePath.toLowerCase();
  if (lower.includes('payment') || lower.includes('billing')) return 'Payment Service';
  if (lower.includes('auth') || lower.includes('login')) return 'Authentication Service';
  if (lower.includes('api') || lower.includes('gateway')) return 'API Gateway';
  if (lower.includes('secret') || lower.includes('vault') || lower.includes('credential')) return 'Secrets Management';
  return 'Cloud Services';
}

// ─── Main Detector ──────────────────────────────────────────

export function detectCloudKms(
  filePath: string,
  content: string,
  repository: string,
  project: string,
): Finding[] {
  const findings: Finding[] = [];
  const now = new Date().toISOString();
  const service = inferService(filePath);

  for (const pattern of CLOUD_KMS_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(content)) !== null) {
      const textBefore = content.slice(0, match.index);
      const lineNumber = textBefore.split('\n').length;

      const posKey = `${filePath}:${lineNumber}:${pattern.algorithm}`;
      if (findings.some(f => `${f.file}:${f.line}:${f.algorithm}` === posKey)) continue;

      const detectedPattern = match[0].slice(0, 100);
      const inComment = isCommentOrDoc(content, match.index);
      const inTestPath = isTestOrVendorPath(filePath);

      let confidence = pattern.confidence;
      const confidenceReasons: string[] = [
        `base ${pattern.confidence} from ${pattern.evidenceType}`,
      ];

      if (inComment) {
        confidence -= 0.35;
        confidenceReasons.push('-0.35 in comment/documentation');
      }
      if (inTestPath) {
        confidence -= 0.20;
        confidenceReasons.push('-0.20 in test/vendor path');
      }

      confidence = Math.max(0.1, Math.min(1, Math.round(confidence * 100) / 100));
      if (confidence < 0.50) continue;

      // Severity depends on evidence type
      const severity: Severity =
        pattern.evidenceType === 'api-usage' ? 'info' :
        pattern.evidenceType === 'config-reference' && detectedPattern.includes('arn:') ? 'medium' :
        pattern.severity;

      const riskBreakdown = computeRiskScore({
        quantumStatus: 'adequate',
        baseSeverity: severity,
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isHardcoded: false,
        service,
      });

      const algorithmSeverity = deriveAlgorithmSeverity({
        algorithm: pattern.algorithm,
        quantumStatus: 'adequate',
        baseSeverity: severity,
        category: pattern.category,
      });

      const effective = deriveEffectiveSeverity({
        algorithmSeverity: algorithmSeverity.severity,
        quantumStatus: 'adequate',
        contextualRisk: riskBreakdown.totalScore,
      });

      findings.push({
        id: `kms-${Math.random().toString(36).substr(2, 9)}`,
        file: filePath,
        line: lineNumber,
        repository,
        project,
        service,
        language: 'unknown',
        algorithm: pattern.algorithm,
        category: pattern.category,
        usage: pattern.usage,
        detectedPattern,
        confidence,
        quantumStatus: 'adequate',
        classicalStatus: 'strong',
        algorithmSeverity: algorithmSeverity.severity,
        severity: effective.severity,
        severityRationale: `${algorithmSeverity.rationale}. ${effective.rationale}`,
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isCryptoAgile: true,
        isHardcoded: false,
        contextSource: 'EXPLICIT',
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        remediationStatus: 'open',
        migrationPriority: 0,
        recommendedAlgorithm: pattern.evidenceType === 'package-dependency'
          ? 'Verify actual KMS usage; dependency alone does not guarantee active use'
          : `Ensure ${pattern.provider} KMS supports PQC algorithms for migration readiness`,
        migrationStrategy: pattern.evidenceType === 'package-dependency'
          ? 'Review codebase for actual KMS API calls before classifying as active asset'
          : `Verify ${pattern.provider} KMS PQC support; plan migration when PQC algorithms are GA`,
        tags: ['cloud', 'kms', pattern.provider.toLowerCase(), pattern.evidenceType],
        detectedAt: now,
        firstSeen: now,
        lastSeen: now,
        evidence: {
          detectionLayers: ['regex', 'cloud-kms-detection'],
          matchedText: detectedPattern,
          confidenceDerivation: confidenceReasons.join('; ') + '.',
        },
      });
    }
  }

  return findings;
}
