// ============================================================
// Qrypto — Detector: Dockerfile / Container Configuration
//
// Detects crypto-related packages, configurations, and base images
// in Dockerfiles and compose files.
//
// SAFETY: Never executes images or builds containers.
// Static text analysis only.
//
// Evidence model:
//   OBSERVED: "OpenSSL package appears in Dockerfile"
//   INFERRED: "This may carry legacy crypto dependencies"
//
// Clearly labels confidence/context for each finding.
// ============================================================

import type { Finding, Severity } from '../../types';
import { computeRiskScore } from '../riskEngine';
import { deriveAlgorithmSeverity, deriveEffectiveSeverity } from '../severity';

interface ContainerPattern {
  regex: RegExp;
  algorithm: string;
  usage: string;
  severity: Severity;
  confidence: number;
  evidenceType: 'package-install' | 'base-image' | 'config-directive' | 'compose-reference' | 'multi-stage';
  /** Specific crypto concern if any */
  cryptoConcern?: string;
}

// ─── Dockerfile Patterns ────────────────────────────────────

const DOCKERFILE_PATTERNS: ContainerPattern[] = [
  // ── Base images with known crypto stacks ──
  {
    regex: /^FROM\s+(.*?:([\w.\-]+))/gmi,
    algorithm: 'Docker Base Image',
    usage: 'container base image',
    severity: 'info',
    confidence: 0.70,
    evidenceType: 'base-image',
  },

  // ── OpenSSL / libssl installations ──
  {
    regex: /(?:apt-get|apt|apk|yum|dnf|zypper)\s+(?:install|add)\s+(?:-[a-z]*\s+)*(?:.*?(?:openssl|libssl|libssl-dev|libssl3|openssl-devel)[^\n]*)/gi,
    algorithm: 'OpenSSL',
    usage: 'OpenSSL package installation in container',
    severity: 'low',
    confidence: 0.85,
    evidenceType: 'package-install',
    cryptoConcern: 'May include deprecated cipher support',
  },
  {
    regex: /(?:pip|pip3|npm|yarn|go\s+get|go\s+install)\s+(?:.*?(?:pyOpenSSL|openssl|crypto)[^\n]*)/gi,
    algorithm: 'OpenSSL',
    usage: 'Crypto package installation in container build',
    severity: 'info',
    confidence: 0.80,
    evidenceType: 'package-install',
    cryptoConcern: 'Verify OpenSSL version for known vulnerabilities',
  },

  // ── Java crypto stacks ──
  {
    regex: /(?:openjdk|java|jdk|jre|java-1[.\d]+-openjdk)/gi,
    algorithm: 'Java Crypto Stack',
    usage: 'Java runtime installation in container',
    severity: 'info',
    confidence: 0.75,
    evidenceType: 'package-install',
    cryptoConcern: 'Java includes JCE crypto provider; verify supported algorithms',
  },

  // ── GnuTLS ──
  {
    regex: /(?:apt-get|apt|apk|yum)\s+(?:install|add)\s+(?:.*?(?:gnutls|libgnutls)[^\n]*)/gi,
    algorithm: 'GnuTLS',
    usage: 'GnuTLS library installation in container',
    severity: 'info',
    confidence: 0.82,
    evidenceType: 'package-install',
    cryptoConcern: 'GnuTLS may support deprecated algorithms',
  },

  // ── NSS (Network Security Services) ──
  {
    regex: /(?:apt-get|apt|apk|yum)\s+(?:install|add)\s+(?:.*?(?:nss|libnss|nss-util)[^\n]*)/gi,
    algorithm: 'NSS',
    usage: 'Network Security Services installation in container',
    severity: 'info',
    confidence: 0.80,
    evidenceType: 'package-install',
    cryptoConcern: 'NSS provides TLS implementation; verify supported cipher suites',
  },

  // ── Crypto-specific packages ──
  {
    regex: /(?:apt-get|apt|apk|yum)\s+(?:install|add)\s+(?:.*?(?:libgcrypt|libssh|libsodium|nettle)[^\n]*)/gi,
    algorithm: 'Crypto Library',
    usage: 'Cryptographic library installation in container',
    severity: 'info',
    confidence: 0.82,
    evidenceType: 'package-install',
    cryptoConcern: 'Cryptographic library installed; verify version and configuration',
  },

  // ── Weak/outdated base image tags ──
  {
    regex: /^FROM\s+\S+:(?:latest|trusty|xenial|bionic|centos[67]|alpine[23]\.\d|jdk-8|jdk-11)\s*$/gmi,
    algorithm: 'Legacy Base Image',
    usage: 'potentially outdated base image tag',
    severity: 'medium',
    confidence: 0.65,
    evidenceType: 'base-image',
    cryptoConcern: 'Outdated base image may include deprecated crypto libraries',
  },

  // ── COPY/ADD of crypto config files ──
  {
    regex: /(?:COPY|ADD)\s+(?:.*?(?:\.pem|\.key|\.crt|\.p12|\.pfx|\.jks|\.keystore|\.truststore)[^\n]*)/gi,
    algorithm: 'Certificate Material',
    usage: 'cryptographic certificate/key material in container',
    severity: 'medium',
    confidence: 0.88,
    evidenceType: 'config-directive',
    cryptoConcern: 'Private key or certificate material in container image',
  },

  // ── TLS configuration in container ──
  {
    regex: /(?:ENV|ARG)\s+(?:.*?(?:SSL|TLS|HTTPS|CERT|KEY)[A-Z_]*\s*=)/gi,
    algorithm: 'TLS Configuration',
    usage: 'TLS/crypto environment variable in container',
    severity: 'info',
    confidence: 0.75,
    evidenceType: 'config-directive',
    cryptoConcern: 'TLS configuration variable detected; verify settings',
  },
];

// ─── Docker Compose Patterns ────────────────────────────────

const COMPOSE_PATTERNS: ContainerPattern[] = [
  // ── Volumes exposing crypto material ──
  {
    regex: /(?:volumes|volume)[\s\S]*?(?:\.pem|\.key|\.crt|\.p12|keystore|truststore)/gi,
    algorithm: 'Certificate Volume Mount',
    usage: 'crypto material mounted into container',
    severity: 'medium',
    confidence: 0.82,
    evidenceType: 'compose-reference',
    cryptoConcern: 'Certificate/key files mounted as Docker volumes',
  },

  // ── Environment variables with secrets ──
  {
    regex: /(?:environment|env_file)[\s\S]*?(?:KEY|SECRET|PASSWORD|TOKEN|CERT)[A-Z_]*(?:\s*[=:])/gi,
    algorithm: 'Secret in Compose',
    usage: 'secret/credential reference in compose file',
    severity: 'low',
    confidence: 0.60,
    evidenceType: 'compose-reference',
    cryptoConcern: 'Secret material referenced in compose configuration',
  },
];

// ─── File Detection ─────────────────────────────────────────

function isDockerfile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.endsWith('dockerfile') ||
    lower.match(/dockerfile\.\w+$/) !== null ||
    lower.endsWith('.dockerfile');
}

function isComposeFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.endsWith('docker-compose.yml') ||
    lower.endsWith('docker-compose.yaml') ||
    lower.endsWith('compose.yml') ||
    lower.endsWith('compose.yaml');
}

function isComment(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith('#');
}

// ─── Main Detector ──────────────────────────────────────────

export function detectContainerConfig(
  filePath: string,
  content: string,
  repository: string,
  project: string,
): Finding[] {
  const findings: Finding[] = [];

  const isDocker = isDockerfile(filePath);
  const isCompose = isComposeFile(filePath);

  if (!isDocker && !isCompose) return findings;

  const now = new Date().toISOString();
  const patterns = isDocker ? DOCKERFILE_PATTERNS : COMPOSE_PATTERNS;
  const lines = content.split('\n');

  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(content)) !== null) {
      const textBefore = content.slice(0, match.index);
      const lineNumber = textBefore.split('\n').length;

      // Check if this line is a comment
      const currentLine = lines[lineNumber - 1] || '';
      if (isComment(currentLine)) {
        continue; // Skip commented-out directives
      }

      // For Dockerfiles, skip lines in multi-stage build arguments
      if (isDocker && /^(?:ARG|ENV)\s/.test(currentLine.trim())) {
        // ARG/ENV with crypto are still worth noting
      }

      const posKey = `${filePath}:${lineNumber}:${pattern.algorithm}`;
      if (findings.some(f => `${f.file}:${f.line}:${f.algorithm}` === posKey)) continue;

      const detectedPattern = match[0].slice(0, 150);
      const inTestPath = /(?:test|tests|fixture|example|sample)/i.test(filePath);

      let confidence = pattern.confidence;
      const reasons: string[] = [`base ${pattern.confidence} from ${pattern.evidenceType}`];

      if (inTestPath) {
        confidence -= 0.15;
        reasons.push('-0.15 in test/example path');
      }

      confidence = Math.max(0.3, Math.min(1, Math.round(confidence * 100) / 100));

      const riskBreakdown = computeRiskScore({
        quantumStatus: 'adequate',
        baseSeverity: pattern.severity,
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isHardcoded: false,
        service: 'Container Infrastructure',
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

      // Build evidence with OBSERVED vs INFERRED distinction
      const evidenceText = pattern.cryptoConcern
        ? `OBSERVED: ${detectedPattern}. INFERENCE: ${pattern.cryptoConcern}`
        : `OBSERVED: ${detectedPattern}`;

      findings.push({
        id: `ctr-${Math.random().toString(36).substr(2, 9)}`,
        file: filePath,
        line: lineNumber,
        repository,
        project,
        service: 'Container Infrastructure',
        language: 'unknown',
        algorithm: pattern.algorithm,
        category: 'public-key',
        usage: pattern.usage,
        detectedPattern: evidenceText.slice(0, 100),
        confidence,
        quantumStatus: 'adequate',
        classicalStatus: 'adequate',
        algorithmSeverity: algorithmSeverity.severity,
        severity: effective.severity,
        severityRationale: `${algorithmSeverity.rationale}. ${effective.rationale}`,
        internetFacing: false,
        dataSensitivity: 'medium',
        dataLifetimeYears: 5,
        isCryptoAgile: false,
        isHardcoded: false,
        contextSource: 'EXPLICIT',
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        remediationStatus: 'open',
        migrationPriority: 0,
        recommendedAlgorithm: 'Review container image for supported crypto algorithms and plan updates',
        migrationStrategy: 'Audit container base image; update to latest stable version with PQC support',
        tags: ['container', 'docker', isDocker ? 'dockerfile' : 'compose', pattern.evidenceType],
        detectedAt: now,
        firstSeen: now,
        lastSeen: now,
        evidence: {
          detectionLayers: ['regex', 'container-detection'],
          matchedText: detectedPattern,
          confidenceDerivation: reasons.join('; ') + '.',
        },
      });
    }
  }

  return findings;
}
