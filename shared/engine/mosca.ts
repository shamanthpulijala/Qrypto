// ============================================================
// Qrypto — Mosca Engine
//
// Implements the Harvest-Now-Decrypt-Later (HNDL) risk model
// based on Mosca's theorem:
//
//   X = data lifetime (confidentiality requirement in years)
//   Y = migration time (estimated time to migrate to PQC)
//   Z = threat horizon (configurable year when CRQC expected)
//
//   If X + Y > Z, the data is at risk — it will still be
//   protected by quantum-vulnerable cryptography when CRQCs
//   arrive.
//
// The threat horizon is ALWAYS presented as an assumption,
// never as a fact. The user controls it.
//
// Reference: Mosca's theorem (2008), updated for NIST PQC timeline.
// ============================================================

import type { Finding } from '../types';

// ─── Types ────────────────────────────────────────────────────

export interface MoscaAssessment {
  /** Configurable threat horizon year (default: 2030). */
  threatHorizonYear: number;
  /** Human-readable statement of the assumption. */
  horizonAssumption: string;
  /** Per-finding Mosca analysis. */
  findings: MoscaFindingResult[];
  /** Summary statistics. */
  summary: MoscaSummary;
}

export interface MoscaFindingResult {
  findingId: string;
  algorithm: string;
  service: string;
  file: string;
  line: number;
  /** Data lifetime requirement (X) in years. */
  dataLifetimeYears: number;
  /** Estimated migration time (Y) in years. */
  migrationTimeYears: number;
  /** Threat horizon (Z) in years from now. */
  threatHorizonYears: number;
  /** Whether X + Y > Z. */
  atRisk: boolean;
  /** The margin: Z - (X + Y). Negative means at risk. */
  marginYears: number;
  /** Step-by-step derivation for explainability. */
  derivation: MoscaDerivation;
  /** Overall Mosca risk level. */
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe';
}

export interface MoscaDerivation {
  /** Step-by-step explanation. */
  steps: string[];
  /** Final equation rendered as text. */
  equation: string;
  /** Human-readable conclusion. */
  conclusion: string;
}

export interface MoscaSummary {
  /** Total findings analysed. */
  totalFindings: number;
  /** How many are at risk (X + Y > Z). */
  atRiskCount: number;
  /** How many are safe. */
  safeCount: number;
  /** Risk distribution. */
  riskDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    safe: number;
  };
  /** The most urgent finding. */
  mostUrgent: MoscaFindingResult | null;
}

// ─── Migration Time Estimation ────────────────────────────────
// Estimated time to migrate from the current algorithm to its
// PQC replacement. Based on algorithm complexity, not invented.

function estimateMigrationTimeYears(finding: Finding): number {
  const algo = finding.algorithm.toUpperCase();

  // Hardcoded secrets: immediate rotation, days → ~0.02 years
  if (finding.category === 'secret') return 0.02;

  // TLS/config changes: weeks → ~0.04 years
  if (finding.category === 'tls') return 0.04;

  // Hash function replacement: typically straightforward
  if (finding.category === 'hash') return 0.08; // ~1 month

  // Symmetric cipher: usually configuration change
  if (finding.category === 'symmetric') return 0.08;

  // PQC algorithms: already migrated
  if (finding.quantumStatus === 'quantum-resistant') return 0;

  // RSA key establishment → ML-KEM: significant effort (hybrid deployment)
  if (algo.includes('RSA') || algo.includes('DH')) {
    return finding.usage.toLowerCase().includes('key') ? 0.5 : 0.75;
  }

  // ECC/ECDH → ML-KEM hybrid
  if (algo.includes('ECDH') || algo.includes('ECC')) return 0.5;

  // ECDSA/DSA → ML-DSA: certificate chain reissuance needed
  if (algo.includes('ECDSA') || algo.includes('DSA')) return 0.75;

  // Default: moderate migration effort
  return 0.5;
}

// ─── Mosca Risk Level ─────────────────────────────────────────

function moscaRiskLevel(
  atRisk: boolean,
  marginYears: number,
  dataLifetimeYears: number,
): MoscaFindingResult['riskLevel'] {
  if (!atRisk) return 'safe';
  if (marginYears < -5) return 'critical';
  if (marginYears < -2) return 'high';
  if (marginYears < 0) return 'medium';
  return 'low';
}

// ─── Main Assessment ──────────────────────────────────────────

export interface MoscaOptions {
  /** Threat horizon year. Default: 2030. */
  threatHorizonYear?: number;
}

/**
 * Run the Mosca assessment on scan findings.
 *
 * The threat horizon is ALWAYS configurable and ALWAYS presented
 * as an assumption. This is not a prediction — it is a parameter
 * the user controls.
 */
export function runMoscaAssessment(
  findings: Finding[],
  options: MoscaOptions = {},
): MoscaAssessment {
  const now = new Date();
  const currentYear = now.getFullYear();
  const threatHorizonYear = options.threatHorizonYear ?? 2030;
  const threatHorizonYears = Math.max(0, threatHorizonYear - currentYear);

  // Only assess findings that are quantum-vulnerable or classically weak
  const assessableFindings = findings.filter(
    f => f.quantumStatus === 'vulnerable' || f.quantumStatus === 'classical-weak'
  );

  const results: MoscaFindingResult[] = [];

  for (const f of assessableFindings) {
    const dataLifetimeYears = f.dataLifetimeYears || 5;
    const migrationTimeYears = estimateMigrationTimeYears(f);
    const totalProtectionNeeded = dataLifetimeYears + migrationTimeYears;
    const atRisk = totalProtectionNeeded > threatHorizonYears;
    const marginYears = threatHorizonYears - totalProtectionNeeded;

    const derivation: MoscaDerivation = {
      steps: [
        `Data lifetime requirement (X): ${dataLifetimeYears} years`,
        `Estimated migration time (Y): ${migrationTimeYears.toFixed(2)} years`,
        `Threat horizon (Z): ${threatHorizonYears} years (${threatHorizonYear})`,
        `Protection needed: X + Y = ${dataLifetimeYears} + ${migrationTimeYears.toFixed(2)} = ${totalProtectionNeeded.toFixed(2)} years`,
        `Margin: Z - (X + Y) = ${threatHorizonYears} - ${totalProtectionNeeded.toFixed(2)} = ${marginYears.toFixed(2)} years`,
      ],
      equation: `${dataLifetimeYears} + ${migrationTimeYears.toFixed(2)} = ${totalProtectionNeeded.toFixed(2)} vs ${threatHorizonYears}`,
      conclusion: atRisk
        ? `AT RISK: Data protected by ${f.algorithm} requires ${totalProtectionNeeded.toFixed(1)} years of confidentiality, but the threat horizon is only ${threatHorizonYears} years. Data intercepted today may be decryptable before migration is complete.`
        : `SAFE: ${f.algorithm} migration can be completed within the ${threatHorizonYear} threat horizon with ${marginYears.toFixed(1)} years of margin.`,
    };

    results.push({
      findingId: f.id,
      algorithm: f.algorithm,
      service: f.service,
      file: f.file,
      line: f.line,
      dataLifetimeYears,
      migrationTimeYears,
      threatHorizonYears,
      atRisk,
      marginYears,
      derivation,
      riskLevel: moscaRiskLevel(atRisk, marginYears, dataLifetimeYears),
    });
  }

  // Sort by risk (worst first)
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, safe: 4 };
  results.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

  // Summary
  const atRiskCount = results.filter(r => r.atRisk).length;
  const summary: MoscaSummary = {
    totalFindings: results.length,
    atRiskCount,
    safeCount: results.length - atRiskCount,
    riskDistribution: {
      critical: results.filter(r => r.riskLevel === 'critical').length,
      high: results.filter(r => r.riskLevel === 'high').length,
      medium: results.filter(r => r.riskLevel === 'medium').length,
      low: results.filter(r => r.riskLevel === 'low').length,
      safe: results.filter(r => r.riskLevel === 'safe').length,
    },
    mostUrgent: results.find(r => r.riskLevel === 'critical' || r.riskLevel === 'high') ?? null,
  };

  return {
    threatHorizonYear,
    horizonAssumption: `This assessment assumes a cryptographically relevant quantum computer may exist by ${threatHorizonYear}. This is a configurable assumption, not a prediction. Adjust the horizon based on your organization's risk tolerance and current threat intelligence.`,
    findings: results,
    summary,
  };
}
