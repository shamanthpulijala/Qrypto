// ============================================================
// QuantumGuard AI — Quantum Risk Engine
// Transparent, deterministic risk scoring formula
// ============================================================

import type { QuantumStatus, Severity, RiskBreakdown, RiskWeights } from '../types';
import { DEFAULT_RISK_WEIGHTS } from '../types';

export interface RiskInput {
  quantumStatus: QuantumStatus;
  baseSeverity: Severity;
  internetFacing: boolean;
  dataSensitivity: 'critical' | 'high' | 'medium' | 'low';
  dataLifetimeYears: number;
  isHardcoded: boolean;
  service: string;
  keySize?: number;
  weights?: RiskWeights;
  /** P0-12: Override business criticality (0-100) instead of using service name lookup */
  businessCriticalityOverride?: number;
}

// ─── Component Scorers ─────────────────────────────────────────

/** Algorithm intrinsic quantum risk: 0–100 */
function algorithmRiskScore(quantumStatus: QuantumStatus, baseSeverity: Severity, keySize?: number): number {
  let base = 0;
  switch (quantumStatus) {
    case 'vulnerable':        base = 85; break; // RSA, ECC, ECDH, DSA
    case 'classical-weak':    base = 70; break; // MD5, SHA-1, DES, weak TLS
    case 'adequate':          base = 20; break; // AES-256, SHA-256
    case 'quantum-resistant': base = 5;  break; // PQC
    case 'unknown':           base = 60; break; // secrets, unknowns
  }

  // Severity adjustments
  if (baseSeverity === 'critical') base = Math.min(100, base + 15);
  if (baseSeverity === 'low')     base = Math.max(0, base - 10);

  // RSA key size penalties: smaller key = worse
  if (quantumStatus === 'vulnerable' && keySize) {
    if (keySize <= 1024) base = Math.min(100, base + 10);
    if (keySize >= 4096) base = Math.max(0, base - 5);
  }

  return Math.round(base);
}

/** Business criticality: 0–100 based on inferred service role */
function businessCriticalityScore(service: string, dataSensitivity: 'critical' | 'high' | 'medium' | 'low'): number {
  // Generic service criticality mapping — no demo-company-specific names.
  // Scores reflect the *type* of service, not a particular vendor's product.
  const serviceScores: Record<string, number> = {
    'Payment Service': 100,
    'Authentication Service': 95,
    'Transaction Service': 90,
    'API Gateway': 80,
    'Data Layer': 85,
    'User Service': 75,
    'PKI/TLS Layer': 85,
    'Crypto Library': 70,
    'Core Services': 65,
    'Configuration': 60,
    'Test Suite': 10,
    'Web Server': 75,
    'App': 60,
  };
  const serviceScore = serviceScores[service] ?? 60;
  const sensitivityMultiplier = { critical: 1.0, high: 0.85, medium: 0.70, low: 0.50 };
  return Math.round(serviceScore * (sensitivityMultiplier[dataSensitivity] ?? 0.70));
}


/** Internet exposure factor: 0–100 */
function internetExposureScore(internetFacing: boolean, service: string): number {
  if (!internetFacing) {
    // Internal services still have some exposure through lateral movement
    return service === 'Data Layer' ? 40 : 20;
  }
  return 100;
}

/** Harvest-now-decrypt-later data lifetime risk: 0–100 */
function dataLifetimeScore(years: number): number {
  if (years <= 1)  return 10;
  if (years <= 5)  return 30;
  if (years <= 10) return 60;
  if (years <= 25) return 85;
  return 100; // 25+ years
}

/** Data sensitivity: 0–100 */
function dataSensitivityScore(sensitivity: 'critical' | 'high' | 'medium' | 'low'): number {
  return { critical: 100, high: 75, medium: 50, low: 25 }[sensitivity];
}

/** Migration difficulty: 0–100 (higher = harder to fix) */
function migrationDifficultyScore(
  quantumStatus: QuantumStatus,
  isHardcoded: boolean,
  service: string
): number {
  let base = 0;
  switch (quantumStatus) {
    case 'vulnerable':        base = 70; break; // full PQC migration is complex
    case 'classical-weak':    base = 30; break; // mostly algorithm swap
    case 'adequate':          base = 10; break;
    case 'quantum-resistant': base = 5;  break;
    case 'unknown':           base = 50; break;
  }
  if (isHardcoded) base = Math.min(100, base + 20); // hardcoded = harder to change
  if (service === 'Payment Service') base = Math.min(100, base + 15); // compliance constraints
  if (service === 'PKI/TLS Layer') base = Math.min(100, base + 10);
  return Math.round(base);
}

// ─── Main Score Computation ───────────────────────────────────

export function computeRiskScore(input: RiskInput): RiskBreakdown {
  const weights = input.weights ?? DEFAULT_RISK_WEIGHTS;

  const algorithmRisk = algorithmRiskScore(input.quantumStatus, input.baseSeverity, input.keySize);
  const businessCriticality = input.businessCriticalityOverride ?? businessCriticalityScore(input.service, input.dataSensitivity);
  const internetExposure = internetExposureScore(input.internetFacing, input.service);
  const dataLifetime = dataLifetimeScore(input.dataLifetimeYears);
  const dataSensitivity = dataSensitivityScore(input.dataSensitivity);
  const migrationDifficulty = migrationDifficultyScore(input.quantumStatus, input.isHardcoded, input.service);

  const totalScore = Math.round(
    algorithmRisk       * weights.algorithmRisk +
    businessCriticality * weights.businessCriticality +
    internetExposure    * weights.internetExposure +
    dataLifetime        * weights.dataLifetime +
    dataSensitivity     * weights.dataSensitivity +
    migrationDifficulty * weights.migrationDifficulty
  );

  return {
    algorithmRisk,
    businessCriticality,
    internetExposure,
    dataLifetime,
    dataSensitivity,
    migrationDifficulty,
    totalScore: Math.min(100, Math.max(0, totalScore)),
  };
}

// ─── Severity & Score Color Helpers ───────────────────────────

/** Risk score color (higher risk = red) */
export function scoreToSeverity(score: number): string {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Moderate';
  if (score >= 20) return 'Low';
  return 'Minimal';
}

export function scoreToColor(score: number): string {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f97316';
  if (score >= 40) return '#eab308';
  if (score >= 20) return '#22c55e';
  return '#94a3b8';
}

/** Readiness & Agility score color (higher score = green/good!) */
export function readinessScoreToColor(score: number): string {
  if (score >= 80) return '#22c55e'; // Green (Excellent / Agile)
  if (score >= 60) return '#14b8a6'; // Cyan/Teal (Good)
  if (score >= 40) return '#eab308'; // Yellow (Moderate)
  if (score >= 20) return '#f97316'; // Orange (Low)
  return '#ef4444';                   // Red (Poor / Rigid)
}

// ─── Quantum Readiness Index ─────────────────────────────────

import type { Finding } from '../types';

export function computeQuantumReadinessIndex(findings: Finding[]): {
  overall: number;
  cryptographicInventory: number;
  legacyCrypto: number;
  pqcMigration: number;
  cryptoAgility: number;
  secretManagement: number;
  tlsPosture: number;
  certificatePosture: number;
} {
  if (findings.length === 0) {
    return { overall: 0, cryptographicInventory: 0, legacyCrypto: 0, pqcMigration: 0, cryptoAgility: 0, secretManagement: 0, tlsPosture: 0, certificatePosture: 0 };
  }

  const total = findings.length;

  // Inventory completeness (all findings have full context)
  const inventoryComplete = findings.filter(f => f.service && f.language !== 'unknown' && f.confidence > 0.7).length;
  const cryptographicInventory = Math.round((inventoryComplete / total) * 100);

  // Legacy crypto: penalize for classical-weak
  const classicWeak = findings.filter(f => f.quantumStatus === 'classical-weak').length;
  const legacyCrypto = Math.round(Math.max(0, 100 - (classicWeak / total) * 300));

  // PQC migration: how many findings are already remediated or using PQC
  const remediated = findings.filter(f => f.remediationStatus === 'remediated' || f.quantumStatus === 'quantum-resistant').length;
  const pqcMigration = Math.round((remediated / total) * 100);

  // Crypto agility: penalize hard-coded findings
  const hardcoded = findings.filter(f => f.isHardcoded && f.category !== 'secret').length;
  const cryptoAgility = Math.round(Math.max(0, 100 - (hardcoded / total) * 200));

  // Secret management: penalize hardcoded secrets
  const secrets = findings.filter(f => f.category === 'secret').length;
  const secretManagement = Math.round(Math.max(0, 100 - (secrets / Math.max(total, 1)) * 400));

  // TLS posture: penalize weak TLS
  const weakTls = findings.filter(f => f.category === 'tls' && (f.quantumStatus === 'classical-weak')).length;
  const goodTls = findings.filter(f => f.category === 'tls' && f.quantumStatus === 'adequate').length;
  const tlsTotal = weakTls + goodTls;
  const tlsPosture = tlsTotal === 0 ? 75 : Math.round((goodTls / tlsTotal) * 100);

  // Certificate posture
  const vulnCerts = findings.filter(f => (f.category === 'certificate' || f.algorithm.includes('SHA1withRSA')) && f.quantumStatus !== 'adequate').length;
  const certificatePosture = Math.round(Math.max(0, 100 - vulnCerts * 15));

  const overall = Math.round(
    cryptographicInventory * 0.15 +
    legacyCrypto           * 0.20 +
    pqcMigration           * 0.25 +
    cryptoAgility          * 0.15 +
    secretManagement       * 0.10 +
    tlsPosture             * 0.08 +
    certificatePosture     * 0.07
  );

  return {
    overall: Math.min(100, Math.max(0, overall)),
    cryptographicInventory,
    legacyCrypto,
    pqcMigration,
    cryptoAgility,
    secretManagement,
    tlsPosture,
    certificatePosture,
  };
}
