// ============================================================
// QuantumGuard AI — §35 Risk Engine Tests
//
// Tests for:
//   - Deterministic score computation
//   - Severity mapping
//   - Edge cases (min/max, clipping)
// ============================================================

import { describe, it, expect } from 'vitest';
import { computeRiskScore, scoreToSeverity, scoreToColor, computeQuantumReadinessIndex } from '../engine/riskEngine';
import type { RiskInput } from '../engine/riskEngine';
import type { Finding } from '../types';

// ─── Helper ───────────────────────────────────────────────────

function makeRiskInput(overrides: Partial<RiskInput> = {}): RiskInput {
  return {
    quantumStatus: 'vulnerable',
    baseSeverity: 'high',
    internetFacing: true,
    dataSensitivity: 'critical',
    dataLifetimeYears: 10,
    isHardcoded: false,
    service: 'Payment Service',
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'QG-0001',
    file: 'test.ts',
    line: 1,
    repository: 'test',
    project: 'test',
    service: 'Core Services',
    language: 'typescript',
    algorithm: 'RSA-2048',
    category: 'asymmetric',
    usage: 'key-exchange',
    detectedPattern: 'RSA',
    confidence: 0.9,
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    severity: 'high',
    internetFacing: false,
    dataSensitivity: 'medium',
    dataLifetimeYears: 5,
    isCryptoAgile: false,
    isHardcoded: false,
    riskScore: 60,
    riskBreakdown: {
      algorithmRisk: 85,
      businessCriticality: 65,
      internetExposure: 20,
      dataLifetime: 30,
      dataSensitivity: 50,
      migrationDifficulty: 70,
      totalScore: 60,
    },
    remediationStatus: 'open',
    migrationPriority: 1,
    recommendedAlgorithm: 'ML-KEM',
    migrationStrategy: 'Phased migration',
    tags: ['asymmetric', 'quantum-vulnerable'],
    detectedAt: new Date().toISOString(),
    ...overrides,
  };
}

// ─── Deterministic Score Tests ─────────────────────────────────

describe('Risk Engine — Deterministic Score Computation', () => {
  it('produces a consistent score for identical inputs', () => {
    const input = makeRiskInput();
    const result1 = computeRiskScore(input);
    const result2 = computeRiskScore(input);
    expect(result1.totalScore).toBe(result2.totalScore);
  });

  it('assigns higher score to internet-facing vulnerable service vs internal', () => {
    const internetFacing = makeRiskInput({ internetFacing: true });
    const internal = makeRiskInput({ internetFacing: false });
    const scoreInternet = computeRiskScore(internetFacing).totalScore;
    const scoreInternal = computeRiskScore(internal).totalScore;
    expect(scoreInternet).toBeGreaterThan(scoreInternal);
  });

  it('assigns higher score to Payment Service vs Test Suite', () => {
    const payment = makeRiskInput({ service: 'Payment Service' });
    const test = makeRiskInput({ service: 'Test Suite', dataSensitivity: 'low' });
    const paymentScore = computeRiskScore(payment).totalScore;
    const testScore = computeRiskScore(test).totalScore;
    expect(paymentScore).toBeGreaterThan(testScore);
  });

  it('assigns lower score to quantum-resistant algorithms', () => {
    const vulnerable = makeRiskInput({ quantumStatus: 'vulnerable' });
    const pqc = makeRiskInput({ quantumStatus: 'quantum-resistant', baseSeverity: 'low' });
    const vulnScore = computeRiskScore(vulnerable).totalScore;
    const pqcScore = computeRiskScore(pqc).totalScore;
    expect(vulnScore).toBeGreaterThan(pqcScore);
  });

  it('assigns higher score for long-lived data (HNDL risk)', () => {
    const shortLived = makeRiskInput({ dataLifetimeYears: 1 });
    const longLived = makeRiskInput({ dataLifetimeYears: 25 });
    const shortScore = computeRiskScore(shortLived).totalScore;
    const longScore = computeRiskScore(longLived).totalScore;
    expect(longScore).toBeGreaterThan(shortScore);
  });

  it('assigns higher score for hardcoded finding', () => {
    const notHardcoded = makeRiskInput({ isHardcoded: false });
    const hardcoded = makeRiskInput({ isHardcoded: true });
    const notHardcodedScore = computeRiskScore(notHardcoded).totalScore;
    const hardcodedScore = computeRiskScore(hardcoded).totalScore;
    expect(hardcodedScore).toBeGreaterThan(notHardcodedScore);
  });

  it('returns all breakdown components', () => {
    const result = computeRiskScore(makeRiskInput());
    expect(result).toHaveProperty('algorithmRisk');
    expect(result).toHaveProperty('businessCriticality');
    expect(result).toHaveProperty('internetExposure');
    expect(result).toHaveProperty('dataLifetime');
    expect(result).toHaveProperty('dataSensitivity');
    expect(result).toHaveProperty('migrationDifficulty');
    expect(result).toHaveProperty('totalScore');
  });
});

// ─── Severity Mapping ─────────────────────────────────────────

describe('Risk Engine — Severity Mapping', () => {
  it('scoreToSeverity maps 80+ to Critical', () => {
    expect(scoreToSeverity(80)).toBe('Critical');
    expect(scoreToSeverity(95)).toBe('Critical');
    expect(scoreToSeverity(100)).toBe('Critical');
  });

  it('scoreToSeverity maps 60–79 to High', () => {
    expect(scoreToSeverity(60)).toBe('High');
    expect(scoreToSeverity(70)).toBe('High');
    expect(scoreToSeverity(79)).toBe('High');
  });

  it('scoreToSeverity maps 40–59 to Moderate', () => {
    expect(scoreToSeverity(40)).toBe('Moderate');
    expect(scoreToSeverity(50)).toBe('Moderate');
    expect(scoreToSeverity(59)).toBe('Moderate');
  });

  it('scoreToSeverity maps 20–39 to Low', () => {
    expect(scoreToSeverity(20)).toBe('Low');
    expect(scoreToSeverity(30)).toBe('Low');
    expect(scoreToSeverity(39)).toBe('Low');
  });

  it('scoreToSeverity maps below 20 to Minimal', () => {
    expect(scoreToSeverity(0)).toBe('Minimal');
    expect(scoreToSeverity(10)).toBe('Minimal');
    expect(scoreToSeverity(19)).toBe('Minimal');
  });

  it('scoreToColor returns red for scores >= 80', () => {
    expect(scoreToColor(80)).toBe('#ef4444');
    expect(scoreToColor(100)).toBe('#ef4444');
  });

  it('scoreToColor returns orange for 60-79', () => {
    expect(scoreToColor(60)).toBe('#f97316');
    expect(scoreToColor(75)).toBe('#f97316');
  });

  it('scoreToColor returns yellow for 40-59', () => {
    expect(scoreToColor(40)).toBe('#eab308');
    expect(scoreToColor(55)).toBe('#eab308');
  });

  it('scoreToColor returns green for 20-39', () => {
    expect(scoreToColor(20)).toBe('#22c55e');
    expect(scoreToColor(35)).toBe('#22c55e');
  });
});

// ─── Edge Cases ───────────────────────────────────────────────

describe('Risk Engine — Edge Cases', () => {
  it('clamps totalScore to [0, 100]', () => {
    const highInput = makeRiskInput({
      quantumStatus: 'vulnerable',
      baseSeverity: 'critical',
      internetFacing: true,
      dataSensitivity: 'critical',
      dataLifetimeYears: 30,
      isHardcoded: true,
      service: 'Payment Service',
    });
    const result = computeRiskScore(highInput);
    expect(result.totalScore).toBeLessThanOrEqual(100);
    expect(result.totalScore).toBeGreaterThanOrEqual(0);
  });

  it('handles quantum-resistant status correctly', () => {
    const input = makeRiskInput({ quantumStatus: 'quantum-resistant', baseSeverity: 'low' });
    const result = computeRiskScore(input);
    // PQC findings should have low scores
    expect(result.algorithmRisk).toBeLessThan(30);
  });

  it('handles Test Suite service as minimal criticality', () => {
    const input = makeRiskInput({ service: 'Test Suite', dataSensitivity: 'low', internetFacing: false });
    const result = computeRiskScore(input);
    expect(result.businessCriticality).toBeLessThan(20);
  });

  it('handles dataLifetimeYears = 0 without crashing', () => {
    const input = makeRiskInput({ dataLifetimeYears: 0 });
    const result = computeRiskScore(input);
    expect(result.totalScore).toBeGreaterThanOrEqual(0);
  });

  it('handles unknown quantumStatus', () => {
    const input = makeRiskInput({ quantumStatus: 'unknown' as any });
    const result = computeRiskScore(input);
    expect(result.algorithmRisk).toBeGreaterThan(0);
  });
});

// ─── Quantum Readiness Index ──────────────────────────────────

describe('Risk Engine — Quantum Readiness Index', () => {
  it('returns zero for empty findings array', () => {
    const result = computeQuantumReadinessIndex([]);
    expect(result.overall).toBe(0);
  });

  it('penalizes for classical-weak findings', () => {
    const weakFindings = [
      makeFinding({ quantumStatus: 'classical-weak', classicalStatus: 'weak' }),
      makeFinding({ quantumStatus: 'classical-weak', classicalStatus: 'weak' }),
      makeFinding({ quantumStatus: 'classical-weak', classicalStatus: 'weak' }),
    ];
    const result = computeQuantumReadinessIndex(weakFindings);
    expect(result.legacyCrypto).toBeLessThan(80);
  });

  it('rewards remediated findings in PQC migration score', () => {
    const mixed = [
      makeFinding({ remediationStatus: 'remediated', quantumStatus: 'quantum-resistant' }),
      makeFinding({ remediationStatus: 'remediated', quantumStatus: 'quantum-resistant' }),
      makeFinding({ remediationStatus: 'open', quantumStatus: 'vulnerable' }),
    ];
    const result = computeQuantumReadinessIndex(mixed);
    expect(result.pqcMigration).toBeGreaterThan(50);
  });

  it('penalizes hardcoded findings in crypto agility score', () => {
    const hardcodedFindings = Array.from({ length: 5 }, () =>
      makeFinding({ isHardcoded: true, category: 'asymmetric' })
    );
    const result = computeQuantumReadinessIndex(hardcodedFindings);
    expect(result.cryptoAgility).toBeLessThan(80);
  });

  it('penalizes hardcoded secrets in secret management score', () => {
    const secretFindings = Array.from({ length: 3 }, () =>
      makeFinding({ category: 'secret' })
    );
    const result = computeQuantumReadinessIndex(secretFindings);
    expect(result.secretManagement).toBeLessThan(60);
  });
});
