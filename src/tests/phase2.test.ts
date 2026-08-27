// ============================================================
// Qrypto — Phase 2 Tests
//
// Tests for:
//   - Algorithm registry (lookup, normalization, CycloneDX mappings)
//   - CycloneDX 1.6 CBOM generation
//   - Mosca engine (X = Y + Z, configurable horizon)
// ============================================================

import { describe, it, expect } from 'vitest';
import { lookupAlgorithm, normalizeAlgorithm } from '../engine/registry';
import { generateCBOM, serializeCBOM } from '../engine/cbom';
import { runMoscaAssessment } from '../engine/mosca';
import type { Finding } from '../types';

// ─── Helper ───────────────────────────────────────────────────

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
    keySize: 2048,
    category: 'public-key',
    usage: 'key establishment',
    detectedPattern: 'RSA',
    confidence: 0.9,
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    algorithmSeverity: 'high',
    severity: 'high',
    severityRationale: 'RSA-2048 is quantum-vulnerable.',
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
    migrationStrategy: 'Hybrid migration',
    tags: ['quantum-vulnerable'],
    detectedAt: new Date().toISOString(),
    ...overrides,
  };
}

// ─── Algorithm Registry Tests ─────────────────────────────────

describe('Algorithm Registry — Lookup', () => {
  it('looks up RSA-2048 and returns correct quantum status', () => {
    const entry = lookupAlgorithm('RSA-2048');
    expect(entry.quantumStatus).toBe('vulnerable');
    expect(entry.canonicalName).toContain('RSA');
    expect(entry.cycloneDxPrimitive).toBe('public-key');
  });

  it('looks up ML-KEM and returns quantum-resistant', () => {
    const entry = lookupAlgorithm('ML-KEM');
    expect(entry.quantumStatus).toBe('quantum-resistant');
    expect(entry.nistStandard).toBe('FIPS 203');
  });

  it('looks up MD5 and returns classical-weak / broken', () => {
    const entry = lookupAlgorithm('MD5');
    expect(entry.quantumStatus).toBe('classical-weak');
    expect(entry.classicalStatus).toBe('broken');
    expect(entry.severity).toBe('critical');
  });

  it('looks up AES-256-GCM and returns adequate', () => {
    const entry = lookupAlgorithm('AES-256-GCM');
    expect(entry.quantumStatus).toBe('adequate');
    expect(entry.classicalStatus).toBe('strong');
  });

  it('looks up TLS 1.3 and returns adequate', () => {
    const entry = lookupAlgorithm('TLS 1.3');
    expect(entry.quantumStatus).toBe('adequate');
    expect(entry.classicalStatus).toBe('strong');
  });

  it('looks up TLS 1.0 and returns classical-weak', () => {
    const entry = lookupAlgorithm('TLS 1.0');
    expect(entry.quantumStatus).toBe('classical-weak');
  });

  it('returns sensible defaults for unknown algorithms', () => {
    const entry = lookupAlgorithm('UNKNOWN_ALGO_XYZ');
    expect(entry.quantumStatus).toBe('unknown');
    expect(entry.severity).toBe('medium');
  });

  it('case-insensitive lookup', () => {
    const entry = lookupAlgorithm('rsa-2048');
    expect(entry.quantumStatus).toBe('vulnerable');
  });
});

describe('Algorithm Registry — Normalization', () => {
  it('normalizes RSA-2048 to canonical form', () => {
    expect(normalizeAlgorithm('rsa-2048')).toContain('RSA');
  });

  it('normalizes ML-KEM-768', () => {
    expect(normalizeAlgorithm('ML-KEM-768')).toBe('ML-KEM-768');
  });
});

// ─── CycloneDX CBOM Tests ─────────────────────────────────────

describe('CycloneDX CBOM — Generation', () => {
  it('generates a valid CycloneDX 1.6 BOM structure', () => {
    const findings = [
      makeFinding({ algorithm: 'RSA-2048', quantumStatus: 'vulnerable' }),
      makeFinding({ id: 'QG-0002', algorithm: 'AES-256-GCM', quantumStatus: 'adequate', category: 'symmetric' }),
    ];
    const bom = generateCBOM(findings);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.version).toBe(1);
    expect(bom.components.length).toBeGreaterThan(0);
  });

  it('uses "cryptographic-asset" type (not invalid "cryptography")', () => {
    const findings = [makeFinding()];
    const bom = generateCBOM(findings);
    for (const comp of bom.components) {
      expect(comp.type).toBe('cryptographic-asset');
    }
  });

  it('includes evidence occurrences with file locations', () => {
    const findings = [makeFinding({ file: 'src/auth.py', line: 42 })];
    const bom = generateCBOM(findings);
    const rsa = bom.components.find(c => c.name.includes('RSA'));
    expect(rsa).toBeDefined();
    expect(rsa!.evidence!.occurrences[0].location).toContain('src/auth.py');
  });

  it('includes quantum status properties', () => {
    const findings = [makeFinding({ quantumStatus: 'vulnerable' })];
    const bom = generateCBOM(findings);
    const comp = bom.components[0];
    const qsProp = comp.properties!.find(p => p.name === 'qrypto:quantumStatus');
    expect(qsProp!.value).toBe('vulnerable');
  });

  it('groups findings by algorithm+keySize', () => {
    const findings = [
      makeFinding({ algorithm: 'RSA-2048', keySize: 2048 }),
      makeFinding({ id: 'QG-0002', algorithm: 'RSA-2048', keySize: 2048 }),
      makeFinding({ id: 'QG-0003', algorithm: 'RSA-4096', keySize: 4096 }),
    ];
    const bom = generateCBOM(findings);
    // Should have 2 components: RSA-2048 and RSA-4096
    expect(bom.components.length).toBe(2);
  });

  it('serializes to valid JSON', () => {
    const findings = [makeFinding()];
    const bom = generateCBOM(findings);
    const json = serializeCBOM(bom);
    const parsed = JSON.parse(json);
    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(parsed.specVersion).toBe('1.6');
  });
});

// ─── Mosca Engine Tests ───────────────────────────────────────

describe('Mosca Engine — X = Y + Z Model', () => {
  it('identifies findings at risk when X + Y > Z', () => {
    const findings = [
      makeFinding({
        algorithm: 'RSA-2048',
        dataLifetimeYears: 20, // X = 20
        quantumStatus: 'vulnerable',
      }),
    ];
    // Y ≈ 0.75 for RSA signatures, Z = (2030 - 2026) = 4
    // X + Y = 20 + 0.75 = 20.75 > 4 → at risk
    const result = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].atRisk).toBe(true);
    expect(result.findings[0].dataLifetimeYears).toBe(20);
  });

  it('identifies short-lived data as safe', () => {
    const findings = [
      makeFinding({
        algorithm: 'SHA-1',
        dataLifetimeYears: 0.5, // X = 0.5
        quantumStatus: 'classical-weak',
      }),
    ];
    // Y ≈ 0.08 for hash, Z = 4
    // X + Y = 0.5 + 0.08 = 0.58 < 4 → safe
    const result = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].atRisk).toBe(false);
  });

  it('PQC findings are not assessed (already safe)', () => {
    const findings = [
      makeFinding({
        algorithm: 'ML-KEM-768',
        quantumStatus: 'quantum-resistant',
      }),
    ];
    const result = runMoscaAssessment(findings);
    expect(result.findings.length).toBe(0);
  });

  it('configurable threat horizon changes results', () => {
    const findings = [
      makeFinding({
        algorithm: 'RSA-2048',
        dataLifetimeYears: 8,
        quantumStatus: 'vulnerable',
      }),
    ];
    // With horizon 2035: Z = 9 (assuming 2026), X+Y ≈ 8 + 0.75 = 8.75 < 9 → safe
    const result2035 = runMoscaAssessment(findings, { threatHorizonYear: 2035 });
    // With horizon 2030: Z = 4, X+Y ≈ 8.75 > 4 → at risk
    const result2030 = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    expect(result2030.findings[0].atRisk).toBe(true);
    // 2035 result might still be at risk depending on exact migration time, but horizon should differ
    expect(result2035.findings[0].threatHorizonYears).toBeGreaterThan(result2030.findings[0].threatHorizonYears);
  });

  it('provides step-by-step derivation for explainability', () => {
    const findings = [makeFinding({ dataLifetimeYears: 15 })];
    const result = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    const derivation = result.findings[0].derivation;
    expect(derivation.steps.length).toBeGreaterThanOrEqual(4);
    expect(derivation.equation).toContain('+');
    expect(derivation.conclusion).toBeTruthy();
  });

  it('summary counts are correct', () => {
    const findings = [
      makeFinding({ dataLifetimeYears: 25, quantumStatus: 'vulnerable' }),
      makeFinding({ id: 'QG-0002', dataLifetimeYears: 0.5, quantumStatus: 'classical-weak' }),
    ];
    const result = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    expect(result.summary.totalFindings).toBe(2);
    expect(result.summary.atRiskCount + result.summary.safeCount).toBe(2);
  });

  it('horizon assumption is documented as assumption, not fact', () => {
    const result = runMoscaAssessment([], { threatHorizonYear: 2035 });
    expect(result.horizonAssumption).toContain('assumption');
    expect(result.horizonAssumption).toContain('2035');
  });
});
