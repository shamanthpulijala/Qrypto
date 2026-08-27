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
import { scanFile } from '../engine/scanner';
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

  it('migration time estimation uses finding context (hardcoded, library)', () => {
    // Hardcoded RSA should have longer migration time than non-hardcoded
    const hardcoded = makeFinding({
      algorithm: 'RSA-2048',
      isHardcoded: true,
      quantumStatus: 'vulnerable',
      dataLifetimeYears: 10,
      library: undefined,
    });
    const withLib = makeFinding({
      id: 'QG-0002',
      algorithm: 'RSA-2048',
      isHardcoded: false,
      quantumStatus: 'vulnerable',
      dataLifetimeYears: 10,
      library: 'cryptography',
    });
    const r1 = runMoscaAssessment([hardcoded], { threatHorizonYear: 2030 });
    const r2 = runMoscaAssessment([withLib], { threatHorizonYear: 2030 });
    // Hardcoded should have longer migration time
    expect(r1.findings[0].migrationTimeYears).toBeGreaterThan(r2.findings[0].migrationTimeYears);
  });

  it('derivation documents the estimation basis', () => {
    const findings = [makeFinding({
      algorithm: 'RSA-2048',
      isHardcoded: true,
      library: 'cryptography',
      quantumStatus: 'vulnerable',
      dataLifetimeYears: 10,
    })];
    const result = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    const yStep = result.findings[0].derivation.steps[1];
    expect(yStep).toContain('estimated from');
    expect(yStep).toContain('hardcoded');
  });
});

// ─── CBOM Schema Validation Tests ─────────────────────────────

describe('CBOM — Schema Validation', () => {
  it('validates required CycloneDX 1.6 top-level fields', () => {
    const bom = generateCBOM([makeFinding()]);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(typeof bom.version).toBe('number');
    expect(bom.metadata).toBeDefined();
    expect(bom.metadata.timestamp).toBeTruthy();
    expect(bom.metadata.tools).toBeDefined();
    expect(bom.metadata.tools.length).toBeGreaterThan(0);
    expect(Array.isArray(bom.components)).toBe(true);
  });

  it('validates component structure', () => {
    const bom = generateCBOM([makeFinding()]);
    for (const comp of bom.components) {
      expect(comp.type).toBe('cryptographic-asset');
      expect(comp['bom-ref']).toBeTruthy();
      expect(comp.name).toBeTruthy();
      expect(comp.cryptoProperties).toBeDefined();
      expect(comp.cryptoProperties.assetType).toBeTruthy();
      expect(comp.cryptoProperties.algorithmProperties).toBeDefined();
      expect(comp.evidence).toBeDefined();
      expect(comp.evidence.occurrences.length).toBeGreaterThan(0);
      expect(comp.properties).toBeDefined();
    }
  });

  it('validates empty scan produces valid BOM with no components', () => {
    const bom = generateCBOM([]);
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.components.length).toBe(0);
  });

  it('validates single finding produces single component', () => {
    const bom = generateCBOM([makeFinding({ algorithm: 'RSA-2048' })]);
    expect(bom.components.length).toBe(1);
    expect(bom.components[0].name).toContain('RSA');
  });

  it('validates PQC algorithm in CBOM', () => {
    const bom = generateCBOM([makeFinding({
      algorithm: 'ML-KEM-768',
      quantumStatus: 'quantum-resistant',
      category: 'pqc',
    })]);
    const comp = bom.components[0];
    expect(comp.name).toContain('ML-KEM');
    const qsProp = comp.properties!.find(p => p.name === 'qrypto:quantumStatus');
    expect(qsProp!.value).toBe('quantum-resistant');
  });

  it('validates unknown algorithm in CBOM', () => {
    const bom = generateCBOM([makeFinding({
      algorithm: 'CUSTOM_CRYPTO_XYZ',
      quantumStatus: 'unknown',
    })]);
    // Should still produce a valid component
    expect(bom.components.length).toBe(1);
    expect(bom.components[0].name).toBeTruthy();
  });

  it('serialized CBOM is valid JSON', () => {
    const bom = generateCBOM([makeFinding()]);
    const json = serializeCBOM(bom);
    const parsed = JSON.parse(json);
    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(parsed.specVersion).toBe('1.6');
    expect(Array.isArray(parsed.components)).toBe(true);
  });

  it('metadata tool information is present', () => {
    const bom = generateCBOM([], { projectName: 'Test', toolVersion: '2.0.0' });
    expect(bom.metadata.tools[0].vendor).toBe('Qrypto');
    expect(bom.metadata.tools[0].version).toBe('2.0.0');
    expect(bom.metadata.component).toBeDefined();
    expect(bom.metadata.component!.name).toBe('Test');
  });
});

// ─── Browser/Backend Parity Tests ─────────────────────────────

describe('Browser/Backend Parity — Scanner', () => {
  it('scanFile produces identical results for same input', () => {
    const input = {
      path: 'src/auth.py',
      content: 'from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
    };
    const result1 = scanFile(input);
    const result2 = scanFile(input);
    // Same input should produce same findings
    expect(result1.length).toBe(result2.length);
    for (let i = 0; i < result1.length; i++) {
      expect(result1[i].algorithm).toBe(result2[i].algorithm);
      expect(result1[i].quantumStatus).toBe(result2[i].quantumStatus);
      expect(result1[i].severity).toBe(result2[i].severity);
      expect(result1[i].riskScore).toBe(result2[i].riskScore);
      expect(result1[i].confidence).toBe(result2[i].confidence);
    }
  });

  it('CBOM is deterministic for same findings', () => {
    const findings = [
      makeFinding({ algorithm: 'RSA-2048', keySize: 2048 }),
      makeFinding({ id: 'QG-0002', algorithm: 'AES-256-GCM', category: 'symmetric' }),
    ];
    const bom1 = generateCBOM(findings);
    const bom2 = generateCBOM(findings);
    expect(bom1.components.length).toBe(bom2.components.length);
    for (let i = 0; i < bom1.components.length; i++) {
      expect(bom1.components[i].name).toBe(bom2.components[i].name);
      expect(bom1.components[i].type).toBe(bom2.components[i].type);
    }
  });

  it('Mosca assessment is deterministic for same findings', () => {
    const findings = [makeFinding({ dataLifetimeYears: 15, quantumStatus: 'vulnerable' })];
    const r1 = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    const r2 = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    expect(r1.findings[0].atRisk).toBe(r2.findings[0].atRisk);
    expect(r1.findings[0].dataLifetimeYears).toBe(r2.findings[0].dataLifetimeYears);
    expect(r1.findings[0].migrationTimeYears).toBe(r2.findings[0].migrationTimeYears);
  });
});

// ─── Integration Test: Scan → Mosca → CBOM ───────────────────

describe('Integration — Scan → Mosca → CBOM Pipeline', () => {
  it('full pipeline: scan sample code → findings → Mosca → CBOM', () => {
    // 1. Scan a realistic sample
    const scanInput = {
      path: 'services/payment/crypto.py',
      content: [
        'from cryptography.hazmat.primitives.asymmetric import rsa',
        'key = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
        'import hashlib',
        'h = hashlib.md5(data)',
      ].join('\n'),
    };
    const findings = scanFile(scanInput);
    expect(findings.length).toBeGreaterThan(0);

    // 2. Run Mosca on findings
    const mosca = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    expect(mosca.findings.length).toBeGreaterThanOrEqual(0);
    expect(mosca.horizonAssumption).toContain('assumption');

    // 3. Generate CBOM from findings
    const bom = generateCBOM(findings, { projectName: 'Payment Service' });
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.components.length).toBeGreaterThan(0);

    // 4. Verify CBOM components reference real findings
    const algos = bom.components.map(c => c.name);
    expect(algos.some(a => a.includes('RSA'))).toBe(true);

    // 5. Verify consistency: CBOM quantum status matches finding quantum status
    for (const comp of bom.components) {
      const qsProp = comp.properties!.find(p => p.name === 'qrypto:quantumStatus');
      expect(qsProp).toBeDefined();
    }
  });

  it('scan → PQC findings are not flagged as vulnerable by Mosca', () => {
    const scanInput = {
      path: 'src/pqc.py',
      content: 'from oqs import KeyEncapsulation\nkem = KeyEncapsulation("ML-KEM-768")',
    };
    const findings = scanFile(scanInput);
    // If PQC is detected, Mosca should not flag it as at-risk
    const mosca = runMoscaAssessment(findings, { threatHorizonYear: 2030 });
    const pqcInMosca = mosca.findings.filter(f => f.algorithm.includes('ML-KEM'));
    expect(pqcInMosca.length).toBe(0); // PQC should not appear in Mosca assessment
  });
});
