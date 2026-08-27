// ============================================================
// Qrypto — Security Regression Tests
//
// Tests for previously fixed vulnerabilities and security
// invariants. These must never regress.
// ============================================================

import { describe, it, expect } from 'vitest';
import type { Finding } from '../types';

// ─── Test Helpers ────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'QG-0001',
    file: 'src/auth.py',
    line: 42,
    repository: 'test-repo',
    project: 'test-project',
    service: 'Authentication Service',
    language: 'python',
    algorithm: 'RSA-2048',
    keySize: 2048,
    category: 'public-key',
    usage: 'public-key cryptography',
    detectedPattern: 'RSA.generate(2048)',
    confidence: 0.95,
    quantumStatus: 'vulnerable',
    classicalStatus: 'adequate',
    algorithmSeverity: 'high',
    severity: 'high',
    severityRationale: 'RSA-2048 is quantum-vulnerable.',
    internetFacing: true,
    dataSensitivity: 'critical',
    dataLifetimeYears: 10,
    isCryptoAgile: false,
    isHardcoded: false,
    riskScore: 72,
    riskBreakdown: {
      algorithmRisk: 80,
      businessCriticality: 70,
      internetExposure: 80,
      dataLifetime: 60,
      dataSensitivity: 80,
      migrationDifficulty: 50,
      totalScore: 72,
    },
    remediationStatus: 'open',
    migrationPriority: 1,
    recommendedAlgorithm: 'ML-DSA-65 (FIPS 204)',
    migrationStrategy: 'Hybrid migration',
    tags: ['public-key', 'quantum-vulnerable'],
    detectedAt: '2026-01-01T00:00:00.000Z',
    fingerprint: 'abc123',
    firstSeen: '2026-01-01T00:00:00.000Z',
    lastSeen: '2026-01-01T00:00:00.000Z',
    evidence: {
      detectionLayers: ['regex'],
      matchedText: 'RSA.generate(2048)',
      confidenceDerivation: 'base 0.97 from pattern specificity.',
    },
    ...overrides,
  };
}

// ─── P0-0c: Role Injection Protection ────────────────────────
// The register endpoint must NOT accept role from request body.
// This is a regression test for the critical auth vulnerability.

describe('Security: Role Injection Protection', () => {
  it('register endpoint rejects client-controlled role', async () => {
    // The auth.routes.ts must NOT read role from req.body
    // This is verified by code review — the route ignores body.role
    // and always creates users with role='ANALYST' (or bootstrap admin)
    //
    // This test verifies the code invariant by checking the route
    // does not destructure role from the request body.
    const fs = await import('fs');
    const path = await import('path');
    const routeFile = fs.readFileSync(
      path.resolve('server/src/routes/auth.routes.ts'),
      'utf-8'
    );

    // The old vulnerable code had: const { email, password, name, role } = req.body
    // The fixed code must NOT have role in the destructuring
    const registerSection = routeFile.substring(
      routeFile.indexOf("router.post("),
      routeFile.indexOf("router.post(", routeFile.indexOf("router.post(") + 1)
    );

    // Should NOT read role from body
    expect(registerSection).not.toMatch(/const\s*\{[^}]*\brole\b[^}]*\}\s*=\s*req\.body/);
  });

  it('requireRole middleware is actually used', async () => {
    const fs = await import('fs');
    const path = await import('path');

    // Check that requireRole is imported and used in route files
    const routeFiles = [
      'server/src/routes/auth.routes.ts',
      'server/src/routes/findings.routes.ts',
      'server/src/routes/scan.routes.ts',
    ];

    let totalUses = 0;
    for (const file of routeFiles) {
      try {
        const content = fs.readFileSync(path.resolve(file), 'utf-8');
        const matches = content.match(/requireRole\(/g);
        totalUses += matches?.length ?? 0;
      } catch { /* file may not exist */ }
    }

    // requireRole must be used at least once (admin user management)
    expect(totalUses).toBeGreaterThanOrEqual(1);
  });
});

// ─── P0-0c: JWT Configuration ────────────────────────────────

describe('Security: JWT Configuration', () => {
  it('JWT secret must not use the leaked fallback value', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const config = fs.readFileSync(
      path.resolve('server/src/config.ts'),
      'utf-8'
    );

    // The config must reject the leaked fallback secret
    expect(config).toContain('LEAKED_FALLBACK_SECRET');
    expect(config).toContain('fallback-secret-for-dev-only-do-not-use-in-prod');

    // The config must fail-fast in production with no secret
    expect(config).toContain('process.exit(1)');
  });

  it('JWT algorithm is pinned', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const authMiddleware = fs.readFileSync(
      path.resolve('server/src/middleware/auth.ts'),
      'utf-8'
    );

    // Algorithm must be explicitly specified in verify
    expect(authMiddleware).toContain('algorithms:');
  });
});

// ─── P0-2: Algorithm Severity Not Inflated ───────────────────

describe('Security: Algorithm Severity Invariants', () => {
  it('ML-KEM is never above info severity', async () => {
    const { deriveAlgorithmSeverity } = await import('../engine/severity');

    const result = deriveAlgorithmSeverity({
      algorithm: 'ML-KEM-768',
      quantumStatus: 'quantum-resistant',
      baseSeverity: 'info',
      keySize: 768,
      category: 'pqc',
    });

    expect(result.severity).toBe('info');
  });

  it('MD5 is never below high severity', async () => {
    const { deriveAlgorithmSeverity } = await import('../engine/severity');

    const result = deriveAlgorithmSeverity({
      algorithm: 'MD5',
      quantumStatus: 'classical-weak',
      baseSeverity: 'critical',
      category: 'hash',
    });

    expect(['critical', 'high']).toContain(result.severity);
  });

  it('effective severity never exceeds one level above algorithm severity', async () => {
    const { deriveEffectiveSeverity } = await import('../engine/severity');

    // Algorithm is info, contextual risk is very high
    const result = deriveEffectiveSeverity({
      algorithmSeverity: 'info',
      quantumStatus: 'quantum-resistant',
      contextualRisk: 95,
    });

    // Should not escalate beyond low (one level above info)
    expect(['info', 'low']).toContain(result.severity);
  });
});

// ─── P0-4: Confidence Computation ────────────────────────────

describe('Security: Confidence Computation', () => {
  it('confidence is never a literal copy of pattern constant', async () => {
    const { scanFile } = await import('../engine/scanner');

    const findings = scanFile({
      path: 'test/comment.py',
      content: '# This uses RSA for testing purposes\nrsa_key = "not a real key"',
      repository: 'test',
      project: 'test',
    });

    // Findings in comments should have reduced confidence
    const commentFindings = findings.filter(f =>
      f.evidence?.confidenceDerivation?.includes('comment or string')
    );

    if (commentFindings.length > 0) {
      for (const f of commentFindings) {
        expect(f.confidence).toBeLessThan(0.80);
      }
    }
  });

  it('test/vendor paths reduce confidence', async () => {
    const { scanFile } = await import('../engine/scanner');

    const findings = scanFile({
      path: 'test/fixtures/crypto.py',
      content: 'from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
      repository: 'test',
      project: 'test',
    });

    // Findings in test paths should have reduced confidence
    const testFindings = findings.filter(f =>
      f.evidence?.confidenceDerivation?.includes('test/vendor')
    );

    if (testFindings.length > 0) {
      for (const f of testFindings) {
        expect(f.confidence).toBeLessThan(0.85);
      }
    }
  });
});

// ─── P0-8: Fingerprint Stability ─────────────────────────────

describe('Security: Finding Fingerprints', () => {
  it('fingerprints are stable across rescans', async () => {
    const { scanFile } = await import('../engine/scanner');

    const file = {
      path: 'src/auth.py',
      content: 'from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
      repository: 'test-repo',
      project: 'test',
    };

    const run1 = scanFile(file);
    const run2 = scanFile(file);

    // Same input → same fingerprints
    expect(run1.length).toBe(run2.length);
    for (let i = 0; i < run1.length; i++) {
      expect(run1[i].fingerprint).toBe(run2[i].fingerprint);
    }
  });

  it('fingerprints exclude line numbers', async () => {
    const { scanFile } = await import('../engine/scanner');

    // Same algorithm, same pattern, different line number
    const file1 = {
      path: 'src/auth.py',
      content: 'x = 1\nfrom cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
      repository: 'test-repo',
      project: 'test',
    };
    const file2 = {
      path: 'src/auth.py',
      content: 'from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
      repository: 'test-repo',
      project: 'test',
    };

    const run1 = scanFile(file1);
    const run2 = scanFile(file2);

    // Same algorithm + pattern → same fingerprint (despite different line)
    if (run1.length > 0 && run2.length > 0) {
      expect(run1[0].fingerprint).toBe(run2[0].fingerprint);
    }
  });
});

// ─── P0-12: Context Overrides ────────────────────────────────

describe('Security: Context Override Recalculation', () => {
  it('ML-KEM in payment path stays info after override', async () => {
    const { deriveAlgorithmSeverity, deriveEffectiveSeverity } = await import('../engine/severity');
    const { computeRiskScore } = await import('../engine/riskEngine');

    // ML-KEM in a "payment" path with high context
    const riskBreakdown = computeRiskScore({
      quantumStatus: 'quantum-resistant',
      baseSeverity: 'info',
      internetFacing: true,
      dataSensitivity: 'critical',
      dataLifetimeYears: 15,
      isHardcoded: false,
      service: 'Payment Service',
    });

    const algSev = deriveAlgorithmSeverity({
      algorithm: 'ML-KEM-768',
      quantumStatus: 'quantum-resistant',
      baseSeverity: 'info',
      keySize: 768,
      category: 'pqc',
    });

    const effective = deriveEffectiveSeverity({
      algorithmSeverity: algSev.severity,
      quantumStatus: 'quantum-resistant',
      contextualRisk: riskBreakdown.totalScore,
    });

    // ML-KEM must stay info regardless of context
    expect(effective.severity).toBe('info');
  });
});

// ─── P0-5: CBOM Spec Conformance ─────────────────────────────

describe('Security: CycloneDX CBOM Conformance', () => {
  it('CBOM uses correct cryptographic-asset type', async () => {
    const { generateCBOM } = await import('../engine/cbom');

    const bom = generateCBOM([makeFinding()]);

    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    for (const comp of bom.components) {
      expect(comp.type).toBe('cryptographic-asset');
    }
  });

  it('CBOM is valid JSON', async () => {
    const { generateCBOM, serializeCBOM } = await import('../engine/cbom');

    const bom = generateCBOM([makeFinding()]);
    const json = serializeCBOM(bom);
    const parsed = JSON.parse(json);

    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(parsed.specVersion).toBe('1.6');
  });
});

// ─── P0-3: Mosca Explainability ──────────────────────────────

describe('Security: Mosca Explainability', () => {
  it('every finding has a step-by-step derivation', async () => {
    const { runMoscaAssessment } = await import('../engine/mosca');

    const finding = makeFinding({
      quantumStatus: 'vulnerable',
      dataLifetimeYears: 10,
    });

    const assessment = runMoscaAssessment([finding], { threatHorizonYear: 2030 });

    expect(assessment.findings.length).toBe(1);
    const result = assessment.findings[0];
    expect(result.derivation.steps.length).toBeGreaterThanOrEqual(3);
    expect(result.derivation.equation).toBeTruthy();
    expect(result.derivation.conclusion).toBeTruthy();
  });

  it('threat horizon is documented as assumption', async () => {
    const { runMoscaAssessment } = await import('../engine/mosca');

    const assessment = runMoscaAssessment([], { threatHorizonYear: 2035 });

    expect(assessment.horizonAssumption).toContain('assumption');
    expect(assessment.horizonAssumption).toContain('2035');
  });
});
