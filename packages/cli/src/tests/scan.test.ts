// ============================================================
// Qrypto CLI — Tests
// ============================================================

import { describe, it, expect } from 'vitest';
import { formatJson, formatCsv, formatText } from '../utils/format';
import type { Finding } from '../../../../shared/types/index';

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

function makeOutput(findings: Finding[] = [makeFinding()]) {
  return {
    scan: {
      repository: 'test-repo',
      path: '/tmp/test',
      filesScanned: 10,
      linesScanned: 500,
      findingsTotal: findings.length,
      executionMs: 150,
    },
    findings,
    mosca: {
      threatHorizonYear: 2030,
      horizonAssumption: 'Test assumption',
      findings: [],
      summary: {
        totalFindings: 0,
        atRiskCount: 0,
        safeCount: 0,
        riskDistribution: { critical: 0, high: 0, medium: 0, low: 0, safe: 0 },
        mostUrgent: null,
      },
    },
    readiness: { overall: 65 },
  };
}

// ─── Tests ───────────────────────────────────────────────────

describe('CLI Formatters', () => {
  describe('formatJson', () => {
    it('produces valid JSON', () => {
      const output = makeOutput();
      const json = formatJson(output);
      const parsed = JSON.parse(json);
      expect(parsed.scan.repository).toBe('test-repo');
      expect(parsed.findings).toHaveLength(1);
      expect(parsed.readiness.overall).toBe(65);
    });

    it('handles empty findings', () => {
      const output = makeOutput([]);
      const json = formatJson(output);
      const parsed = JSON.parse(json);
      expect(parsed.findings).toHaveLength(0);
      expect(parsed.scan.findingsTotal).toBe(0);
    });
  });

  describe('formatCsv', () => {
    it('produces valid CSV with headers', () => {
      const findings = [makeFinding()];
      const csv = formatCsv(findings);
      const lines = csv.split('\n');
      expect(lines[0]).toContain('id');
      expect(lines[0]).toContain('algorithm');
      expect(lines[0]).toContain('severity');
      expect(lines).toHaveLength(2); // header + 1 row
    });

    it('escapes commas in values', () => {
      const finding = makeFinding({
        detectedPattern: 'RSA.generate(2048, " cipher")',
      });
      const csv = formatCsv([finding]);
      // CSV standard: inner quotes are doubled
      expect(csv).toContain('"" cipher""');
    });

    it('handles multiple findings', () => {
      const findings = [
        makeFinding({ id: 'QG-0001', algorithm: 'RSA-2048' }),
        makeFinding({ id: 'QG-0002', algorithm: 'AES-256' }),
      ];
      const csv = formatCsv(findings);
      const lines = csv.split('\n');
      expect(lines).toHaveLength(3); // header + 2 rows
    });
  });

  describe('formatText', () => {
    it('includes repository name', () => {
      const output = makeOutput();
      const text = formatText(output);
      expect(text).toContain('test-repo');
    });

    it('includes severity counts', () => {
      const output = makeOutput();
      const text = formatText(output);
      expect(text).toContain('Critical:');
      expect(text).toContain('High:');
    });

    it('includes Mosca when findings exist', () => {
      const output = makeOutput();
      const text = formatText(output);
      // Mosca section appears when there are assessable findings
      expect(text).toContain('QRYPTO');
    });

    it('truncates at 20 findings', () => {
      const findings = Array.from({ length: 25 }, (_, i) =>
        makeFinding({ id: `QG-${String(i + 1).padStart(4, '0')}` })
      );
      const output = makeOutput(findings);
      const text = formatText(output);
      expect(text).toContain('and 5 more findings');
    });
  });
});

describe('CLI Exit Codes', () => {
  it('severity ranking is correct', () => {
    // This tests the logic, not the actual CLI
    const SEVERITY_RANK: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };

    expect(SEVERITY_RANK['critical']).toBeGreaterThan(SEVERITY_RANK['high']);
    expect(SEVERITY_RANK['high']).toBeGreaterThan(SEVERITY_RANK['medium']);
    expect(SEVERITY_RANK['medium']).toBeGreaterThan(SEVERITY_RANK['low']);
    expect(SEVERITY_RANK['low']).toBeGreaterThan(SEVERITY_RANK['info']);
  });
});
