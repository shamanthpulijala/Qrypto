// ============================================================
// Qrypto CLI — Output Formatters
// ============================================================

import type { Finding } from '../../../shared/types/index.js';
import type { MoscaAssessment } from '../../../shared/engine/mosca.js';

interface ScanOutput {
  scan: {
    repository: string;
    path: string;
    filesScanned: number;
    linesScanned: number;
    findingsTotal: number;
    executionMs: number;
  };
  findings: Finding[];
  mosca: MoscaAssessment;
  readiness: { overall: number; [key: string]: any };
}

// ─── JSON Format ─────────────────────────────────────────────

export function formatJson(output: ScanOutput): string {
  return JSON.stringify(output, null, 2);
}

// ─── CSV Format ──────────────────────────────────────────────

export function formatCsv(findings: Finding[]): string {
  const headers = [
    'id', 'file', 'line', 'algorithm', 'keySize', 'category',
    'usage', 'severity', 'algorithmSeverity', 'confidence',
    'quantumStatus', 'classicalStatus', 'riskScore',
    'internetFacing', 'dataSensitivity', 'dataLifetimeYears',
    'service', 'language', 'detectedPattern',
    'recommendedAlgorithm', 'migrationStrategy', 'fingerprint',
  ];

  const escapeCsv = (value: any): string => {
    if (value === null || value === undefined) return '';
    const str = String(value);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const rows = findings.map(f =>
    headers.map(h => escapeCsv((f as any)[h])).join(',')
  );

  return [headers.join(','), ...rows].join('\n');
}

// ─── Text Format ─────────────────────────────────────────────

export function formatText(output: ScanOutput): string {
  const lines: string[] = [];
  const { scan, findings, mosca, readiness } = output;

  lines.push('═══════════════════════════════════════════════════════════');
  lines.push('  QRYPTO — Cryptographic Discovery & Analysis Report');
  lines.push('═══════════════════════════════════════════════════════════');
  lines.push('');
  lines.push(`  Repository:   ${scan.repository}`);
  lines.push(`  Path:         ${scan.path}`);
  lines.push(`  Files:        ${scan.filesScanned}`);
  lines.push(`  Lines:        ${scan.linesScanned.toLocaleString()}`);
  lines.push(`  Findings:     ${scan.findingsTotal}`);
  lines.push(`  Scan time:    ${scan.executionMs}ms`);
  lines.push(`  Readiness:    ${readiness.overall}/100`);
  lines.push('');

  // Severity summary
  const bySeverity = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    medium: findings.filter(f => f.severity === 'medium'),
    low: findings.filter(f => f.severity === 'low'),
    info: findings.filter(f => f.severity === 'info'),
  };

  lines.push('─── Severity Summary ───────────────────────────────────────');
  lines.push(`  Critical: ${bySeverity.critical.length}`);
  lines.push(`  High:     ${bySeverity.high.length}`);
  lines.push(`  Medium:   ${bySeverity.medium.length}`);
  lines.push(`  Low:      ${bySeverity.low.length}`);
  lines.push(`  Info:     ${bySeverity.info.length}`);
  lines.push('');

  // Mosca summary
  if (mosca.summary.totalFindings > 0) {
    lines.push('─── Mosca Assessment ───────────────────────────────────────');
    lines.push(`  Threat horizon: ${mosca.threatHorizonYear} (assumption)`);
    lines.push(`  At risk:        ${mosca.summary.atRiskCount} finding(s)`);
    lines.push(`  Safe:           ${mosca.summary.safeCount} finding(s)`);
    if (mosca.summary.mostUrgent) {
      lines.push(`  Most urgent:    ${mosca.summary.mostUrgent.algorithm} at ${mosca.summary.mostUrgent.file}:${mosca.summary.mostUrgent.line}`);
    }
    lines.push('');
  }

  // Top findings
  if (findings.length > 0) {
    lines.push('─── Findings (top 20 by risk) ──────────────────────────────');
    lines.push('');

    const top = findings.slice(0, 20);
    for (const f of top) {
      const sev = f.severity.toUpperCase().padEnd(8);
      lines.push(`  [${sev}] ${f.algorithm} (${f.category})`);
      lines.push(`         ${f.file}:${f.line}`);
      lines.push(`         ${f.detectedPattern}`);
      lines.push(`         Risk: ${f.riskScore}/100 | Confidence: ${(f.confidence * 100).toFixed(0)}% | ${f.quantumStatus}`);
      if (f.recommendedAlgorithm) {
        lines.push(`         → ${f.recommendedAlgorithm}`);
      }
      lines.push('');
    }

    if (findings.length > 20) {
      lines.push(`  ... and ${findings.length - 20} more findings`);
      lines.push('');
    }
  }

  lines.push('═══════════════════════════════════════════════════════════');

  return lines.join('\n');
}
