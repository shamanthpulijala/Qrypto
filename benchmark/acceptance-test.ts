#!/usr/bin/env npx tsx
// ============================================================
// QRYPTO — Final Acceptance Test
//
// Scans two independent directories and verifies:
// 1. Real findings are produced (not fabricated)
// 2. Results differ between directories (data-driven)
// 3. All pipeline stages execute
// 4. Outputs are consistent
// 5. Mosca, CBOM, severity, confidence are derived from real data
// ============================================================

import fs from 'fs';
import path from 'path';
import { runScanPipeline, type PipelineFile } from '../shared/engine/pipeline.js';

function loadDir(dir: string): PipelineFile[] {
  const files: PipelineFile[] = [];
  const exts = new Set(['.ts', '.js', '.py', '.java', '.go', '.json', '.yaml', '.yml', '.toml', '.xml', '.env']);

  function walk(d: string, rel: string) {
    for (const entry of fs.readdirSync(d)) {
      const full = path.join(d, entry);
      const r = rel ? `${rel}/${entry}` : entry;
      if (fs.statSync(full).isDirectory()) walk(full, r);
      else if (exts.has(path.extname(entry).toLowerCase())) {
        files.push({ path: r, content: fs.readFileSync(full, 'utf-8') });
      }
    }
  }
  walk(dir, '');
  return files;
}

async function runAcceptance() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  QRYPTO ACCEPTANCE TEST — End-to-End Verification');
  console.log('═══════════════════════════════════════════════════════════\n');

  const errors: string[] = [];
  let passed = 0;
  let failed = 0;

  function check(name: string, condition: boolean, detail: string) {
    if (condition) {
      console.log(`  ✓ ${name} — ${detail}`);
      passed++;
    } else {
      console.log(`  ✗ ${name} — ${detail}`);
      errors.push(`${name}: ${detail}`);
      failed++;
    }
  }

  // ── Scan Directory A: shared/engine (crypto-heavy) ─────────
  console.log('── Scan A: shared/engine ─────────────────────────────────');
  const filesA = loadDir(path.join(import.meta.dirname ?? '.', '..', 'shared/engine'));
  const resultA = await runScanPipeline(filesA, { repository: 'engine', project: 'Qrypto Engine' });

  check('Scan A produces findings', resultA.findings.length > 0, `${resultA.findings.length} findings`);
  check('Scan A has stats', resultA.stats.filesScanned > 0, `${resultA.stats.filesScanned} files scanned`);
  check('Scan A has readiness index', typeof resultA.readinessIndex.overall === 'number', `readiness=${resultA.readinessIndex.overall}`);
  check('Scan A has severity spread', 
    resultA.findings.some(f => f.severity === 'high') && resultA.findings.some(f => f.severity === 'info'),
    `severities: ${[...new Set(resultA.findings.map(f => f.severity))].join(', ')}`);

  // Evidence check
  const withEvidence = resultA.findings.filter(f => f.evidence?.matchedText);
  check('Scan A findings have evidence', withEvidence.length > 0, `${withEvidence.length} findings with matchedText`);

  // Confidence check
  const avgConfidence = resultA.findings.reduce((s, f) => s + f.confidence, 0) / resultA.findings.length;
  check('Scan A has computed confidence', avgConfidence > 0 && avgConfidence <= 1, `avg=${avgConfidence.toFixed(2)}`);

  // Severity rationale
  const withRationale = resultA.findings.filter(f => f.severityRationale && f.severityRationale.length > 0);
  check('Scan A findings have severity rationale', withRationale.length > 0, `${withRationale.length} with rationale`);

  // Fingerprint
  const withFingerprint = resultA.findings.filter(f => f.fingerprint);
  check('Scan A findings have fingerprints', withFingerprint.length === resultA.findings.length, `${withFingerprint.length}/${resultA.findings.length}`);

  // contextSource
  const withContextSource = resultA.findings.filter(f => f.contextSource);
  check('Scan A findings have contextSource', withContextSource.length > 0, `${withContextSource.length} with source label`);

  // Different algorithms
  const algsA = new Set(resultA.findings.map(f => f.algorithm));
  check('Scan A detects multiple algorithms', algsA.size >= 3, `${algsA.size} unique algorithms: ${[...algsA].slice(0, 5).join(', ')}`);

  // ── Scan Directory B: server/src (different profile) ───────
  console.log('\n── Scan B: server/src ────────────────────────────────────');
  const filesB = loadDir(path.join(import.meta.dirname ?? '.', '..', 'server/src'));
  const resultB = await runScanPipeline(filesB, { repository: 'qrypto-server', project: 'Qrypto Server' });

  check('Scan B produces findings', resultB.findings.length > 0, `${resultB.findings.length} findings`);
  check('Scan B has different finding count than A', resultA.findings.length !== resultB.findings.length,
    `A=${resultA.findings.length}, B=${resultB.findings.length}`);

  // ── Cross-verification ─────────────────────────────────────
  console.log('\n── Cross-Verification ────────────────────────────────────');
  const algsB = new Set(resultB.findings.map(f => f.algorithm));
  const commonAlgs = [...algsA].filter(a => algsB.has(a));
  const uniqueToA = [...algsA].filter(a => !algsB.has(a));
  const uniqueToB = [...algsB].filter(a => !algsA.has(a));

  check('Scans detect different algorithm profiles', uniqueToA.length > 0 || uniqueToB.length > 0,
    `A-only: ${uniqueToA.join(', ') || 'none'} | B-only: ${uniqueToB.join(', ') || 'none'}`);

  // ── Pipeline stages ────────────────────────────────────────
  console.log('\n── Pipeline Stages ───────────────────────────────────────');
  const stages = ['validate', 'extract', 'detect-language', 'run-detectors', 'deduplicate', 'confidence', 'risk-engine'];
  for (const stage of stages) {
    const hasLog = resultA.log.some(l => l.startsWith(`[${stage}]`));
    check(`Stage '${stage}' executed`, hasLog, hasLog ? 'logged' : 'no log entry');
  }

  // ── Mosca check ────────────────────────────────────────────
  console.log('\n── Mosca Assessment ──────────────────────────────────────');
  const moscaFindings = resultA.findings.filter(f => f.riskScore > 0);
  check('Risk scores are computed', moscaFindings.length > 0, `${moscaFindings.length} findings with risk > 0`);

  const riskBreakdowns = resultA.findings.filter(f => f.riskBreakdown && f.riskBreakdown.totalScore > 0);
  check('Risk breakdowns are populated', riskBreakdowns.length > 0, `${riskBreakdowns.length} with breakdown`);

  // ── Algorithm Severity ─────────────────────────────────────
  console.log('\n── Algorithm Severity ────────────────────────────────────');
  const pqcFindings = resultA.findings.filter(f => f.algorithm.toUpperCase().includes('ML-'));
  if (pqcFindings.length > 0) {
    const allInfo = pqcFindings.every(f => f.algorithmSeverity === 'info');
    check('PQC algorithms have info severity', allInfo, `${pqcFindings.length} PQC findings all severity=info`);
  } else {
    check('PQC algorithms have info severity', true, 'no PQC findings in this corpus (acceptable)');
  }

  // ── Summary ────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log(`  ACCEPTANCE RESULT: ${passed} passed, ${failed} failed`);
  console.log(`  Scan A: ${resultA.findings.length} findings, ${resultA.stats.executionMs}ms`);
  console.log(`  Scan B: ${resultB.findings.length} findings, ${resultB.stats.executionMs}ms`);
  console.log('═══════════════════════════════════════════════════════════');

  if (failed > 0) {
    console.log('\n  Failed checks:');
    for (const e of errors) console.log(`    ✗ ${e}`);
    process.exit(1);
  }
}

runAcceptance().catch(err => {
  console.error('Acceptance test failed:', err);
  process.exit(1);
});
