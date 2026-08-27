#!/usr/bin/env node

// ============================================================
// Qrypto Benchmark Harness
//
// Measures detection accuracy against a labelled corpus.
// Only publishes MEASURED results — never fabricated numbers.
//
// Methodology:
// 1. Scan each corpus file with the shared engine
// 2. Compare detected findings against expected labels
// 3. Compute precision, recall, F1, and scan duration
//
// Run: npx tsx benchmark/run.ts
// ============================================================

import fs from 'fs';
import path from 'path';
import { runScanPipeline, type PipelineFile } from '../shared/engine/pipeline.js';

// ─── Expected Labels ─────────────────────────────────────────
// Each label: { file, algorithm, category, quantumStatus, severity? }
// The scanner must detect at least one finding matching these criteria.

interface ExpectedLabel {
  file: string;
  algorithm: string;
  category: string;
  quantumStatus: string;
  /** If specified, severity must match exactly. Otherwise any severity is OK. */
  severity?: string;
}

const EXPECTED_LABELS: ExpectedLabel[] = [
  // Python
  { file: 'python_crypto.py', algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable' },
  { file: 'python_crypto.py', algorithm: 'ECC', category: 'public-key', quantumStatus: 'vulnerable' },
  { file: 'python_crypto.py', algorithm: 'AES', category: 'symmetric', quantumStatus: 'adequate' },
  { file: 'python_crypto.py', algorithm: 'SHA-256', category: 'hash', quantumStatus: 'adequate' },
  { file: 'python_crypto.py', algorithm: 'SHA-1', category: 'hash', quantumStatus: 'classical-weak' },
  { file: 'python_crypto.py', algorithm: 'MD5', category: 'hash', quantumStatus: 'classical-weak' },

  // JavaScript
  { file: 'js_crypto.js', algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable' },
  { file: 'js_crypto.js', algorithm: 'RSA', category: 'signature', quantumStatus: 'vulnerable' },
  { file: 'js_crypto.js', algorithm: 'AES', category: 'symmetric', quantumStatus: 'adequate' },
  { file: 'js_crypto.js', algorithm: 'SHA-256', category: 'hash', quantumStatus: 'adequate' },
  { file: 'js_crypto.js', algorithm: 'SHA-1', category: 'hash', quantumStatus: 'classical-weak' },
  { file: 'js_crypto.js', algorithm: 'MD5', category: 'hash', quantumStatus: 'classical-weak' },

  // Java
  { file: 'java_crypto.java', algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable' },
  { file: 'java_crypto.java', algorithm: 'ECDSA', category: 'signature', quantumStatus: 'vulnerable' },
  { file: 'java_crypto.java', algorithm: 'AES', category: 'symmetric', quantumStatus: 'adequate' },
  { file: 'java_crypto.java', algorithm: 'SHA-256', category: 'hash', quantumStatus: 'adequate' },
  { file: 'java_crypto.java', algorithm: 'MD5', category: 'hash', quantumStatus: 'classical-weak' },
  { file: 'java_crypto.java', algorithm: 'DES', category: 'symmetric', quantumStatus: 'classical-weak' },

  // Go
  { file: 'go/crypto.go', algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable' },
  { file: 'go/crypto.go', algorithm: 'ECDSA', category: 'signature', quantumStatus: 'vulnerable' },
  { file: 'go/crypto.go', algorithm: 'AES', category: 'symmetric', quantumStatus: 'adequate' },
  { file: 'go/crypto.go', algorithm: 'SHA-256', category: 'hash', quantumStatus: 'adequate' },
  { file: 'go/crypto.go', algorithm: 'SHA-1', category: 'hash', quantumStatus: 'classical-weak' },
  { file: 'go/crypto.go', algorithm: 'MD5', category: 'hash', quantumStatus: 'classical-weak' },

  // TypeScript (Web Crypto)
  { file: 'typescript/webcrypto.ts', algorithm: 'RSA', category: 'public-key', quantumStatus: 'vulnerable' },
  { file: 'typescript/webcrypto.ts', algorithm: 'ECDSA', category: 'signature', quantumStatus: 'vulnerable' },
  { file: 'typescript/webcrypto.ts', algorithm: 'AES', category: 'symmetric', quantumStatus: 'adequate' },
  { file: 'typescript/webcrypto.ts', algorithm: 'SHA-256', category: 'hash', quantumStatus: 'adequate' },
  { file: 'typescript/webcrypto.ts', algorithm: 'SHA-1', category: 'hash', quantumStatus: 'classical-weak' },
];

// ─── Corpus Loading ──────────────────────────────────────────

function loadCorpus(corpusDir: string): PipelineFile[] {
  const files: PipelineFile[] = [];

  function walk(dir: string, relativePath: string) {
    const entries = fs.readdirSync(dir);
    for (const entry of entries) {
      const fullPath = path.join(dir, entry);
      const stat = fs.statSync(fullPath);
      const relPath = relativePath ? `${relativePath}/${entry}` : entry;

      if (stat.isDirectory()) {
        walk(fullPath, relPath);
      } else if (stat.isFile()) {
        const content = fs.readFileSync(fullPath, 'utf-8');
        files.push({
          path: relPath,
          content,
          sizeBytes: stat.size,
        });
      }
    }
  }

  walk(corpusDir, '');
  return files;
}

// ─── Matching Logic ──────────────────────────────────────────

function matchesLabel(
  finding: { algorithm: string; category: string; quantumStatus: string; file: string },
  label: ExpectedLabel,
): boolean {
  // File must match
  if (finding.file !== label.file) return false;

  // Algorithm must be a substring match (case-insensitive)
  const algoMatch = finding.algorithm.toUpperCase().includes(label.algorithm.toUpperCase()) ||
                    label.algorithm.toUpperCase().includes(finding.algorithm.toUpperCase());
  if (!algoMatch) return false;

  // Category must match
  if (finding.category !== label.category) return false;

  // Quantum status must match
  if (finding.quantumStatus !== label.quantumStatus) return false;

  return true;
}

// ─── Benchmark Runner ────────────────────────────────────────

async function runBenchmark() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  QRYPTO BENCHMARK — Detection Accuracy Measurement');
  console.log('═══════════════════════════════════════════════════════════');
  console.log('');

  const corpusDir = path.join(import.meta.dirname ?? '.', 'corpus');
  const files = loadCorpus(corpusDir);

  console.log(`Corpus: ${files.length} file(s)`);
  console.log(`Labels: ${EXPECTED_LABELS.length} expected detection(s)`);
  console.log('');

  // Run the scan
  const startTime = Date.now();
  const result = await runScanPipeline(files, {
    repository: 'benchmark-corpus',
    project: 'benchmark',
  });
  const scanDurationMs = Date.now() - startTime;

  console.log(`Scan complete: ${result.findings.length} findings in ${scanDurationMs}ms`);
  console.log('');

  // Match findings against labels
  const truePositives: Array<{ label: ExpectedLabel; finding: any }> = [];
  const falseNegatives: ExpectedLabel[] = [];
  const matchedFindingIds = new Set<string>();

  for (const label of EXPECTED_LABELS) {
    const match = result.findings.find(f =>
      matchesLabel(f, label) && !matchedFindingIds.has(f.id)
    );

    if (match) {
      truePositives.push({ label, finding: match });
      matchedFindingIds.add(match.id);
    } else {
      falseNegatives.push(label);
    }
  }

  // False positives: findings not matched to any label
  // (we don't count all unmatched findings as false positives —
  // only those that don't match any label at all)
  const falsePositives = result.findings.filter(f => !matchedFindingIds.has(f.id));

  // Compute metrics
  const tp = truePositives.length;
  const fn = falseNegatives.length;
  const fp = falsePositives.length;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

  // Report
  console.log('─── Results ───────────────────────────────────────────────');
  console.log('');
  console.log(`  True Positives:   ${tp} / ${EXPECTED_LABELS.length} expected labels matched`);
  console.log(`  False Negatives:  ${fn} (expected but not detected)`);
  console.log(`  Extra Findings:   ${fp} (detected but not in expected labels — not necessarily wrong)`);
  console.log('');
  console.log(`  Precision:        ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall:           ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1 Score:         ${(f1 * 100).toFixed(1)}%`);
  console.log(`  Scan Duration:    ${scanDurationMs}ms`);
  console.log('');

  // Detail: matched labels
  console.log('─── Matched Labels ────────────────────────────────────────');
  for (const { label, finding } of truePositives) {
    console.log(`  ✓ ${label.file}: ${label.algorithm} (${label.category}) → ${finding.id} [${finding.severity}]`);
  }
  console.log('');

  // Detail: missed labels
  if (falseNegatives.length > 0) {
    console.log('─── Missed Labels ─────────────────────────────────────────');
    for (const label of falseNegatives) {
      console.log(`  ✗ ${label.file}: ${label.algorithm} (${label.category}) — NOT DETECTED`);
    }
    console.log('');
  }

  // Write results to JSON
  const results = {
    timestamp: new Date().toISOString(),
    corpus: {
      files: files.length,
      expectedLabels: EXPECTED_LABELS.length,
    },
    scan: {
      findingsTotal: result.findings.length,
      executionMs: scanDurationMs,
    },
    metrics: {
      truePositives: tp,
      falseNegatives: fn,
      falsePositives: fp,
      precision: Math.round(precision * 1000) / 1000,
      recall: Math.round(recall * 1000) / 1000,
      f1: Math.round(f1 * 1000) / 1000,
    },
    matched: truePositives.map(({ label, finding }) => ({
      expected: label,
      detected: { id: finding.id, algorithm: finding.algorithm, severity: finding.severity },
    })),
    missed: falseNegatives,
  };

  const resultsDir = path.join(import.meta.dirname ?? '.', 'results');
  if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });
  const resultsPath = path.join(resultsDir, `benchmark-${new Date().toISOString().slice(0, 10)}.json`);
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
  console.log(`Results written to ${resultsPath}`);

  console.log('');
  console.log('═══════════════════════════════════════════════════════════');
}

runBenchmark().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
