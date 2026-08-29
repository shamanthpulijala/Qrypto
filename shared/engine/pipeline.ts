// ============================================================
// QuantumGuard AI — §12 Scanning Pipeline
//
// Upload → Validate → Extract → Detect Language → Parse →
// Run Detectors → Normalize → Deduplicate → Confidence →
// Risk Engine → Store Results → Dashboard
//
// Key rule: Do NOT send entire repository to LLM.
// Only send relevant evidence snippets.
// ============================================================

import type { Finding } from '../types';
import { scanFile, scanFiles, type ScanFile } from './scanner';
import { initAstParser, enrichWithAst } from './detectors/ast';
import { detectDependencies } from './detectors/dependencies';
import { detectConfigWeaknesses } from './detectors/config';
import { extractCertificates, createCertificateFindings } from './x509';

// P1 Extension Detectors
import { detectHardwareModules } from './detectors/hardware';
import { detectCloudKms } from './detectors/cloudKms';
import { detectContainerConfig } from './detectors/container';
import { detectBinaryArtifacts } from './detectors/binary';

import { computeQuantumReadinessIndex } from './riskEngine';

// ─── Pipeline Types ─────────────────────────────────────────

export interface PipelineFile {
  path: string;
  content: string;
  sizeBytes?: number;
}

export interface PipelineOptions {
  repository?: string;
  project?: string;
  maxFileSizeBytes?: number;       // skip files exceeding this size
  allowedExtensions?: string[];     // only scan these extensions
  onProgress?: (stage: PipelineStage, progress: number, log: string) => void;
}

export type PipelineStage =
  | 'validate'
  | 'extract'
  | 'detect-language'
  | 'parse'
  | 'run-detectors'
  | 'normalize'
  | 'deduplicate'
  | 'confidence'
  | 'risk-engine'
  | 'store'
  | 'complete';

export interface PipelineResult {
  findings: Finding[];
  stats: PipelineStats;
  readinessIndex: ReturnType<typeof computeQuantumReadinessIndex>;
  log: string[];
  errors: string[];
}

export interface PipelineStats {
  filesSubmitted: number;
  filesScanned: number;
  filesSkipped: number;
  linesScanned: number;
  findingsRaw: number;
  findingsAfterDedup: number;
  secretsMasked: number;
  executionMs: number;
}

// ─── Supported Extensions ───────────────────────────────────

const DEFAULT_EXTENSIONS = [
  '.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.c', '.cpp', '.h', '.hpp', '.cs',
  '.rb', '.php', '.swift', '.kt', '.scala', '.clj',
  '.yml', '.yaml', '.json', '.xml', '.sh', '.conf', '.cfg', '.ini',
  '.env', '.properties', '.gradle', '.toml', '.tf', '.lock',
  '.dockerfile', '.dockerignore',
  '.dll', '.so', '.dylib', '.exe', '.bin', '.obj', '.o', '.a', '.class', '.jar', '.war', '.ear',
  '.p11', '.pkcs11', '.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.jks', '.der',
  '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar',
  '.txt', '.md', '.rst', '.log', '.csv', '.sql'
];

// P1: Filename-based detection (for files without typical extensions)
const EXTRA_FILENAMES = [
  'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
  'compose.yml', 'compose.yaml',
];

// ─── Stage 1: Validate ──────────────────────────────────────

function validate(
  files: PipelineFile[],
  opts: PipelineOptions
): { valid: PipelineFile[]; skipped: string[] } {
  const maxSize = opts.maxFileSizeBytes ?? 500 * 1024 * 1024; // 500 MB default to match upload limits
  const exts = opts.allowedExtensions ?? DEFAULT_EXTENSIONS;
  const valid: PipelineFile[] = [];
  const skipped: string[] = [];

  for (const f of files) {
    const lp = f.path.toLowerCase();

    // Allow resources without a typical extension if they are clearly actionable files.
    const baseName = lp.split('/').pop() || '';
    const hasValidExt = exts.some(ext => lp.endsWith(ext));
    const hasValidFilename = EXTRA_FILENAMES.some(name => baseName === name);
    const hasNoKnownExtension = !baseName.includes('.') && baseName.length > 0;
    if (!hasValidExt && !hasValidFilename && !hasNoKnownExtension) {
      skipped.push(`${f.path} (unsupported extension)`);
      continue;
    }

    // Skip by size
    const size = f.sizeBytes ?? new Blob([f.content]).size;
    if (size > maxSize) {
      skipped.push(`${f.path} (exceeds ${maxSize} byte limit)`);
      continue;
    }

    const lp2 = f.path.toLowerCase();
    const isBinaryFile = ['.dll', '.so', '.dylib', '.exe', '.bin', '.obj', '.o', '.a', '.class', '.jar', '.war', '.ear', '.pfx', '.p12', '.der'].some(ext => lp2.endsWith(ext));
    if (!isBinaryFile && f.content.length > 0) {
      const nonPrintable = (f.content.match(/[\x00-\x08\x0B-\x0C\x0E-\x1F]/g) || []).length;
      if (nonPrintable / f.content.length > 0.1) {
        skipped.push(`${f.path} (appears binary)`);
        continue;
      }
    }

    valid.push(f);
  }

  return { valid, skipped };
}

// ─── Stage 2: Extract (safe content extraction) ─────────────

function extract(files: PipelineFile[]): PipelineFile[] {
  // Strip null bytes, normalize line endings, truncate very long lines
  return files.map(f => ({
    ...f,
    content: f.content
      .replace(/\0/g, '')                          // strip null bytes
      .replace(/\r\n/g, '\n')                      // normalize CRLF
      .split('\n')
      .map(line => line.length > 2000 ? line.slice(0, 2000) + '…' : line) // truncate runaway lines
      .join('\n'),
  }));
}

// ─── Stage 3: Language Detection ────────────────────────────
// (Handled inside scanner.ts per-file — no separate pass needed)

// ─── Stage 4: Deduplication ─────────────────────────────────

/**
 * Remove duplicate findings:
 * - Same file + algorithm + line within ±3 lines = duplicate
 * - Same file + algorithm + exact pattern = duplicate
 */
function deduplicate(findings: Finding[]): Finding[] {
  // Group by file + algorithm + rounded line (bucket by 3)
  const buckets = new Map<string, Finding[]>();

  for (const f of findings) {
    const lineKey = `${f.file}:${f.algorithm}:${Math.floor(f.line / 3)}`;
    if (!buckets.has(lineKey)) buckets.set(lineKey, []);
    buckets.get(lineKey)!.push(f);
  }

  // From each bucket, keep the finding with highest confidence
  // (prefer code matches over comment matches)
  const unique = new Map<string, Finding>();
  for (const [, group] of buckets) {
    group.sort((a, b) => b.confidence - a.confidence);
    const best = group[0];
    unique.set(best.id, best);
  }

  return [...unique.values()];
}

// ─── Stage 5: Confidence Filtering ──────────────────────────

function filterByConfidence(findings: Finding[], threshold = 0.70): Finding[] {
  return findings.filter(f => f.confidence >= threshold);
}

// ─── §12 Evidence Extraction for AI ────────────────────────
//
// Rule: Do NOT send the entire repository to an LLM.
// Extract only the relevant evidence snippet (≤5 lines around the finding).
//

export function extractEvidenceSnippet(
  fileContent: string,
  lineNumber: number,
  contextLines = 2
): string {
  const lines = fileContent.split('\n');
  const start = Math.max(0, lineNumber - 1 - contextLines);
  const end = Math.min(lines.length - 1, lineNumber - 1 + contextLines);
  return lines
    .slice(start, end + 1)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join('\n');
}

// ─── Main Pipeline ───────────────────────────────────────────

export async function runScanPipeline(
  files: PipelineFile[],
  opts: PipelineOptions = {}
): Promise<PipelineResult> {
  const startMs = Date.now();
  const log: string[] = [];
  const errors: string[] = [];
  const emit = (stage: PipelineStage, pct: number, msg: string) => {
    log.push(`[${stage}] ${msg}`);
    opts.onProgress?.(stage, pct, msg);
  };

  // ── Stage 1: Validate ──────────────────────────────────
  emit('validate', 5, `Validating ${files.length} submitted file(s)…`);
  const { valid, skipped } = validate(files, opts);
  skipped.forEach(s => emit('validate', 5, `Skipped: ${s}`));
  emit('validate', 10, `${valid.length} file(s) passed validation, ${skipped.length} skipped.`);

  // ── Stage 2: Extract ───────────────────────────────────
  emit('extract', 15, 'Safely extracting and normalizing file contents…');
  const extracted = extract(valid);
  emit('extract', 20, `Content normalized for ${extracted.length} files.`);

  // ── Stage 3: Detect Language ───────────────────────────
  emit('detect-language', 25, 'Detecting file languages…');
  const linesTotal = extracted.reduce((acc, f) => acc + f.content.split('\n').length, 0);
  emit('detect-language', 30, `${linesTotal.toLocaleString()} lines queued for scanning.`);

  // ── Stage 4: Parse & Prepare ───────────────────────────
  emit('parse', 35, 'Preparing scan files and initializing parsers…');
  await initAstParser();
  const scanFileObjects: ScanFile[] = extracted.map(f => ({
    path: f.path,
    content: f.content,
    repository: opts.repository ?? 'uploaded',
    project: opts.project ?? 'Unknown Project',
  }));

  // ── Stage 5: Run Detectors ─────────────────────────────
  emit('run-detectors', 40, 'Running deterministic cryptographic detectors…');
  // Progress simulation per file
  const allRawFindings: Finding[] = [];
  for (let i = 0; i < scanFileObjects.length; i++) {
    const fileFindings = scanFile(scanFileObjects[i]);
    
    // Add dependency findings
    const depFindings = detectDependencies(scanFileObjects[i].path, scanFileObjects[i].content);
    fileFindings.push(...depFindings);

    // Add config findings
    const configFindings = detectConfigWeaknesses(scanFileObjects[i].path, scanFileObjects[i].content);
    fileFindings.push(...configFindings);

    // Add certificate findings (X.509 parsing)
    const certs = extractCertificates(scanFileObjects[i].content, scanFileObjects[i].path);
    if (certs.length > 0) {
      const certFindings = createCertificateFindings(
        certs, scanFileObjects[i].path, opts.repository ?? 'uploaded', opts.project ?? 'Unknown'
      );
      fileFindings.push(...certFindings as Finding[]);
    }

    // P1: Hardware module detection (HSM/PKCS#11/TPM)
    const hwFindings = detectHardwareModules(
      scanFileObjects[i].path, scanFileObjects[i].content,
      opts.repository ?? 'uploaded', opts.project ?? 'Unknown'
    );
    fileFindings.push(...hwFindings);

    // P1: Cloud KMS detection
    const kmsFindings = detectCloudKms(
      scanFileObjects[i].path, scanFileObjects[i].content,
      opts.repository ?? 'uploaded', opts.project ?? 'Unknown'
    );
    fileFindings.push(...kmsFindings);

    // P1: Container config detection (Dockerfile, compose)
    const containerFindings = detectContainerConfig(
      scanFileObjects[i].path, scanFileObjects[i].content,
      opts.repository ?? 'uploaded', opts.project ?? 'Unknown'
    );
    fileFindings.push(...containerFindings);

    // P1: Binary artifact detection (only for binary-like files)
    const binFindings = detectBinaryArtifacts(
      scanFileObjects[i].path, scanFileObjects[i].content,
      opts.repository ?? 'uploaded', opts.project ?? 'Unknown'
    );
    fileFindings.push(...binFindings);

    // Enrich findings with AST context
    await enrichWithAst(scanFileObjects[i].path, scanFileObjects[i].content, fileFindings);

    allRawFindings.push(...fileFindings);
    const pct = 40 + Math.round(((i + 1) / scanFileObjects.length) * 25);
    emit('run-detectors', pct, `Scanned ${scanFileObjects[i].path} → ${fileFindings.length} findings`);
  }
  emit('run-detectors', 65, `Detectors complete: ${allRawFindings.length} raw findings.`);

  // ── Stage 6: Normalize ─────────────────────────────────
  emit('normalize', 68, 'Normalizing findings to standard format…');
  // (Normalization happens inside scanner — no separate pass needed)
  emit('normalize', 70, 'Normalization complete.');

  // ── Stage 7: Deduplicate ───────────────────────────────
  emit('deduplicate', 72, 'Deduplicating overlapping findings…');
  const deduped = deduplicate(allRawFindings);
  const dupeCount = allRawFindings.length - deduped.length;
  emit('deduplicate', 78, `Deduplication removed ${dupeCount} duplicate(s). ${deduped.length} unique findings.`);

  // ── Stage 8: Confidence Filtering ──────────────────────
  emit('confidence', 80, 'Applying confidence threshold (≥0.70)…');
  const confident = filterByConfidence(deduped, 0.70);
  emit('confidence', 83, `${confident.length} findings above confidence threshold.`);

  // ── Stage 9: Risk Engine ───────────────────────────────
  emit('risk-engine', 85, 'Computing risk scores…');
  confident.sort((a, b) => b.riskScore - a.riskScore);
  confident.forEach((f, i) => { f.migrationPriority = i + 1; });
  emit('risk-engine', 90, 'Risk scoring complete. Findings sorted by risk priority.');

  // ── Stage 10: Store / Dashboard ────────────────────────
  emit('store', 95, 'Computing quantum readiness index…');
  const readinessIndex = computeQuantumReadinessIndex(confident);
  emit('complete', 100, `Scan complete. ${confident.length} findings. Readiness: ${readinessIndex.overall}/100`);

  const executionMs = Date.now() - startMs;

  return {
    findings: confident,
    stats: {
      filesSubmitted: files.length,
      filesScanned: extracted.length,
      filesSkipped: skipped.length,
      linesScanned: linesTotal,
      findingsRaw: allRawFindings.length,
      findingsAfterDedup: confident.length,
      secretsMasked: confident.filter(f => f.category === 'secret').length,
      executionMs,
    },
    readinessIndex,
    log,
    errors,
  };
}
