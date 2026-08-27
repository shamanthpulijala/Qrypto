// ============================================================
// Qrypto CLI — Scan Command
//
// Reads files from a local directory, runs the shared scan
// pipeline, and outputs results in the requested format.
//
// SECURITY: The scanned directory is treated as untrusted input.
// We read files but never execute them.
// ============================================================

import fs from 'fs';
import path from 'path';
import { runScanPipeline, type PipelineFile } from '../../../../shared/engine/pipeline.js';
import { generateCBOM, serializeCBOM } from '../../../../shared/engine/cbom.js';
import { runMoscaAssessment } from '../../../../shared/engine/mosca.js';
import { computeQuantumReadinessIndex } from '../../../../shared/engine/riskEngine.js';
import { formatJson, formatCsv, formatText } from '../utils/format.js';

// ─── Supported file extensions ───────────────────────────────

const SUPPORTED_EXTENSIONS = new Set([
  '.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go',
  '.yml', '.yaml', '.json', '.xml', '.sh', '.conf',
  '.env', '.properties', '.gradle', '.toml', '.tf',
  '.pem', '.crt', '.key', '.der',
]);

const MAX_FILE_SIZE = 1_000_000; // 1 MB
const MAX_FILES = 10_000;

// ─── Severity ranking for --fail-on ──────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// ─── File discovery ──────────────────────────────────────────

function discoverFiles(dirPath: string): PipelineFile[] {
  const files: PipelineFile[] = [];

  function walk(currentPath: string) {
    if (files.length >= MAX_FILES) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      return; // skip unreadable directories
    }

    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;

      const fullPath = path.join(currentPath, entry.name);

      // Skip hidden directories and node_modules
      if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist') {
        continue;
      }

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!SUPPORTED_EXTENSIONS.has(ext)) continue;

        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > MAX_FILE_SIZE) continue;
          if (stat.size === 0) continue;

          // Security: skip files with too many non-printable characters (binary check)
          const content = fs.readFileSync(fullPath, 'utf-8');
          const nonPrintable = (content.match(/[\x00-\x08\x0B-\x0C\x0E-\x1F]/g) || []).length;
          if (content.length > 0 && nonPrintable / content.length > 0.1) continue;

          const relativePath = path.relative(dirPath, fullPath).replace(/\\/g, '/');

          files.push({
            path: relativePath,
            content,
            sizeBytes: stat.size,
          });
        } catch {
          // skip unreadable files
        }
      }
    }
  }

  walk(dirPath);
  return files;
}

// ─── Main scan function ──────────────────────────────────────

export async function runScan(
  targetPath: string,
  options: {
    format?: string;
    failOn?: string;
    output?: string;
    confidenceFilter?: boolean;
    confidenceThreshold?: string;
    repository?: string;
    verbose?: boolean;
  }
): Promise<number> {
  const startTime = Date.now();

  // Validate path
  const resolvedPath = path.resolve(targetPath);
  if (!fs.existsSync(resolvedPath)) {
    console.error(`[qrypto] Path not found: ${resolvedPath}`);
    return 1;
  }

  const isFile = fs.statSync(resolvedPath).isFile();
  const scanDir = isFile ? path.dirname(resolvedPath) : resolvedPath;

  // Discover files
  if (options.verbose) {
    console.error(`[qrypto] Discovering files in ${scanDir}...`);
  }

  let files: PipelineFile[];
  if (isFile) {
    // Single file mode
    const content = fs.readFileSync(resolvedPath, 'utf-8');
    files = [{
      path: path.basename(resolvedPath),
      content,
      sizeBytes: Buffer.byteLength(content),
    }];
  } else {
    files = discoverFiles(scanDir);
  }

  if (files.length === 0) {
    console.error(`[qrypto] No scannable files found in ${resolvedPath}`);
    return 1;
  }

  if (options.verbose) {
    console.error(`[qrypto] Found ${files.length} scannable files`);
  }

  // Run the shared pipeline
  const repository = options.repository || path.basename(scanDir);
  const result = await runScanPipeline(files, {
    repository,
    project: repository,
    onProgress: options.verbose
      ? (_stage, _pct, msg) => console.error(`[qrypto] ${msg}`)
      : undefined,
  });

  let findings = result.findings;

  // Apply confidence filter
  const threshold = parseFloat(options.confidenceThreshold || '0.70');
  if (options.confidenceFilter !== false) {
    findings = findings.filter(f => f.confidence >= threshold);
  }

  // Run Mosca assessment
  const mosca = runMoscaAssessment(findings);
  const readiness = computeQuantumReadinessIndex(findings);

  const executionTime = Date.now() - startTime;

  // Build output
  const output = {
    scan: {
      repository,
      path: resolvedPath,
      filesScanned: result.stats.filesScanned,
      linesScanned: result.stats.linesScanned,
      findingsTotal: findings.length,
      executionMs: executionTime,
    },
    findings,
    mosca,
    readiness,
  };

  // Format output
  const format = options.format || 'text';
  let formatted: string;

  switch (format) {
    case 'json':
      formatted = formatJson(output);
      break;
    case 'csv':
      formatted = formatCsv(findings);
      break;
    case 'cbom':
      const bom = generateCBOM(findings, { projectName: repository });
      formatted = serializeCBOM(bom);
      break;
    case 'text':
    default:
      formatted = formatText(output);
      break;
  }

  // Write output
  if (options.output) {
    fs.writeFileSync(options.output, formatted, 'utf-8');
    if (options.verbose) {
      console.error(`[qrypto] Output written to ${options.output}`);
    }
  } else {
    process.stdout.write(formatted + '\n');
  }

  // Print summary to stderr (so it doesn't mix with piped output)
  console.error(`[qrypto] Scan complete: ${findings.length} findings in ${executionTime}ms`);
  console.error(`[qrypto] Readiness: ${readiness.overall}/100`);
  if (mosca.summary.atRiskCount > 0) {
    console.error(`[qrypto] Mosca: ${mosca.summary.atRiskCount} finding(s) at risk (X + Y > Z)`);
  }

  // Policy check
  if (options.failOn) {
    const failThreshold = SEVERITY_RANK[options.failOn.toLowerCase()];
    if (failThreshold === undefined) {
      console.error(`[qrypto] Invalid --fail-on value: ${options.failOn}. Use: critical, high, medium, low`);
      return 1;
    }

    const violatingFindings = findings.filter(f => {
      const rank = SEVERITY_RANK[f.severity] ?? 0;
      return rank >= failThreshold;
    });

    if (violatingFindings.length > 0) {
      console.error(`[qrypto] POLICY VIOLATION: ${violatingFindings.length} finding(s) meet or exceed ${options.failOn} severity`);
      return 2;
    }
  }

  return 0;
}
