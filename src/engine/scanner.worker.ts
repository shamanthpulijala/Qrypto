// ============================================================
// Qrypto AI Advisor — Scanner Web Worker
//
// All heavy computation (ZIP extraction + pipeline) runs here,
// completely off the main thread. The UI thread stays responsive
// regardless of archive or project size.
//
// Message protocol (main → worker):
//   { type: 'START_SCAN', payload: WorkerScanRequest }
//
// Message protocol (worker → main):
//   { type: 'PROGRESS',  payload: WorkerProgressEvent }
//   { type: 'COMPLETE',  payload: WorkerCompleteEvent }
//   { type: 'ERROR',     payload: { message: string } }
// ============================================================

import JSZip from 'jszip';
import { runScanPipeline } from '../../shared/engine/pipeline';
import type { PipelineResult } from '../../shared/engine/pipeline';

// ─── Message Types ───────────────────────────────────────────

export interface WorkerScanRequest {
  /** Raw files passed as transferable File objects. */
  files: File[];
  /** Optional project name (e.g. from the ZIP filename). */
  projectName?: string;
  /** Repository identifier for findings. */
  repository?: string;
}

export interface WorkerProgressEvent {
  stage: string;
  progress: number;
  log: string;
}

export interface WorkerCompleteEvent {
  result: PipelineResult;
  projectName: string;
}

// ─── Helpers ─────────────────────────────────────────────────

const SUPPORTED_EXT = [
  '.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.c', '.cpp',
  '.h', '.hpp', '.cs', '.rb', '.php', '.swift', '.kt', '.scala', '.clj',
  '.yml', '.yaml', '.json', '.xml', '.sh', '.conf', '.cfg', '.ini',
  '.env', '.properties', '.gradle', '.toml', '.tf', '.lock',
  '.dockerfile', '.dockerignore', '.pem', '.key', '.crt', '.cer',
  '.p12', '.pfx', '.jks', '.der', '.p11', '.pkcs11',
  '.dll', '.so', '.dylib', '.exe', '.bin', '.obj', '.o', '.a',
  '.class', '.jar', '.war', '.ear',
  '.txt', '.md', '.rst', '.log', '.csv', '.sql',
];

const MAX_FILE_BYTES = 500 * 1024 * 1024; // 500 MB
const MAX_FILES = 2000;

function isSupported(relativePath: string): boolean {
  const lower = relativePath.toLowerCase();
  const baseName = lower.split('/').pop() ?? '';
  // Files without extension are often Dockerfiles, Makefiles, etc. — keep them
  if (!baseName.includes('.')) return true;
  // Dockerfile / compose by name
  if (baseName === 'dockerfile' || baseName.startsWith('docker-compose') || baseName.startsWith('compose')) return true;
  return SUPPORTED_EXT.some(ext => lower.endsWith(ext));
}

function emit(progress: number, stage: string, log: string) {
  const msg: { type: 'PROGRESS'; payload: WorkerProgressEvent } = {
    type: 'PROGRESS',
    payload: { stage, progress, log },
  };
  self.postMessage(msg);
}

// ─── ZIP Extraction ──────────────────────────────────────────

async function extractZip(
  file: File,
  projectNameOverride?: string,
): Promise<{ files: { path: string; content: string }[]; projectName: string }> {
  emit(5, 'extract', `Loading ZIP archive "${file.name}" (${(file.size / 1024 / 1024).toFixed(1)} MB)…`);

  const zip = await JSZip.loadAsync(file);
  const extractedFiles: { path: string; content: string }[] = [];
  
  // 1. Collect all valid entries first to prevent synchronous explosion
  const validEntries: { relativePath: string; zipEntry: JSZip.JSZipObject }[] = [];
  zip.forEach((relativePath, zipEntry) => {
    if (zipEntry.dir) return;
    if (relativePath.includes('..')) return; // security: prevent path traversal
    if (relativePath.includes('node_modules/') || relativePath.includes('.git/') || relativePath.includes('.next/')) return;
    if (!isSupported(relativePath)) return;
    validEntries.push({ relativePath, zipEntry });
  });

  // 2. Extract sequentially to bound memory and enforce MAX_FILES
  let count = 0;
  for (const { relativePath, zipEntry } of validEntries) {
    if (extractedFiles.length >= MAX_FILES) break;
    
    count++;
    if (count % 100 === 0) {
      emit(5, 'extract', `Extracting file ${count} of ${Math.min(validEntries.length, MAX_FILES)} from ZIP…`);
      await new Promise(resolve => setTimeout(resolve, 0));
    }

    try {
      const content = await zipEntry.async('string');
      extractedFiles.push({ path: relativePath, content });
    } catch {
      // Silently skip unreadable entries (encrypted, corrupt, etc.)
    }
  }

  emit(15, 'extract', `Extracted ${extractedFiles.length} file(s) from ZIP.`);

  const projectName = projectNameOverride ?? file.name.replace(/\.zip$/i, '');
  return { files: extractedFiles, projectName };
}

// ─── Plain File Reading ───────────────────────────────────────

async function readPlainFiles(
  fileList: File[],
): Promise<{ files: { path: string; content: string }[]; projectName: string }> {
  emit(5, 'extract', `Reading ${fileList.length} file(s)…`);

  const decoder = new TextDecoder('utf-8', { fatal: false });
  const results: { path: string; content: string }[] = [];

  let count = 0;
  for (const file of fileList) {
    count++;
    if (count % 250 === 0) {
      emit(5, 'extract', `Reading file ${count} of ${fileList.length}…`);
      // Yield to event loop
      await new Promise(resolve => setTimeout(resolve, 0));
    }

    const path = file.webkitRelativePath || file.name;
    if (path.includes('node_modules/') || path.includes('.git/') || path.includes('.next/')) continue;
    if (!isSupported(path)) continue;
    if (file.size > MAX_FILE_BYTES) continue;

    try {
      const buffer = await file.arrayBuffer();
      const content = decoder.decode(new Uint8Array(buffer)).replace(/\u0000/g, '');
      results.push({ path, content });
      if (results.length >= MAX_FILES) break;
    } catch {
      // ignore unreadable files
    }
  }

  emit(15, 'extract', `${results.length} file(s) ready for scanning.`);

  const projectName =
    fileList.length === 1
      ? fileList[0].name.replace(/\.\w+$/, '')
      : `${fileList.length} files`;

  return { files: results, projectName };
}

// ─── Worker Entry Point ──────────────────────────────────────

self.onmessage = async (event: MessageEvent<{ type: string; payload: WorkerScanRequest }>) => {
  if (event.data.type !== 'START_SCAN') return;

  const { files, projectName: requestedProjectName, repository = 'uploaded/repo' } = event.data.payload;

  try {
    // ── Step 1: Resolve files (ZIP or plain) ──────────────
    let pipelineFiles: { path: string; content: string }[];
    let resolvedProjectName: string;

    const zipFile = files.find(f => f.name.toLowerCase().endsWith('.zip'));

    if (zipFile) {
      const result = await extractZip(zipFile, requestedProjectName);
      pipelineFiles = result.files;
      resolvedProjectName = result.projectName;
    } else {
      const result = await readPlainFiles(files);
      pipelineFiles = result.files;
      resolvedProjectName = requestedProjectName ?? result.projectName;
    }

    if (pipelineFiles.length === 0) {
      throw new Error('No scannable files were found in the uploaded archive.');
    }

    // ── Step 2: Run the full scan pipeline ────────────────
    emit(20, 'pipeline', 'Starting cryptographic scan pipeline…');

    const pipelineResult = await runScanPipeline(pipelineFiles, {
      repository,
      project: resolvedProjectName,
      maxFileSizeBytes: 50 * 1024 * 1024,
      onProgress: (stage, progress, log) => {
        // Remap pipeline progress (0–100) into the 20–100 band
        // so the overall progress bar fills smoothly.
        const mapped = 20 + Math.round(progress * 0.8);
        emit(mapped, stage, log);
      },
    });

    // ── Step 3: Report completion ─────────────────────────
    const completeMsg: { type: 'COMPLETE'; payload: WorkerCompleteEvent } = {
      type: 'COMPLETE',
      payload: { result: pipelineResult, projectName: resolvedProjectName },
    };
    self.postMessage(completeMsg);
  } catch (err: any) {
    const errMsg: { type: 'ERROR'; payload: { message: string } } = {
      type: 'ERROR',
      payload: { message: err?.message ?? 'Unknown error in scanner worker.' },
    };
    self.postMessage(errMsg);
  }
};
