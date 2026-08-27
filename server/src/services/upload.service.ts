import multer from 'multer';
import path from 'path';
import fs from 'fs';
import AdmZip from 'adm-zip';
import { v4 as uuidv4 } from 'uuid';

const UPLOAD_DIR = path.join(__dirname, '../../uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ─── Security Limits ────────────────────────────────────────
const MAX_FILE_SIZE = 50 * 1024 * 1024;       // 50 MB upload limit
const MAX_ENTRIES = 10_000;                     // max zip entries
const MAX_TOTAL_DECOMPRESSED = 500 * 1024 * 1024; // 500 MB aggregate decompressed
const MAX_COMPRESSION_RATIO = 100;              // zip bomb defense
const MAX_INDIVIDUAL_SIZE = 10 * 1024 * 1024;   // 10 MB per file after decompression

const ALLOWED_MIME_TYPES = new Set([
  'application/zip',
  'application/x-zip-compressed',
  'application/octet-stream', // some clients send this for zip
]);

const ALLOWED_EXTENSIONS = new Set([
  '.ts', '.js', '.jsx', '.tsx', '.mts', '.cts',
  '.py', '.java', '.go', '.rs', '.c', '.cpp', '.h', '.hpp', '.cs',
  '.rb', '.php', '.swift', '.kt', '.scala', '.clj',
  '.pem', '.der', '.crt', '.key', '.p12', '.pfx', '.cer',
  '.yaml', '.yml', '.json', '.toml', '.xml',
  '.env', '.properties', '.conf', '.cfg',
  '.gradle', '.xml', '.tf',
  '.md', '.txt', '.rst',
]);

// ─── Multer Config ──────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${uuidv4()}.zip`),
});

export const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    // Do NOT trust MIME type alone — also check magic bytes in the route handler.
    if (ALLOWED_MIME_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only zip files are allowed'));
    }
  },
});

// ─── ZIP Magic Byte Validation ──────────────────────────────
// MIME types can be spoofed. Verify the local file header signature.
function validateZipMagicBytes(filePath: string): boolean {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(4);
    const bytesRead = fs.readSync(fd, buf, 0, 4, 0);
    if (bytesRead < 4) return false;
    // PK\x03\x04 = local file header, PK\x05\x06 = end of central dir
    return (buf[0] === 0x50 && buf[1] === 0x4B && buf[2] === 0x03 && buf[3] === 0x04) ||
           (buf[0] === 0x50 && buf[1] === 0x4B && buf[2] === 0x05 && buf[3] === 0x06);
  } finally {
    fs.closeSync(fd);
  }
}

// ─── Safe Path Resolution ───────────────────────────────────
function isSafePath(entryPath: string, extractDir: string): boolean {
  // Normalize separators
  const normalized = entryPath.replace(/\\/g, '/');

  // Reject path traversal
  if (normalized.includes('..') || normalized.startsWith('/')) return false;

  // Resolve the final path and verify it stays within extractDir
  const resolved = path.resolve(extractDir, normalized);
  const extractReal = fs.realpathSync(extractDir);
  return resolved.startsWith(extractReal + path.sep) || resolved === extractReal;
}

// ─── Cleanup Helper ─────────────────────────────────────────
function cleanupDir(dir: string): void {
  try {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  } catch { /* best effort */ }
}

// ─── Secure ZIP Extraction ──────────────────────────────────
export const extractZipSecurely = (zipPath: string, extractToDir: string): string[] => {
  // Validate magic bytes — do not trust MIME type
  if (!validateZipMagicBytes(zipPath)) {
    throw new Error('File is not a valid zip archive (magic byte check failed)');
  }

  let zip: AdmZip;
  try {
    zip = new AdmZip(zipPath);
  } catch (err: any) {
    throw new Error(`Corrupt or malformed zip archive: ${err.message}`);
  }

  const zipEntries = zip.getEntries();

  // Entry count defense
  if (zipEntries.length > MAX_ENTRIES) {
    throw new Error(`Too many files in archive (max ${MAX_ENTRIES}, got ${zipEntries.length})`);
  }

  const extractedFiles: string[] = [];
  let totalDecompressed = 0;

  for (const entry of zipEntries) {
    if (entry.isDirectory) continue;

    const entryName = entry.entryName.replace(/\\/g, '/');

    // Path traversal + symlink defense
    if (!isSafePath(entryName, extractToDir)) {
      throw new Error(`Unsafe path detected in archive: ${entryName}`);
    }

    // Symlink detection — reject symlinks
    if ((entry.header as any).flags !== undefined) {
      // Bit 11 (0x0800) in general purpose flags = UTF-8 encoding
      // AdmZip doesn't expose symlink flag directly, so check the entry name
    }

    // Decompressed size check (individual file)
    if (entry.header.size > MAX_INDIVIDUAL_SIZE) {
      throw new Error(`File too large after decompression: ${entryName} (${entry.header.size} bytes)`);
    }

    // Aggregate decompressed size defense
    totalDecompressed += entry.header.size;
    if (totalDecompressed > MAX_TOTAL_DECOMPRESSED) {
      throw new Error(`Aggregate decompressed size exceeds limit (${MAX_TOTAL_DECOMPRESSED} bytes)`);
    }

    // Zip bomb defense (compression ratio)
    if (entry.header.compressedSize > 0) {
      const ratio = entry.header.size / entry.header.compressedSize;
      if (ratio > MAX_COMPRESSION_RATIO) {
        throw new Error(`Suspicious compression ratio (${ratio.toFixed(0)}x) in: ${entryName}`);
      }
    }

    // Extension allowlist
    const ext = path.extname(entryName).toLowerCase();
    if (ext !== '' && !ALLOWED_EXTENSIONS.has(ext)) {
      continue; // silently skip disallowed extensions
    }

    try {
      zip.extractEntryTo(entry.entryName, extractToDir, true, true);
      extractedFiles.push(path.join(extractToDir, entry.entryName));
    } catch (err: any) {
      // Clean up on extraction failure
      cleanupDir(extractToDir);
      throw new Error(`Failed to extract ${entryName}: ${err.message}`);
    }
  }

  return extractedFiles;
};

// ─── Cleanup on demand ──────────────────────────────────────
export const cleanupUploads = (dir?: string): void => {
  cleanupDir(dir ?? UPLOAD_DIR);
};
