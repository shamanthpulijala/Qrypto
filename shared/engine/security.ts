// ============================================================
// Qrypto AI Advisor — §20 Security & Safety Controls
//
// Cybersecurity product safety rules:
// - Path traversal protection
// - File size limits & type filtering
// - Secret masking
// - Input validation & HTML escaping
// - Client-side AI rate limiting
// - Uploaded code analyzed ONLY as static data (NO execution)
// ============================================================

// ─── File Upload Limits ──────────────────────────────────────

export const MAX_FILE_SIZE_BYTES = 1_048_576; // 1 MB per file
export const MAX_TOTAL_UPLOAD_BYTES = 10_485_760; // 10 MB total

export const ALLOWED_EXTENSIONS = new Set([
  '.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go',
  '.yml', '.yaml', '.json', '.xml', '.sh', '.conf',
  '.env', '.properties', '.gradle', '.toml', '.tf', '.txt',
]);

// ─── Path Traversal Protection ───────────────────────────────

/**
 * Sanitizes file paths to prevent directory traversal attacks (e.g. ../../etc/passwd)
 */
export function sanitizeFilePath(rawPath: string): string {
  if (!rawPath) return 'unnamed_file.txt';

  // Normalize backslashes to forward slashes
  let clean = rawPath.replace(/\\/g, '/');

  // Strip leading slashes and drive letters (e.g. C:/)
  clean = clean.replace(/^[a-zA-Z]:\//, '').replace(/^\/+/, '');

  // Strip tilde home-dir prefix
  clean = clean.replace(/^~\//, '');

  // Remove unsafe control characters
  clean = clean.replace(/[\x00-\x1F\x7F]/g, '');

  // Iteratively remove path traversal sequences until the string is stable.
  // A single pass can leave residuals like /../ if the input is ../../
  let prev = '';
  while (prev !== clean) {
    prev = clean;
    clean = clean.replace(/(^|\/)\.\.(\.|\/|$)/g, '$1');
    // Remove any remaining double-dots that ended up adjacent to slashes
    clean = clean.replace(/\/\.\.$/g, '');
    // Collapse double slashes
    clean = clean.replace(/\/\//g, '/');
    // Strip leading slashes again (may be exposed after removal)
    clean = clean.replace(/^\/+/, '');
  }

  // Final safety: if the path still contains '..', reject it entirely
  if (clean.includes('..')) {
    return 'unsafe_path_rejected.txt';
  }

  return clean || 'unnamed_file.txt';
}

// ─── File Validation ─────────────────────────────────────────

export interface FileValidationResult {
  valid: boolean;
  error?: string;
  sanitizedPath: string;
}

export function validateUploadedFile(file: { path: string; content: string }): FileValidationResult {
  const sanitizedPath = sanitizeFilePath(file.path);
  const ext = '.' + (sanitizedPath.split('.').pop()?.toLowerCase() ?? '');

  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return {
      valid: false,
      error: `File extension '${ext}' is not supported for scanning. Allowed: ${[...ALLOWED_EXTENSIONS].slice(0, 8).join(', ')}...`,
      sanitizedPath,
    };
  }

  const size = new Blob([file.content]).size;
  if (size > MAX_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: `File '${sanitizedPath}' exceeds maximum file size limit of 1 MB (${(size / 1024 / 1024).toFixed(2)} MB).`,
      sanitizedPath,
    };
  }

  return { valid: true, sanitizedPath };
}

// ─── Secret Masking ──────────────────────────────────────────

/**
 * Masks sensitive values in findings or display snippets
 */
export function maskSecretValue(value: string): string {
  if (!value) return '****';
  const trimmed = value.trim();
  if (trimmed.length <= 8) return '****';
  return `${trimmed.slice(0, 4)}****${trimmed.slice(-4)}`;
}

// ─── HTML Output Escaping ────────────────────────────────────

/**
 * Escapes unsafe HTML characters to prevent XSS vulnerabilities in rendered output
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── Client-Side AI Rate Limiting ─────────────────────────────

class RateLimiter {
  private timestamps: number[] = [];
  private readonly maxCalls: number;
  private readonly windowMs: number;

  constructor(maxCalls = 10, windowMs = 60_000) {
    this.maxCalls = maxCalls;
    this.windowMs = windowMs;
  }

  canMakeCall(): { allowed: boolean; retryAfterSec?: number } {
    const now = Date.now();
    this.timestamps = this.timestamps.filter(t => now - t < this.windowMs);

    if (this.timestamps.length >= this.maxCalls) {
      const oldest = this.timestamps[0];
      const retryAfterSec = Math.ceil((this.windowMs - (now - oldest)) / 1000);
      return { allowed: false, retryAfterSec };
    }

    this.timestamps.push(now);
    return { allowed: true };
  }
}

export const aiRateLimiter = new RateLimiter(10, 60_000); // max 10 AI calls per minute
