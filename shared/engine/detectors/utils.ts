// ============================================================
// Qrypto — Shared Detector Utilities
//
// Extracted from individual detectors to eliminate DRY violations.
// These functions are used by hardware, cloudKms, and container detectors.
// ============================================================

/**
 * Check if a match at the given index is inside a comment or standalone string.
 * Strings used as API arguments (e.g. name: 'RSA-OAEP') are NOT treated as
 * documentation — they are legitimate code.
 */
export function isCommentOrDoc(content: string, matchIndex: number): boolean {
  const lineStart = content.lastIndexOf('\n', matchIndex);
  const lineEnd = content.indexOf('\n', matchIndex + 1);
  const line = content.slice(lineStart + 1, lineEnd === -1 ? content.length : lineEnd).trim();

  // Lines starting with comment markers
  if (/^(\/\/|#|\/\*|\*|<!--)/.test(line)) return true;

  // Check if match is inside a string
  const before = content.slice(Math.max(0, matchIndex - 200), matchIndex);
  const quoteCount = (before.match(/"/g) || []).length;
  if (quoteCount % 2 === 1) {
    // Inside a string — check if it's a standalone string (documentation)
    // vs a string value in code (e.g. algorithm: 'RSA')
    const lastLineBreak = before.lastIndexOf('\n');
    const currentLine = before.slice(lastLineBreak + 1);
    // Code indicators: colon, equals, opening paren before the quote
    if (/[:=,(]\s*['"]/.test(currentLine)) return false; // string value in code = real usage
    return true; // standalone string = likely documentation
  }

  return false;
}

/**
 * Check if a file path suggests test, vendor, fixture, or generated code.
 * Findings in these paths get lower confidence.
 */
export function isTestOrVendorPath(filePath: string): boolean {
  return /(?:test|tests|__tests__|spec|specs|mock|mocks|fixture|fixtures|vendor|node_modules|__mocks__|\.test\.|\.spec\.|generated|dist\/)/i.test(filePath);
}

/**
 * Dependency manifest / lockfile detection.
 *
 * Used to gate `package-dependency` evidence: a package name appearing in a
 * manifest is a dependency declaration. The same string appearing in arbitrary
 * source or prose is not, and must not be reported as one.
 */
const MANIFEST_FILENAMES = new Set([
  'package.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'requirements.txt',
  'requirements-dev.txt',
  'pipfile',
  'pipfile.lock',
  'pyproject.toml',
  'poetry.lock',
  'setup.py',
  'setup.cfg',
  'go.mod',
  'go.sum',
  'cargo.toml',
  'cargo.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'gemfile',
  'gemfile.lock',
  'composer.json',
  'composer.lock',
  'packages.config',
]);

export function isDependencyManifest(filePath: string): boolean {
  const base = filePath.replace(/\\/g, '/').split('/').pop()?.toLowerCase() ?? '';
  if (MANIFEST_FILENAMES.has(base)) return true;
  return /\.(?:csproj|fsproj|vbproj)$/i.test(base);
}

/**
 * Deterministic finding fingerprint — stable across rescans.
 *
 * Deliberately excludes the line number so that inserting a line above a
 * finding does not resurrect a suppressed one. This is the single
 * implementation used by every finding producer in the engine; do not fork it.
 */
export function generateFindingFingerprint(
  repository: string,
  filePath: string,
  algorithm: string,
  usage: string,
  detectedPattern: string
): string {
  const norm = (s: string) => s.toLowerCase().replace(/\s+/g, ' ').replace(/\\/g, '/').trim();
  const normalizedPath = norm(filePath);
  const normalizedPattern = norm(detectedPattern).slice(0, 80); // cap length
  const normalizedRepo = norm(repository);

  const payload = `${normalizedRepo}:${normalizedPath}:${norm(algorithm)}:${norm(usage)}:${normalizedPattern}`;

  // Deterministic string hash (cross-platform, no dependencies)
  let hash = 0;
  for (let i = 0; i < payload.length; i++) {
    const char = payload.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return `fp-${Math.abs(hash).toString(16).padStart(8, '0')}`;
}

/**
 * Deterministic finding id.
 *
 * Replaces `Math.random()` id generation. A random id makes rescan
 * continuity impossible: the same finding gets a new identity on every run,
 * so it can never be upserted, suppressed, or tracked as resolved.
 * The line number IS included here (unlike the fingerprint) so that two
 * distinct occurrences in one file remain distinct rows.
 */
export function stableFindingId(prefix: string, ...parts: (string | number | undefined)[]): string {
  const payload = parts.map(p => String(p ?? '')).join('|').toLowerCase();
  let hash = 5381;
  for (let i = 0; i < payload.length; i++) {
    hash = ((hash << 5) + hash + payload.charCodeAt(i)) | 0;
  }
  return `${prefix}-${Math.abs(hash).toString(36).padStart(7, '0')}`;
}
