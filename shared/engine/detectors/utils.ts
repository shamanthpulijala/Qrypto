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
