// ============================================================
// QuantumGuard AI — AI Code Remediation Generator
// ============================================================

import { GoogleGenerativeAI } from '@google/generative-ai';
import type { Finding } from '../types';

export interface RemediationResult {
  currentCode: string;
  suggestedCode: string;
  explanation: string;
  migrationNotes: string[];
  requiredDependencies: string[];
  testRequirements: string[];
  label: string;
  diff: string;
}

// Built-in deterministic remediation examples (no AI needed for common cases)
const BUILTIN_REMEDIATIONS: Record<string, Partial<RemediationResult>> = {
  'MD5': {
    currentCode: `import hashlib\ndigest = hashlib.md5(data).hexdigest()`,
    suggestedCode: `import hashlib\ndigest = hashlib.sha256(data).hexdigest()`,
    explanation: 'MD5 is cryptographically broken and should not be used for any security-sensitive purpose. SHA-256 provides sufficient security for most use cases.',
    migrationNotes: [
      'SHA-256 output is 64 hex characters vs 32 for MD5 — update any storage/comparison logic',
      'If used for password hashing, use Argon2 or bcrypt instead',
      'If used for non-security checksums only, SHA-256 is safe to substitute',
    ],
    requiredDependencies: ['hashlib (standard library)'],
    testRequirements: ['Update expected hash values in tests', 'Verify output length expectations'],
  },
  'SHA-1': {
    currentCode: `import hashlib\ndigest = hashlib.sha1(data).hexdigest()`,
    suggestedCode: `import hashlib\ndigest = hashlib.sha256(data).hexdigest()`,
    explanation: 'SHA-1 has known collision vulnerabilities (SHAttered attack, 2017). Replace with SHA-256 or SHA-3.',
    migrationNotes: [
      'SHA-256 output is 64 hex characters vs 40 for SHA-1',
      'Check for protocol constraints — some legacy systems may require SHA-1',
    ],
    requiredDependencies: ['hashlib (standard library)'],
    testRequirements: ['Update expected hash values in tests'],
  },
  'DES': {
    currentCode: `from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)`,
    suggestedCode: `from Crypto.Cipher import AES\n# Use AES-256-GCM for authenticated encryption\ncipher = AES.new(key_256bit, AES.MODE_GCM)\nciphertext, tag = cipher.encrypt_and_digest(plaintext)`,
    explanation: 'DES (56-bit key) is cryptographically broken by modern standards. Replace with AES-256-GCM for authenticated encryption.',
    migrationNotes: [
      'AES requires a 256-bit (32-byte) key — rotate and replace the existing DES key',
      'AES-GCM provides both confidentiality and integrity (authenticated encryption)',
      'Data encrypted with DES must be re-encrypted after migration',
    ],
    requiredDependencies: ['pycryptodome or cryptography library'],
    testRequirements: ['Verify encryption/decryption round-trip', 'Validate ciphertext and tag handling'],
  },
  '3DES': {
    currentCode: `javax.crypto.Cipher.getInstance("DESede/CBC/PKCS5Padding")`,
    suggestedCode: `javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")`,
    explanation: '3DES is vulnerable to the Sweet32 birthday attack at 64-bit block sizes. AES-256-GCM is the recommended replacement.',
    migrationNotes: [
      'Update key length to 256 bits (32 bytes)',
      'GCM mode provides authenticated encryption — handle the authentication tag',
      'Re-encrypt existing data after migration',
    ],
    requiredDependencies: ['Java Cryptography Architecture (JCA) — included in JDK'],
    testRequirements: ['Test encryption/decryption with new key size', 'Validate GCM tag verification'],
  },
  'TLS 1.0': {
    currentCode: `ssl_context.minimum_version = ssl.TLSVersion.TLSv1`,
    suggestedCode: `ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3\n# If TLS 1.3 is not universally available:\n# ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2`,
    explanation: 'TLS 1.0 is deprecated by RFC 8996 and vulnerable to attacks including BEAST and POODLE. Enforce TLS 1.3 (minimum TLS 1.2).',
    migrationNotes: [
      'Test with all client environments before enforcing TLS 1.3',
      'TLS 1.3 removes weak cipher suites automatically',
      'Monitor for compatibility issues with legacy clients',
    ],
    requiredDependencies: ['Python ssl module (standard library)'],
    testRequirements: ['Verify handshake succeeds with TLS 1.3', 'Test that TLS 1.0/1.1 connections are rejected'],
  },
  'SHA1withRSA': {
    currentCode: `Signature sig = Signature.getInstance("SHA1withRSA");`,
    suggestedCode: `// For classical security only:\nSignature sig = Signature.getInstance("SHA256withRSA");\n\n// For post-quantum migration planning:\n// Evaluate ML-DSA (FIPS 204) when available in your environment`,
    explanation: 'SHA1withRSA combines a weak hash (SHA-1) with RSA signatures. This is flagged by modern certificate authorities and compliance frameworks.',
    migrationNotes: [
      'SHA256withRSA is a classical improvement; RSA itself remains quantum-vulnerable',
      'For long-term security, plan migration to ML-DSA (CRYSTALS-Dilithium) per FIPS 204',
      'Certificate re-issuance may be required if this is used in X.509 certificates',
    ],
    requiredDependencies: ['Java Cryptography Architecture (JCA) — included in JDK'],
    testRequirements: ['Verify signature creation and verification', 'Test certificate chain validation if applicable'],
  },
};

function buildRemediationPrompt(finding: Finding): string {
  return `You are a cryptographic security engineer generating migration guidance for QuantumGuard AI.

FINDING:
  ID: ${finding.id}
  Algorithm: ${finding.algorithm}${finding.keySize ? ` (${finding.keySize}-bit)` : ''}
  Category: ${finding.category}
  Usage: ${finding.usage}
  File: ${finding.file}
  Language: ${finding.language}
  Quantum Status: ${finding.quantumStatus}
  Severity: ${finding.severity}
  Service: ${finding.service}
  Detected Pattern: ${finding.detectedPattern}
  Recommended Algorithm: ${finding.recommendedAlgorithm || 'See migration strategy'}
  Migration Strategy: ${finding.migrationStrategy || 'Evaluate usage context'}

TASK:
Generate a concise, technically accurate migration example for this finding.

REQUIRED OUTPUT FORMAT (JSON only, no markdown wrapper):
{
  "currentCode": "snippet showing the current pattern (5-10 lines max)",
  "suggestedCode": "snippet showing the recommended replacement (5-10 lines max)",
  "explanation": "1-2 sentence explanation of why this change is needed",
  "migrationNotes": ["note1", "note2", "note3"],
  "requiredDependencies": ["dep1", "dep2"],
  "testRequirements": ["test1", "test2"],
  "diff": "unified diff format showing the change"
}

RULES:
1. Use the detected language (${finding.language}) for code examples
2. If the finding is quantum-vulnerable (RSA/ECC/ECDH), explain this is MIGRATION PLANNING — not an immediate classical vulnerability (unless also classically weak)
3. For PQC migrations, clearly label examples as "AI-generated migration example — validate with your library and protocol context"
4. Do not invent production-ready PQC APIs unless they exist in well-known libraries (liboqs, BouncyCastle PQC, etc.)
5. Be accurate: if the algorithm has known classical attacks (MD5, DES, SHA-1), say so clearly
6. Keep code examples concise and illustrative`;
}

export async function generateRemediation(
  finding: Finding,
  apiKey: string
): Promise<RemediationResult> {
  // Check for built-in deterministic remediation first
  const builtin = BUILTIN_REMEDIATIONS[finding.algorithm];

  if (!apiKey) {
    return {
      currentCode: finding.detectedPattern || `// ${finding.algorithm} usage detected at line ${finding.line}`,
      suggestedCode: `// Recommended: ${finding.recommendedAlgorithm || 'See migration strategy'}\n// AI-generated migration example — requires API key`,
      explanation: finding.migrationStrategy || 'Configure Gemini API key for AI-generated remediation.',
      migrationNotes: ['Configure Gemini API key in Settings for detailed migration guidance'],
      requiredDependencies: [],
      testRequirements: [],
      label: 'Template — API key required for AI-generated guidance',
      diff: '',
      ...builtin,
    };
  }

  // Return built-in for well-known cases (faster, more reliable)
  if (builtin && (builtin.currentCode && builtin.suggestedCode)) {
    return {
      currentCode: builtin.currentCode || '',
      suggestedCode: builtin.suggestedCode || '',
      explanation: builtin.explanation || '',
      migrationNotes: builtin.migrationNotes || [],
      requiredDependencies: builtin.requiredDependencies || [],
      testRequirements: builtin.testRequirements || [],
      label: 'Deterministic migration example',
      diff: generateDiff(builtin.currentCode || '', builtin.suggestedCode || ''),
    };
  }

  // Use AI for complex cases
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
    const result = await model.generateContent(buildRemediationPrompt(finding));
    const text = result.response.text();

    // Parse JSON response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      return {
        ...parsed,
        label: 'AI-generated migration example — validate before use in production',
        diff: parsed.diff || generateDiff(parsed.currentCode || '', parsed.suggestedCode || ''),
      };
    }
  } catch {
    // Fallback
  }

  return {
    currentCode: finding.detectedPattern || `// ${finding.algorithm} detected`,
    suggestedCode: `// Recommended: ${finding.recommendedAlgorithm}\n// ${finding.migrationStrategy}`,
    explanation: finding.migrationStrategy || 'See migration strategy above.',
    migrationNotes: ['Validate replacement in your specific library and protocol context'],
    requiredDependencies: [],
    testRequirements: ['Verify encryption/decryption or signature round-trip'],
    label: 'AI-generated migration example — validate before use in production',
    diff: '',
  };
}

function generateDiff(current: string, suggested: string): string {
  const oldLines = current.split('\n').map(l => `- ${l}`);
  const newLines = suggested.split('\n').map(l => `+ ${l}`);
  return [...oldLines, ...newLines].join('\n');
}
