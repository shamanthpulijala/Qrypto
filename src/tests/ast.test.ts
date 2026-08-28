// ============================================================
// AST Layer Verification Tests (P0-7)
// These tests verify the AST layer ACTUALLY WORKS, not just compiles.
//
// DESIGN: When WASM grammars are available (which they MUST be in the
// test environment), these tests ASSERT that real AST enrichment
// happened — not merely that regex detection worked.
//
// If a grammar genuinely cannot load, the test EXPLICITLY identifies
// that limitation rather than silently passing as "regex-only mode."
// ============================================================

import { describe, it, expect, beforeAll } from 'vitest';
import { initAstParser, enrichWithAst, isAstAvailable, getAstStats, LANG_WASM_MAP } from '../../shared/engine/detectors/ast';
import { scanFile } from '../../shared/engine/scanner';
import type { Finding } from '../../shared/types';

describe('P0-7: AST Layer — Strict Verification', () => {
  let astReady = false;

  beforeAll(async () => {
    astReady = await initAstParser();
    console.log(`AST Parser initialized: ${astReady}`);
  });

  it('AST parser should initialize successfully', async () => {
    const result = await initAstParser();
    expect(result).toBe(true);
    expect(isAstAvailable()).toBe(true);
  });

  /**
   * Helper: enrich findings and return the enriched finding.
   * Proves AST enrichment actually happened by asserting the 'ast' layer
   * was added. If AST is genuinely unavailable, the test is skipped with
   * an explicit message — it does NOT silently pass.
   */
  async function enrichAndAssert(
    filePath: string,
    content: string,
    findings: Finding[],
    algorithmFilter: (f: Finding) => boolean,
  ): Promise<Finding> {
    const before = findings.map(f => ({
      id: f.id,
      layers: [...(f.evidence?.detectionLayers ?? [])],
    }));

    await enrichWithAst(filePath, content, findings);

    const enriched = findings.find(algorithmFilter);
    expect(enriched).toBeDefined();

    // PROVE AST enrichment happened: detectionLayers must now include 'ast'
    const astLayerAdded = enriched!.evidence?.detectionLayers?.includes('ast') ?? false;
    expect(astLayerAdded).toBe(true);

    // PROVE the AST context is genuinely present
    expect(enriched!.evidence!.astContext).toBeDefined();
    expect(enriched!.evidence!.astContext!.type).toBeTruthy();
    expect(enriched!.evidence!.astContext!.inComment).toBeDefined();

    return enriched!;
  }

  describe('Real crypto API calls — AST must enrich', () => {
    it('should detect and enrich RSA key generation in JavaScript (AST proven)', async () => {
      if (!astReady) {
        // AST is NOT available — this is a test environment limitation
        throw new Error(
          'AST parser failed to initialize. WASM grammars are required for this test. ' +
          'Ensure @vscode/tree-sitter-wasm is installed and its WASM files are accessible.'
        );
      }

      const jsCode = `
const crypto = require('crypto');

// Generate RSA key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('RSA', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Sign data
const sign = crypto.createSign('RSA-SHA256');
sign.update('data to sign');
const signature = sign.sign(privateKey, 'hex');
`;

      const findings = scanFile({
        path: 'test/crypto.js',
        content: jsCode,
        repository: 'test-repo',
        project: 'test-project',
      });

      expect(findings.length).toBeGreaterThan(0);
      const rsaFinding = findings.find(f => f.algorithm.toUpperCase().includes('RSA'));
      expect(rsaFinding).toBeDefined();

      const enriched = await enrichAndAssert(
        'test/crypto.js', jsCode, findings,
        f => f.algorithm.toUpperCase().includes('RSA'),
      );

      // AST should detect this is a call expression (not a comment/string)
      expect(enriched.evidence!.astContext!.inComment).toBe(false);
      // Confidence should have been boosted (call expression = real usage)
      expect(enriched.confidence).toBeGreaterThan(0.8);
      // Call arguments should be extracted
      expect(enriched.evidence!.astContext!.callArguments).toBeDefined();
      expect(enriched.evidence!.astContext!.callArguments!.length).toBeGreaterThan(0);
    });

    it('should detect and enrich AES encryption in Python (AST proven)', async () => {
      if (!astReady) {
        throw new Error('AST parser not initialized — WASM grammar required');
      }

      const pyCode = `
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate AES key
key = os.urandom(32)  # AES-256

# Encrypt with AES-GCM
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(b"secret data") + encryptor.finalize()
`;

      const findings = scanFile({
        path: 'test/encrypt.py',
        content: pyCode,
        repository: 'test-repo',
        project: 'test-project',
      });

      expect(findings.length).toBeGreaterThan(0);

      const enriched = await enrichAndAssert(
        'test/encrypt.py', pyCode, findings,
        f => f.evidence?.detectionLayers?.includes('ast') ?? false,
      );

      // AST context should be present
      expect(enriched.evidence!.astContext!.inComment).toBe(false);
    });

    it('should detect and enrich Java crypto (AST proven)', async () => {
      if (!astReady) {
        throw new Error('AST parser not initialized — WASM grammar required');
      }

      const javaCode = `
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CryptoExample {
    public static void main(String[] args) throws Exception {
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }
}
`;

      const findings = scanFile({
        path: 'test/CryptoExample.java',
        content: javaCode,
        repository: 'test-repo',
        project: 'test-project',
      });

      // Scanner detects Cipher.getInstance("AES/GCM/NoPadding") → AES-256
      // and the bare "AES" string from KeyGenerator.getInstance("AES") → AES
      expect(findings.length).toBeGreaterThan(0);
      const cipherFinding = findings.find(f => f.detectedPattern.includes('Cipher'));
      expect(cipherFinding).toBeDefined();

      // Enrich with AST
      await enrichWithAst('test/CryptoExample.java', javaCode, findings);

      // PROVE: Cipher.getInstance("AES/GCM/NoPadding") was AST-enriched
      const astCipher = findings.find(
        f => f.detectedPattern.includes('Cipher') && f.evidence?.detectionLayers?.includes('ast'),
      );
      expect(astCipher).toBeDefined();
      expect(astCipher!.evidence!.astContext).toBeDefined();
      expect(astCipher!.evidence!.astContext!.inComment).toBe(false);
      // AST must identify the node as a meaningful code construct (not punctuation)
      expect(['variable_declarator', 'call_expression', 'function_call', 'assignment']).toContain(
        astCipher!.evidence!.astContext!.type,
      );

      // PROVE: the other Java finding (AES from KeyGenerator.getInstance) was also AST-enriched
      const astOther = findings.find(
        f => f.evidence?.detectionLayers?.includes('ast') && f !== astCipher,
      );
      expect(astOther).toBeDefined();
      expect(astOther!.evidence!.astContext!.inComment).toBe(false);

      // At minimum, 2 of all findings must have AST enrichment
      const astCount = findings.filter(f => f.evidence?.detectionLayers?.includes('ast')).length;
      expect(astCount).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Comment handling — AST must distinguish comments from code', () => {
    it('should penalize confidence when match is in a comment', async () => {
      if (!astReady) {
        throw new Error('AST parser not initialized — WASM grammar required');
      }

      // RSA in a comment - should NOT be high confidence
      const codeWithComment = `
// RSA.generate(2048) - old key generation method, do not use
const crypto = require('crypto');
// Use this instead: crypto.generateKeyPairSync('rsa', { modulusLength: 4096 })
`;

      const findings = scanFile({
        path: 'test/comment.js',
        content: codeWithComment,
        repository: 'test-repo',
        project: 'test-project',
      });

      expect(findings.length).toBeGreaterThan(0);
      const originalConfidence = findings[0].confidence;

      await enrichWithAst('test/comment.js', codeWithComment, findings);

      // AST must have enriched this finding
      const enriched = findings[0];
      expect(enriched.evidence?.detectionLayers?.includes('ast')).toBe(true);
      expect(enriched.evidence!.astContext).toBeDefined();

      // AST should have detected it's in a comment and penalized confidence
      expect(enriched.evidence!.astContext!.inComment).toBe(true);
      expect(enriched.confidence).toBeLessThan(originalConfidence);
      expect(enriched.remediationStatus).toBe('accepted-risk');
    });

    it('should boost confidence when match is in actual code', async () => {
      if (!astReady) {
        throw new Error('AST parser not initialized — WASM grammar required');
      }

      const codeWithRealUsage = `
const crypto = require('crypto');

function signData(data, privateKey) {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  return sign.sign(privateKey, 'hex');
}
`;

      const findings = scanFile({
        path: 'test/real_usage.js',
        content: codeWithRealUsage,
        repository: 'test-repo',
        project: 'test-project',
      });

      expect(findings.length).toBeGreaterThan(0);
      const originalConfidence = findings[0].confidence;

      await enrichWithAst('test/real_usage.js', codeWithRealUsage, findings);

      const enriched = findings[0];
      expect(enriched.evidence?.detectionLayers?.includes('ast')).toBe(true);

      // If AST identified it as a call expression, confidence should increase
      if (enriched.evidence!.astContext!.type === 'call_expression') {
        expect(enriched.confidence).toBeGreaterThan(originalConfidence);
      }
    });
  });

  describe('Call argument extraction — AST must extract real arguments', () => {
    it('should extract arguments from crypto function calls', async () => {
      if (!astReady) {
        throw new Error('AST parser not initialized — WASM grammar required');
      }

      const code = `
const crypto = require('crypto');
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
`;

      const findings = scanFile({
        path: 'test/args.js',
        content: code,
        repository: 'test-repo',
        project: 'test-project',
      });

      await enrichWithAst('test/args.js', code, findings);

      // Findings with call arguments should have them extracted
      const findingsWithArgs = findings.filter(f =>
        f.evidence?.detectionLayers?.includes('ast') &&
        f.evidence?.astContext?.callArguments &&
        f.evidence.astContext.callArguments.length > 0
      );

      expect(findingsWithArgs.length).toBeGreaterThan(0);
      expect(findingsWithArgs[0].evidence!.astContext!.callArguments!.length).toBeGreaterThan(0);
    });
  });

  describe('AST statistics', () => {
    it('should report AST coverage statistics', async () => {
      const findings: Finding[] = [
        {
          id: 'test-1',
          file: 'test.js',
          line: 1,
          repository: 'test',
          project: 'test',
          service: 'test',
          language: 'javascript',
          algorithm: 'RSA',
          category: 'public-key',
          usage: 'key generation',
          detectedPattern: 'crypto.generateKeyPairSync',
          confidence: 0.9,
          quantumStatus: 'vulnerable',
          classicalStatus: 'adequate',
          algorithmSeverity: 'medium',
          severity: 'medium',
          severityRationale: 'test',
          internetFacing: false,
          dataSensitivity: 'medium',
          dataLifetimeYears: 5,
          isCryptoAgile: false,
          isHardcoded: false,
          riskScore: 50,
          riskBreakdown: {
            algorithmRisk: 50,
            businessCriticality: 50,
            internetExposure: 50,
            dataLifetime: 50,
            dataSensitivity: 50,
            migrationDifficulty: 50,
            totalScore: 50,
          },
          remediationStatus: 'open',
          migrationPriority: 1,
          tags: [],
          detectedAt: new Date().toISOString(),
          evidence: {
            detectionLayers: ['regex'],
            matchedText: 'test',
            confidenceDerivation: 'test',
          },
        },
      ];

      const stats = getAstStats(findings);
      expect(stats.totalFindings).toBe(1);
      expect(typeof stats.astAnalyzed).toBe('number');
      expect(typeof stats.inComments).toBe('number');
      expect(typeof stats.inCode).toBe('number');
    });
  });

  describe('WASM grammar availability', () => {
    it('should have WASM files for all supported languages', () => {
      if (!astReady) {
        throw new Error('AST parser not initialized — cannot verify WASM availability');
      }

      // Verify the LANG_WASM_MAP includes the expected languages
      expect(LANG_WASM_MAP['.js']).toBeTruthy();
      expect(LANG_WASM_MAP['.py']).toBeTruthy();
      expect(LANG_WASM_MAP['.java']).toBeTruthy();
      expect(LANG_WASM_MAP['.ts']).toBeTruthy();
    });
  });
});
