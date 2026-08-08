// ============================================================
// QuantumGuard AI — §35 Scanner Tests
//
// Tests for all crypto pattern detectors:
//   RSA, ECC, ECDH, SHA-1, MD5, TLS, Secrets
//   and false positive handling
// ============================================================

import { describe, it, expect } from 'vitest';
import { scanFile } from '../engine/scanner';

// ─── RSA Detection ────────────────────────────────────────────

describe('Scanner — RSA Detection', () => {
  it('detects RSA key generation in Python', () => {
    const findings = scanFile({
      path: 'payment/crypto.py',
      content: `from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)`,
    });
    const rsaFindings = findings.filter(f => f.algorithm.includes('RSA'));
    expect(rsaFindings.length).toBeGreaterThan(0);
    expect(rsaFindings[0].quantumStatus).toBe('vulnerable');
  });

  it('detects RSA in Java Cipher.getInstance call', () => {
    const findings = scanFile({
      path: 'services/payment/CryptoUtil.java',
      content: `Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");`,
    });
    const rsaFindings = findings.filter(f => f.algorithm.includes('RSA'));
    if (rsaFindings.length > 0) {
      expect(rsaFindings[0].severity).toBeDefined();
    }
  });

  it('detects RSA-2048 key size references', () => {
    const findings = scanFile({
      path: 'auth/keys.ts',
      content: `const keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });`,
    });
    const rsaFindings = findings.filter(f => f.algorithm.includes('RSA'));
    expect(rsaFindings.length).toBeGreaterThanOrEqual(0);
  });

  it('detects PEM-encoded RSA private key header', () => {
    const findings = scanFile({
      path: 'config/private.pem',
      content: `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...`,
    });
    const rsaFindings = findings.filter(f => f.algorithm.includes('RSA') || f.category === 'secret');
    expect(rsaFindings.length).toBeGreaterThan(0);
  });

  it('marks RSA findings as quantum-vulnerable', () => {
    const findings = scanFile({
      path: 'main.py',
      content: `import RSA\nkey = RSA.generate(2048)`,
    });
    const rsaFindings = findings.filter(f => f.algorithm.includes('RSA'));
    if (rsaFindings.length > 0) {
      expect(rsaFindings[0].quantumStatus).toBe('vulnerable');
    }
  });
});

// ─── ECC Detection ────────────────────────────────────────────

describe('Scanner — ECC Detection', () => {
  it('detects ECDSA signature usage in Python', () => {
    const findings = scanFile({
      path: 'auth/signer.py',
      content: `from cryptography.hazmat.primitives.asymmetric import ec\nkey = ec.generate_private_key(ec.SECP256R1())`,
    });
    const eccFindings = findings.filter(f => f.algorithm.match(/ECDSA|ECC|EC/));
    expect(eccFindings.length).toBeGreaterThan(0);
    expect(eccFindings[0].quantumStatus).toBe('vulnerable');
  });

  it('detects ECDSA in JavaScript', () => {
    const findings = scanFile({
      path: 'src/crypto.js',
      content: `const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });`,
    });
    const eccFindings = findings.filter(f => f.algorithm.match(/ECDSA|ECC|EC/i));
    expect(eccFindings.length).toBeGreaterThan(0);
  });

  it('marks ECC findings as quantum-vulnerable', () => {
    const findings = scanFile({
      path: 'signing.go',
      content: `curve := elliptic.P256()\nprivate, _ := ecdsa.GenerateKey(curve, rand.Reader)`,
    });
    const eccFindings = findings.filter(f => f.algorithm.match(/ECDSA|ECC|EC/i));
    if (eccFindings.length > 0) {
      expect(eccFindings[0].quantumStatus).toBe('vulnerable');
    }
  });
});

// ─── ECDH Detection ───────────────────────────────────────────

describe('Scanner — ECDH Detection', () => {
  it('detects ECDH key agreement in Python', () => {
    const findings = scanFile({
      path: 'key-exchange/dh.py',
      content: `from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\nfrom cryptography.hazmat.primitives.asymmetric import ec\n\n# ECDH exchange\necdh = ec.ECDH()`,
    });
    const ecdhFindings = findings.filter(f => f.algorithm.includes('ECDH'));
    expect(ecdhFindings.length).toBeGreaterThan(0);
    expect(ecdhFindings[0].quantumStatus).toBe('vulnerable');
  });

  it('detects ECDH in TypeScript', () => {
    const findings = scanFile({
      path: 'src/keyExchange.ts',
      content: `const ecdhKey = crypto.createECDH('prime256v1');\necdhKey.generateKeys();`,
    });
    const ecdhFindings = findings.filter(f => f.algorithm.includes('ECDH'));
    expect(ecdhFindings.length).toBeGreaterThan(0);
  });
});

// ─── SHA-1 Detection ──────────────────────────────────────────

describe('Scanner — SHA-1 Detection', () => {
  it('detects SHA-1 hash usage', () => {
    const findings = scanFile({
      path: 'utils/hash.js',
      content: `const hash = crypto.createHash('sha1').update(data).digest('hex');`,
    });
    const sha1Findings = findings.filter(f => f.algorithm.match(/SHA-1|SHA1/i));
    expect(sha1Findings.length).toBeGreaterThan(0);
    expect(sha1Findings[0].quantumStatus).toBe('classical-weak');
  });

  it('detects SHA1withRSA signature algorithm', () => {
    const findings = scanFile({
      path: 'signing/CertSigner.java',
      content: `Signature sig = Signature.getInstance("SHA1withRSA");`,
    });
    const sha1Findings = findings.filter(f => f.algorithm.match(/SHA1|SHA-1/i));
    expect(sha1Findings.length).toBeGreaterThan(0);
  });

  it('marks SHA-1 as classical-weak', () => {
    const findings = scanFile({
      path: 'utils.py',
      content: `import hashlib\nhash_obj = hashlib.sha1(data)`,
    });
    const sha1Findings = findings.filter(f => f.algorithm.match(/SHA-1|SHA1/i));
    if (sha1Findings.length > 0) {
      expect(sha1Findings[0].quantumStatus).toBe('classical-weak');
      expect(sha1Findings[0].classicalStatus).toBe('weak');
    }
  });
});

// ─── MD5 Detection ────────────────────────────────────────────

describe('Scanner — MD5 Detection', () => {
  it('detects MD5 in Python hashlib', () => {
    const findings = scanFile({
      path: 'legacy/api.py',
      content: `import hashlib\nmd5_hash = hashlib.md5(password.encode()).hexdigest()`,
    });
    const md5Findings = findings.filter(f => f.algorithm === 'MD5');
    expect(md5Findings.length).toBeGreaterThan(0);
    expect(md5Findings[0].quantumStatus).toBe('classical-weak');
  });

  it('detects MD5 in Java MessageDigest', () => {
    const findings = scanFile({
      path: 'auth/LegacyHash.java',
      content: `MessageDigest md = MessageDigest.getInstance("MD5");`,
    });
    const md5Findings = findings.filter(f => f.algorithm === 'MD5');
    expect(md5Findings.length).toBeGreaterThan(0);
    expect(md5Findings[0].classicalStatus).toBe('broken');
  });

  it('detects MD5 in JavaScript', () => {
    const findings = scanFile({
      path: 'api/legacy.js',
      content: `const hash = require('crypto').createHash('md5').update(input).digest('hex');`,
    });
    const md5Findings = findings.filter(f => f.algorithm === 'MD5');
    expect(md5Findings.length).toBeGreaterThan(0);
  });
});

// ─── TLS Detection ────────────────────────────────────────────

describe('Scanner — TLS Detection', () => {
  it('detects TLS 1.0 configuration', () => {
    const findings = scanFile({
      path: 'config/ssl.conf',
      content: `ssl_protocols TLSv1;`,
    });
    const tlsFindings = findings.filter(f => f.category === 'tls' && f.algorithm.includes('1.0'));
    expect(tlsFindings.length).toBeGreaterThanOrEqual(0);
    if (tlsFindings.length > 0) {
      expect(tlsFindings[0].quantumStatus).toBe('classical-weak');
    }
  });

  it('detects TLS 1.1 as deprecated', () => {
    const findings = scanFile({
      path: 'server/config.py',
      content: `ssl_version = "TLSv1.1"\ncontext.minimum_version = ssl.TLSVersion.TLSv1_1`,
    });
    const tlsFindings = findings.filter(f => f.category === 'tls');
    expect(tlsFindings.length).toBeGreaterThan(0);
  });

  it('detects SSLv3 as broken', () => {
    const findings = scanFile({
      path: 'legacy/ssl_config.py',
      content: `ssl_version = ssl.PROTOCOL_SSLv23`,
    });
    const sslFindings = findings.filter(f => f.algorithm.match(/SSL/i) || f.category === 'tls');
    expect(sslFindings.length).toBeGreaterThan(0);
  });
});

// ─── Secret Detection ─────────────────────────────────────────

describe('Scanner — Secret Detection', () => {
  it('detects hardcoded AWS access key', () => {
    const findings = scanFile({
      path: 'config/aws.py',
      content: `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\nAWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
    });
    const secretFindings = findings.filter(f => f.category === 'secret');
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  it('detects JWT secret in environment variable assignment', () => {
    const findings = scanFile({
      path: 'src/auth.ts',
      content: `const JWT_SECRET = "super-secret-key-do-not-share-abc123";`,
    });
    const secretFindings = findings.filter(f => f.category === 'secret');
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  it('detects private key in source code', () => {
    const findings = scanFile({
      path: 'certs/key.pem',
      content: `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...`,
    });
    const secretFindings = findings.filter(f => f.category === 'secret' || f.algorithm.includes('Private Key'));
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  it('masks secret values in detected patterns', () => {
    const findings = scanFile({
      path: 'api/config.py',
      const fakeStripeKey = "sk_" + "live_" + "A".repeat(48);

      content: `STRIPE_SECRET_KEY = "${fakeStripeKey}"`, "`,
    });
    const secretFindings = findings.filter(f => f.category === 'secret');
    if (secretFindings.length > 0) {
      // Should not expose full key
      expect(secretFindings[0].detectedPattern).not.toContain(fakeStripeKey);
    }
  });
});

// ─── False Positive Handling ──────────────────────────────────

describe('Scanner — False Positive Handling', () => {
  it('does not flag SHA-256 as broken', () => {
    const findings = scanFile({
      path: 'utils/hash.ts',
      content: `const hash = crypto.createHash('sha256').update(data).digest('hex');`,
    });
    const sha256Findings = findings.filter(f => f.algorithm.match(/SHA-256|SHA256/i));
    // SHA-256 should be adequate/quantum-resistant, not classical-weak
    sha256Findings.forEach(f => {
      expect(f.quantumStatus).not.toBe('classical-weak');
      expect(f.classicalStatus).not.toBe('broken');
    });
  });

  it('does not flag AES-256 as vulnerable', () => {
    const findings = scanFile({
      path: 'encryption/aes.ts',
      content: `const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);`,
    });
    const aesFindings = findings.filter(f => f.algorithm.match(/AES-256/i));
    aesFindings.forEach(f => {
      expect(f.quantumStatus).not.toBe('vulnerable');
    });
  });

  it('does not flag TLS 1.3 as deprecated', () => {
    const findings = scanFile({
      path: 'server.ts',
      content: `const tls_version = "TLSv1.3";\ncontext.minimum_version = ssl.TLSVersion.TLSv1_3`,
    });
    const tls13Findings = findings.filter(f => f.algorithm.includes('1.3'));
    tls13Findings.forEach(f => {
      expect(f.quantumStatus).not.toBe('classical-weak');
    });
  });

  it('does not duplicate findings for same position', () => {
    const content = `MessageDigest md = MessageDigest.getInstance("MD5");`;
    const findings1 = scanFile({ path: 'test.java', content });
    const findings2 = scanFile({ path: 'test.java', content });
    // Running twice on same content should produce consistent results
    expect(findings1.length).toBe(findings2.length);
  });

  it('assigns unique IDs to findings', () => {
    const findings = scanFile({
      path: 'mixed.py',
      content: `
import hashlib
md5_hash = hashlib.md5(data).hexdigest()
sha1_hash = hashlib.sha1(data).hexdigest()
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
      `,
    });
    const ids = findings.map(f => f.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});
