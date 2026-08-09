/**
 * QuantumGuard AI — Test Repository Generator
 * Generates a sample-repo.zip with intentionally vulnerable crypto patterns
 * Run: node create-test-repo.js
 */

const fs = require('fs');
const path = require('path');

// ── Synthetic vulnerable files ─────────────────────────────────

const FILES = {
  // Python payment service with RSA + MD5
  'services/payment/crypto_utils.py': `
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate RSA-2048 key pair for payment signing
def generate_payment_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

# Sign payment transaction with RSA
def sign_transaction(private_key, transaction_data: bytes) -> bytes:
    signature = private_key.sign(
        transaction_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# Legacy checksum — DO NOT USE IN NEW CODE
def legacy_checksum(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()

# HMAC for API authentication
def compute_hmac(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha1).hexdigest()
`,

  // Java authentication service with ECC + SHA-1
  'services/auth/JwtService.java': `
package com.example.auth;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class JwtService {

    // ECDH key exchange for session establishment
    public static KeyPair generateECDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        try {
            keyGen.initialize(ecSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return keyGen.generateKeyPair();
    }

    // RSA-4096 for token signing
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        return kpg.generateKeyPair();
    }

    // Legacy SHA-1 fingerprint
    public static String computeFingerprint(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(data);
        return Base64.getEncoder().encodeToString(digest);
    }

    // AES-256-GCM encryption (quantum-safe symmetric)
    public static byte[] encrypt(byte[] key, byte[] plaintext) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }
}
`,

  // TypeScript API gateway with TLS config
  'services/gateway/tls-config.ts': `
import tls from 'tls';
import https from 'https';

// TLS configuration for API gateway
export const tlsOptions: tls.TlsOptions = {
  // Legacy protocols still enabled for backward compat
  minVersion: 'TLSv1',
  maxVersion: 'TLSv1.3',
  ciphers: [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'DHE-RSA-AES256-GCM-SHA384',
    // Legacy cipher for old clients
    'DES-CBC3-SHA',
  ].join(':'),
};

// RSA key for TLS termination
export function createServer(cert: Buffer, key: Buffer) {
  return https.createServer({
    cert,
    key,
    ...tlsOptions,
    // Elliptic curve for ECDHE
    ecdhCurve: 'P-256',
  });
}
`,

  // Go microservice with DSA + 3DES
  'services/legacy-banking/legacy_crypto.go': `
package banking

import (
	"crypto/des"
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// LegacyEncrypt uses 3DES for backward compatibility
func LegacyEncrypt(key []byte, data []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(data))
	block.Encrypt(encrypted, data)
	return encrypted, nil
}

// SignWithDSA signs data using DSA (legacy)
func SignWithDSA(data []byte) (*big.Int, *big.Int, error) {
	params := dsa.Parameters{}
	dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
	
	privateKey := &dsa.PrivateKey{}
	privateKey.Parameters = params
	dsa.GenerateKey(privateKey, rand.Reader)
	
	hash := sha256.Sum256(data)
	r, s, err := dsa.Sign(rand.Reader, privateKey, hash[:])
	return r, s, err
}
`,

  // Python config with exposed secrets
  'services/payment/config.py': `
import os

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://localhost/payments')

# !! WARNING: Rotate these immediately !!
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
JWT_SECRET = "super-secret-jwt-signing-key-do-not-share-prod-2024"

# AWS credentials (legacy, should use IAM role)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE123"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# TLS certificate paths
TLS_CERT_PATH = "/etc/ssl/certs/payment-service.crt"
TLS_KEY_PATH = "/etc/ssl/private/payment-service.key"

# Hash algorithm for password storage (INSECURE — migrate to bcrypt)
PASSWORD_HASH_ALGO = "md5"
`,

  // YAML Kubernetes config with TLS settings
  'infrastructure/k8s/ingress.yaml': `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: payment-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES256-GCM-SHA384:RSA+AES:!aNULL:!MD5"
spec:
  tls:
  - hosts:
    - api.payments.internal
    secretName: payment-tls
  rules:
  - host: api.payments.internal
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: payment-service
            port:
              number: 443
`,

  // OpenSSL nginx config
  'infrastructure/nginx/nginx.conf': `
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:!aNULL:!MD5:!DSS;
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    location /api/ {
        proxy_pass http://backend;
    }
}
`,

  // JavaScript frontend with crypto
  'frontend/src/utils/crypto.js': `
const crypto = require('crypto');

// Client-side signature verification using RSA
function verifySignature(publicKey, data, signature) {
  const verify = crypto.createVerify('RSA-SHA256');
  verify.update(data);
  return verify.verify(publicKey, signature, 'base64');
}

// Legacy MD5 for cache busting (non-security use)
function cacheKey(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// ECDSA for document signing
function signDocument(privateKey, document) {
  const sign = crypto.createSign('SHA256');
  sign.update(document);
  return sign.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }, 'base64');
}

// AES-256-CBC encryption
function encryptData(key, iv, data) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
`,

  // Java with PQC (positive indicator)
  'services/auth/PQCKeyExchange.java': `
package com.example.auth.pqc;

// Post-Quantum Cryptography implementation using ML-KEM (FIPS 203)
// This service uses Kyber/ML-KEM for key establishment

import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;

public class PQCKeyExchange {
    
    // ML-KEM-768 for key encapsulation (FIPS 203 compliant)
    public static KeyPair generateMLKEMKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(KyberParameterSpec.kyber768);
        return kpg.generateKeyPair();
    }
    
    // ML-DSA for digital signatures (FIPS 204 compliant)
    public static KeyPair generateMLDSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        return kpg.generateKeyPair();
    }
}
`,
};

// ── Build ZIP using Node.js built-ins ─────────────────────────

// Simple manual ZIP writer using JSZip-compatible structure
// We'll use Node's built-in zlib for DEFLATE and write a proper ZIP

const zlib = require('zlib');

function writeZip(files) {
  const entries = [];
  let offset = 0;
  const localHeaders = [];

  for (const [name, content] of Object.entries(files)) {
    const nameBuffer = Buffer.from(name, 'utf8');
    const contentBuffer = Buffer.from(content, 'utf8');
    const compressed = zlib.deflateRawSync(contentBuffer, { level: 6 });
    const crc = crc32(contentBuffer);

    // Local file header
    const localHeader = Buffer.alloc(30 + nameBuffer.length);
    localHeader.writeUInt32LE(0x04034b50, 0);  // signature
    localHeader.writeUInt16LE(20, 4);            // version needed
    localHeader.writeUInt16LE(0, 6);             // flags
    localHeader.writeUInt16LE(8, 8);             // compression (DEFLATE)
    localHeader.writeUInt16LE(0, 10);            // mod time
    localHeader.writeUInt16LE(0, 12);            // mod date
    localHeader.writeUInt32LE(crc, 14);          // CRC-32
    localHeader.writeUInt32LE(compressed.length, 18); // compressed size
    localHeader.writeUInt32LE(contentBuffer.length, 22); // uncompressed size
    localHeader.writeUInt16LE(nameBuffer.length, 26);   // filename length
    localHeader.writeUInt16LE(0, 28);                   // extra length
    nameBuffer.copy(localHeader, 30);

    entries.push({ name, nameBuffer, contentBuffer, compressed, crc, offset });
    localHeaders.push(localHeader);
    offset += localHeader.length + compressed.length;
  }

  // Central directory
  const centralDirs = [];
  let cdOffset = offset;
  entries.forEach(({ name, nameBuffer, contentBuffer, compressed, crc, offset: entryOffset }) => {
    const cd = Buffer.alloc(46 + nameBuffer.length);
    cd.writeUInt32LE(0x02014b50, 0); // signature
    cd.writeUInt16LE(20, 4);          // version made by
    cd.writeUInt16LE(20, 6);          // version needed
    cd.writeUInt16LE(0, 8);           // flags
    cd.writeUInt16LE(8, 10);          // compression
    cd.writeUInt16LE(0, 12);          // mod time
    cd.writeUInt16LE(0, 14);          // mod date
    cd.writeUInt32LE(crc, 16);        // CRC-32
    cd.writeUInt32LE(compressed.length, 20);    // compressed size
    cd.writeUInt32LE(contentBuffer.length, 24); // uncompressed size
    cd.writeUInt16LE(nameBuffer.length, 28);    // filename length
    cd.writeUInt16LE(0, 30);                    // extra length
    cd.writeUInt16LE(0, 32);                    // comment length
    cd.writeUInt16LE(0, 34);                    // disk number
    cd.writeUInt16LE(0, 36);                    // int attr
    cd.writeUInt32LE(0, 38);                    // ext attr
    cd.writeUInt32LE(entryOffset, 42);           // local header offset
    nameBuffer.copy(cd, 46);
    centralDirs.push(cd);
  });

  const cdSize = centralDirs.reduce((s, b) => s + b.length, 0);

  // End of central directory
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // signature
  eocd.writeUInt16LE(0, 4);          // disk number
  eocd.writeUInt16LE(0, 6);          // disk with cd
  eocd.writeUInt16LE(entries.length, 8);  // entries on disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(cdSize, 12);         // cd size
  eocd.writeUInt32LE(cdOffset, 16);       // cd offset
  eocd.writeUInt16LE(0, 20);             // comment length

  const parts = [];
  entries.forEach((_, i) => {
    parts.push(localHeaders[i]);
    parts.push(entries[i].compressed);
  });
  centralDirs.forEach(cd => parts.push(cd));
  parts.push(eocd);

  return Buffer.concat(parts);
}

// CRC-32 implementation
function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// Write the ZIP
const zipBuffer = writeZip(FILES);
const outputPath = path.join(__dirname, 'sample-vulnerable-repo.zip');
fs.writeFileSync(outputPath, zipBuffer);

console.log(`✅ Created: ${outputPath}`);
console.log(`   Size: ${(zipBuffer.length / 1024).toFixed(1)} KB`);
console.log(`   Files: ${Object.keys(FILES).length}`);
console.log('');
console.log('Upload this ZIP to QuantumGuard AI to test the scanner.');
console.log('Expected detections:');
console.log('  • RSA-2048, RSA-4096 (quantum-vulnerable)');
console.log('  • ECDH / ECDSA / EC (quantum-vulnerable)');
console.log('  • MD5 (classical-weak)');
console.log('  • SHA-1 / HMAC-SHA1 (classical-weak)');
console.log('  • 3DES / DES (classical-weak)');
console.log('  • DSA (quantum-vulnerable)');
console.log('  • TLS 1.0/1.1 (classical-weak)');
console.log('  • AES-256-GCM (adequate — currently strong)');
console.log('  • ML-KEM / ML-DSA (quantum-resistant — positive)');
console.log('  • Stripe secret key, JWT secret, AWS keys (secrets)');
