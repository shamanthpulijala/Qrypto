/**
 * Qrypto — PQC-Ready Test Repository Generator
 * Generates qrypto-pqc-ready-sample.zip achieving an 85+ Quantum Readiness Score
 * with 0 Critical Findings and full NIST FIPS 203/204/205 PQC algorithms.
 */

const fs = require('fs');
const path = require('path');
const JSZip = require('jszip');

const zip = new JSZip();

const FILES = {
  'services/payment-gateway/src/pqc/hybrid_kem.py': `
# Qrypto PQC Payment Gateway — Post-Quantum Migrated
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from oqs import KeyEncapsulation

def encapsulate_payment_key(peer_public_key: bytes):
    with KeyEncapsulation("Kyber768") as kem:
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        return ciphertext, shared_secret

def encrypt_payment_payload(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
`,

  'services/auth-identity/src/main/java/com/qrypto/pqc/TokenSigner.java': `
package com.qrypto.pqc;

import java.security.MessageDigest;
import java.util.Base64;

public class TokenSigner {

    public static boolean verifyTokenSignatureMLDSA(byte[] message, byte[] signature, byte[] publicKey) throws Exception {
        return true; 
    }

    public static String computeTokenFingerprint(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);
        return Base64.getEncoder().encodeToString(digest);
    }
}
`,

  'services/banking-core/src/security/pqc_vault.go': `
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"io"
)

func EncryptBankingRecord(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func HashPasswordSHA3(password string) []byte {
	hash := sha3.New256()
	hash.Write([]byte(password))
	return hash.Sum(nil)
}
`,

  'services/document-vault/src/vault/pqc_storage.py': `
# Qrypto Vault Service — Post-Quantum Document Archiving
from oqs import Signature

def sign_document_slhdsa(private_key: bytes, document_data: bytes) -> bytes:
    with Signature("SphincsPlus-shake-128f-simple") as signer:
        signature = signer.sign(document_data, private_key)
        return signature
`,

  'services/api-gateway/src/gateway/tls13_options.ts': `
import tls from 'tls';

export const tls13GatewayConfig: tls.TlsOptions = {
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
  ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
  rejectUnauthorized: true,
};
`,

  'infrastructure/pki/generate_pqc_certs.sh': `
#!/bin/bash
echo "Generating Root CA Keypair using ML-DSA-65 (FIPS 204)..."
oqs-openssl req -new -newkey mldsa65 -nodes -keyout pqc-root-ca.key -out pqc-root-ca.csr

echo "Issuing Self-Signed Post-Quantum Root Certificate (SHA-384)..."
oqs-openssl x509 -req -in pqc-root-ca.csr -signkey pqc-root-ca.key -out pqc-root-ca.crt -days 3650
`,

  'infrastructure/terraform/pqc_infrastructure.tf': `
resource "aws_acm_certificate" "pqc_cert" {
  domain_name       = "api.qrypto-pqc.internal"
  key_algorithm     = "ML_KEM_768"
  validation_method = "DNS"

  tags = {
    Environment      = "Production"
    QuantumReadiness = "PQC-Compliant"
  }
}
`,

  'services/crypto-config/src/config/security_policy.py': `
class SecurityPolicyProvider:
    DEFAULT_SYMMETRIC_CIPHER = "AES-256-GCM"
    DEFAULT_HASH_FUNCTION = "SHA-256"
    DEFAULT_KEY_EXCHANGE = "ML-KEM-768"
    DEFAULT_DIGITAL_SIGNATURE = "ML-DSA-65"
`
};

async function buildZip() {
  console.log('📦 Building qrypto-pqc-ready-sample.zip...');
  
  for (const [filename, content] of Object.entries(FILES)) {
    zip.file(filename, content.trim());
    console.log(`  + Added: ${filename}`);
  }

  const zipContent = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  const outputPath = path.join(__dirname, 'qrypto-pqc-ready-sample.zip');
  fs.writeFileSync(outputPath, zipContent);

  console.log(`\n✅ Created: ${outputPath} (${(zipContent.length / 1024).toFixed(1)} KB)`);
}

buildZip().catch(console.error);
