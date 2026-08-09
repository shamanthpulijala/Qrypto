/**
 * Qrypto — Enterprise Sample Repository Generator
 * Generates qrypto-enterprise-sample.zip containing a multi-service enterprise repo
 * with comprehensive cryptographic patterns (RSA, ECC, ECDH, 3DES, MD5, SHA-1, TLS, secrets, PQC).
 */

const fs = require('fs');
const path = require('path');
const JSZip = require('jszip');

const zip = new JSZip();

// ── Synthetic Files ─────────────────────────────────────────────

const FILES = {
  // 1. Payment Processing Service (Python)
  'services/payment-processing/src/crypto/payment_signer.py': `
# Qrypto Enterprise — Payment Processing Service
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RSA-2048 Key Generation for Payment Authorization Signatures
def generate_payment_keypair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

# ECDH Key Exchange for Payment Channel Establishment
def establish_payment_channel():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Legacy SHA-1 Transaction Checksum (Weak Hashing)
def compute_legacy_checksum(transaction_payload: bytes) -> str:
    return hashlib.sha1(transaction_payload).hexdigest()

# Legacy MD5 Payment Verification Hash (Broken Hashing)
def compute_md5_hash(data: str) -> str:
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# AES-256-GCM Payload Encryption (Quantum-Adequate)
def encrypt_payload(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
`,

  // 2. Authentication Identity Service (Java)
  'services/auth-service/src/main/java/com/qrypto/auth/TokenSigner.java': `
package com.qrypto.auth;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class TokenSigner {

    // HARDCODED SECRET — Security Violation
    private static final String JWT_SECRET_KEY = "SuperSecretQryptoEnterpriseSigningKey2026!";
    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

    // RSA-4096 Signature Verification
    public static boolean verifyTokenSignature(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    // ECDSA Signature Generation (P-384)
    public static byte[] signWithECDSA(PrivateKey privateKey, byte[] message) throws Exception {
        Signature dsa = Signature.getInstance("SHA384withECDSA");
        dsa.initSign(privateKey);
        dsa.update(message);
        return dsa.sign();
    }

    // Legacy SHA-1 Digest (Deprecated)
    public static String computeSHA1Fingerprint(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(input);
        return Base64.getEncoder().encodeToString(digest);
    }
}
`,

  // 3. Legacy Banking Core Service (Go)
  'services/legacy-banking-core/src/security/des_encryption.go': `
package security

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

// HARDCODED 3DES KEY — Critical Legacy Risk
var LEGACY_3DES_KEY = []byte("LegacyBank24ByteKey01234")

// TripleDES / 3DES Encryption (Classically Weak Cipher)
func EncryptLegacyRecord(plaintext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(LEGACY_3DES_KEY)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte("12345678"))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// MD5 Password Checksum (Broken Hash)
func HashPasswordMD5(password string) string {
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}
`,

  // 4. Document Vault Service (Python - High HNDL Exposure)
  'services/document-vault/src/vault/long_lived_storage.py': `
# Qrypto Vault Service — Long-Lived Confidential Document Storage
# Data Shelf Life: 30 Years (HIGH HARVEST-NOW-DECRYPT-LATER RISK)
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# HARDCODED DB CREDENTIAL
DATABASE_URI = "postgresql://vault_admin:Prod_Vault_Master_PW_2026@vault-db.internal:5432/vault_records"

# Envelope Encryption with RSA-2048 for 30-Year Confidential Medical Records
def encrypt_medical_document(public_key, document_bytes: bytes):
    aes_key = os.urandom(32)
    # Encrypt AES key with RSA-2048 (Vulnerable to HNDL attack)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key, aes_key
`,

  // 5. Mobile API Gateway (TypeScript - TLS 1.0 & Weak Ciphers)
  'services/mobile-gateway/src/gateway/tls_options.ts': `
import tls from 'tls';

// HARDCODED FIREBASE ADMIN PRIVATE KEY
export const FIREBASE_ADMIN_KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3...\\n-----END PRIVATE KEY-----";

// Obsolete TLS 1.0 / 1.1 Configuration (Non-Compliant)
export const gatewayTlsConfig: tls.TlsOptions = {
  minVersion: 'TLSv1.0',
  maxVersion: 'TLSv1.3',
  ciphers: 'ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-SHA:AES256-SHA',
  rejectUnauthorized: false,
};
`,

  // 6. Infrastructure PKI Certificate Generation (Shell Script)
  'infrastructure/pki/generate_ca_certificates.sh': `
#!/bin/bash
# Enterprise PKI Infrastructure Script

echo "Generating Root CA Private Key (RSA 2048)..."
openssl genrsa -out enterprise-root-ca.key 2048

echo "Generating Certificate Signing Request with SHA-1..."
openssl req -new -sha1 -key enterprise-root-ca.key -out enterprise-root-ca.csr

echo "Creating Self-Signed Root Certificate (10-Year Validity)..."
openssl x509 -req -sha1 -days 3650 -in enterprise-root-ca.csr -signkey enterprise-root-ca.key -out enterprise-root-ca.crt
`,

  // 7. Infrastructure Terraform Cluster Config (HCL)
  'infrastructure/terraform/pki_infrastructure.tf': `
# Terraform PKI Cluster Resource
resource "aws_acm_certificate" "enterprise_cert" {
  domain_name       = "api.qrypto-enterprise.internal"
  key_algorithm     = "RSA_2048"
  validation_method = "DNS"

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# HARDCODED AWS SECRET ACCESS KEY
variable "aws_secret_key" {
  default = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
`,

  // 8. Post-Quantum Cryptography Pilot (Python - NIST PQC FIPS 203/204)
  'services/pqc-pilot/src/pqc/hybrid_kem_engine.py': `
# Qrypto PQC Pilot Module — NIST FIPS 203 / FIPS 204 Implementation
# ML-KEM-768 (Kyber768) + ML-DSA-65 (Dilithium3)

class PostQuantumPilotEngine:
    def __init__(self):
        self.algorithm_kem = "ML-KEM-768"
        self.algorithm_dsa = "ML-DSA-65"

    def encapsulate_hybrid_secret(self, peer_public_key: bytes):
        """
        Hybrid Key Encapsulation combining X25519 and ML-KEM-768.
        Provides classical performance with quantum-resistant protection.
        """
        # ML-KEM-768 encapsulation
        kem_ciphertext = b"MLKEM768_CIPHERTEXT_HEADER_..."
        shared_secret = b"PQ_QUANTUM_SAFE_SHARED_SECRET_32_BYTES"
        return kem_ciphertext, shared_secret

    def sign_transaction_pqc(self, private_key_dsa: bytes, payload: bytes) -> bytes:
        """
        ML-DSA-65 (FIPS 204) Digital Signature generation.
        """
        return b"ML_DSA_65_DIGITAL_SIGNATURE_PAYLOAD"
`
};

// ── Zip Generation ──────────────────────────────────────────────

async function buildZip() {
  console.log('📦 Building qrypto-enterprise-sample.zip...');
  
  for (const [filename, content] of Object.entries(FILES)) {
    zip.file(filename, content.trim());
    console.log(`  + Added: ${filename}`);
  }

  const zipContent = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  
  const outputPath = path.join(__dirname, 'qrypto-enterprise-sample.zip');
  fs.writeFileSync(outputPath, zipContent);

  console.log(`\n✅ Created: ${outputPath} (${(zipContent.length / 1024).toFixed(1)} KB)`);
  console.log('You can now upload qrypto-enterprise-sample.zip in the Qrypto platform!');
}

buildZip().catch(console.error);
