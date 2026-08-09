/**
 * Qrypto — Enterprise Sample Repository Dataset
 * Advanced multi-service enterprise codebase containing realistic cryptographic patterns.
 */

export interface EnterpriseSampleFile {
  path: string;
  content: string;
  service: string;
  description: string;
}

export const ENTERPRISE_SAMPLE_FILES: EnterpriseSampleFile[] = [
  {
    service: 'Payment Processing Service',
    path: 'services/payment-processing/src/crypto/payment_signer.py',
    description: 'RSA-2048 signing, ECDH SECP256R1 key exchange, legacy MD5 & SHA-1, AES-256-GCM',
    content: `# Qrypto Enterprise — Payment Processing Service
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RSA-2048 Key Generation for Payment Authorization Signatures (Quantum Vulnerable)
def generate_payment_keypair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

# ECDH Key Exchange for Payment Channel Establishment (Quantum Vulnerable)
def establish_payment_channel():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Legacy SHA-1 Transaction Checksum (Classically Weak)
def compute_legacy_checksum(transaction_payload: bytes) -> str:
    return hashlib.sha1(transaction_payload).hexdigest()

# Legacy MD5 Payment Verification Hash (Classically Broken)
def compute_md5_hash(data: str) -> str:
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# AES-256-GCM Payload Encryption (Quantum-Adequate)
def encrypt_payload(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
`
  },
  {
    service: 'Authentication Identity Service',
    path: 'services/auth-service/src/main/java/com/qrypto/auth/TokenSigner.java',
    description: 'RSA-4096 & ECDSA P-384 token signatures, hardcoded JWT secrets & AWS keys',
    content: `package com.qrypto.auth;

import java.security.*;
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
`
  },
  {
    service: 'Legacy Banking Core Service',
    path: 'services/legacy-banking-core/src/security/des_encryption.go',
    description: '3DES TripleDES cipher, hardcoded 24-byte key, MD5 password digest',
    content: `package security

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/hex"
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
`
  },
  {
    service: 'Document Vault Storage',
    path: 'services/document-vault/src/vault/long_lived_storage.py',
    description: 'RSA-2048 key transport for 30-year retention documents (High HNDL exposure), hardcoded DB password',
    content: `# Qrypto Vault Service — Long-Lived Confidential Document Storage
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
`
  },
  {
    service: 'Mobile API Gateway',
    path: 'services/mobile-gateway/src/gateway/tls_options.ts',
    description: 'Deprecated TLS 1.0 & 1.1 fallback, weak cipher suites (RC4, 3DES), hardcoded Firebase private key',
    content: `import tls from 'tls';

// HARDCODED FIREBASE ADMIN PRIVATE KEY
export const FIREBASE_ADMIN_KEY = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3...\\n-----END PRIVATE KEY-----";

// Obsolete TLS 1.0 / 1.1 Configuration (Non-Compliant)
export const gatewayTlsConfig: tls.TlsOptions = {
  minVersion: 'TLSv1.0',
  maxVersion: 'TLSv1.3',
  ciphers: 'ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-SHA:AES256-SHA',
  rejectUnauthorized: false,
};
`
  },
  {
    service: 'Infrastructure PKI',
    path: 'infrastructure/pki/generate_ca_certificates.sh',
    description: 'Shell script generating RSA-2048 Root CA and SHA-1 certificate signatures',
    content: `#!/bin/bash
# Enterprise PKI Infrastructure Script

echo "Generating Root CA Private Key (RSA 2048)..."
openssl genrsa -out enterprise-root-ca.key 2048

echo "Generating Certificate Signing Request with SHA-1..."
openssl req -new -sha1 -key enterprise-root-ca.key -out enterprise-root-ca.csr

echo "Creating Self-Signed Root Certificate (10-Year Validity)..."
openssl x509 -req -sha1 -days 3650 -in enterprise-root-ca.csr -signkey enterprise-root-ca.key -out enterprise-root-ca.crt
`
  },
  {
    service: 'Terraform Infrastructure',
    path: 'infrastructure/terraform/pki_infrastructure.tf',
    description: 'Terraform HCL manifest configuring RSA-2048 ACM certs and hardcoded AWS secret keys',
    content: `# Terraform PKI Cluster Resource
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
`
  },
  {
    service: 'Post-Quantum Cryptography Pilot',
    path: 'services/pqc-pilot/src/pqc/hybrid_kem_engine.py',
    description: 'Modern PQC pilot implementing NIST ML-KEM-768 (FIPS 203) & ML-DSA-65 (FIPS 204)',
    content: `# Qrypto PQC Pilot Module — NIST FIPS 203 / FIPS 204 Implementation
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
        kem_ciphertext = b"MLKEM768_CIPHERTEXT_HEADER_..."
        shared_secret = b"PQ_QUANTUM_SAFE_SHARED_SECRET_32_BYTES"
        return kem_ciphertext, shared_secret

    def sign_transaction_pqc(self, private_key_dsa: bytes, payload: bytes) -> bytes:
        """
        ML-DSA-65 (FIPS 204) Digital Signature generation.
        """
        return b"ML_DSA_65_DIGITAL_SIGNATURE_PAYLOAD"
`
  }
];
