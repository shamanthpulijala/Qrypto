// ============================================================
// Qrypto AI Advisor — §14 Deliberately Vulnerable Sample Repository
// §15 — NovaBank (fictional organization, no real bank data)
//
// These are SYNTHETIC source files used as scan input.
// They contain intentional cryptographic vulnerabilities for demo.
// DEMO_SECRET_DO_NOT_USE — not real credentials.
// ============================================================

export interface SampleSourceFile {
  path: string;
  content: string;
  service: string;
  description: string;
}

// ─────────────────────────────────────────────────────────────
// §15 — NovaBank Services:
//   Customer API | Payment Service | Authentication Service
//   Mobile Backend | Legacy Banking Service
//   Document Storage | Internal Admin Portal
// ─────────────────────────────────────────────────────────────

export const NOVABANK_SAMPLE_FILES: SampleSourceFile[] = [

  // ── Authentication Service ────────────────────────────────
  {
    service: 'Authentication Service',
    path: 'services/auth/src/signing.py',
    description: 'RSA key generation (quantum-vulnerable), SHA-1 hash (classically weak)',
    content: `"""
NovaBank Authentication Service — JWT Signing
DEMO ONLY — Synthetic vulnerable example for Qrypto scanning.
"""
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, SHA256
import hashlib

# ── RSA Key Generation (§14: RSA.generate(2048)) ──────────────
# QUANTUM-VULNERABLE: RSA-2048 key pair for JWT signing
# Migration target: ML-DSA (FIPS 204) for post-quantum signatures
auth_private_key = RSA.generate(2048)
auth_public_key = auth_private_key.publickey()

def sign_jwt_payload(payload: bytes) -> bytes:
    """Sign JWT payload with RSA-2048 (quantum-vulnerable)."""
    # §14: SHA-1 hash (classically weak, collision attacks known)
    h = SHA1.new(payload)
    return pkcs1_15.new(auth_private_key).sign(h)

def verify_token(token: bytes, signature: bytes) -> bool:
    """Verify token using SHA-1 (WEAK — known collision attacks)."""
    # §14: hashlib.sha1(data) — problematic
    digest = hashlib.sha1(token).hexdigest()
    return True  # simplified for demo

# ── Hardcoded JWT Secret (§14: JWT_SECRET) ──────────────────
# SECRET — must be moved to secrets manager immediately
JWT_SECRET = "DEMO_JWT_SECRET"

# ── Hardcoded API Key (§14: API_KEY) ────────────────────────
API_KEY = "DEMO_SECRET_DO_NOT_USE"
`,
  },

  // ── Payment Service ───────────────────────────────────────
  {
    service: 'NovaBank Payment Service',
    path: 'services/payment/src/crypto/exchange.py',
    description: 'ECDH key exchange (quantum-vulnerable), ECC (quantum-vulnerable)',
    content: `"""
NovaBank Payment Service — Key Exchange
DEMO ONLY — Synthetic vulnerable example for Qrypto scanning.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1

# ── ECDH Key Exchange (§14: ECDH — quantum-vulnerable) ────────
# Migration target: ML-KEM (FIPS 203) — hybrid X25519+ML-KEM during transition
# NOTE: ECDH and ECDSA require DIFFERENT PQC successors:
#   ECDH (key exchange) → ML-KEM
#   ECDSA (signatures)  → ML-DSA

def establish_payment_channel_key():
    """Establish symmetric key via ECDH for payment channel encryption."""
    # §14: ECC curve — secp256r1 (prime256v1)
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # §14: ec.ECDH() — quantum-vulnerable key exchange
    shared_key = ec.ECDH()
    return private_key, shared_key

# ── ECC Key Pair (§14: ECC example) ─────────────────────────
payment_key = ec.generate_private_key(ec.SECP256R1())
payment_public = payment_key.public_key()
`,
  },

  // ── Payment Service — Hashing ─────────────────────────────
  {
    service: 'NovaBank Payment Service',
    path: 'services/payment/src/crypto/hashing.py',
    description: 'MD5 (broken), SHA-1 (weak), AES-256 (healthy)',
    content: `"""
NovaBank Payment Service — Cryptographic Hashing
DEMO ONLY — Synthetic vulnerable example for Qrypto scanning.

IMPORTANT: This file contains both problematic AND healthy examples.
The scanner should correctly distinguish them.
"""
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ── §14: MD5 — BROKEN (not for security use) ────────────────
# MD5 is classically broken — collisions can be computed in minutes.
# Quantum risk is moot: classical attacks already compromise MD5.
# Replace: SHA-256 for integrity; Argon2id for passwords.
def compute_legacy_checksum(data: bytes) -> str:
    """Legacy checksum — DO NOT USE for security."""
    return hashlib.md5(data).hexdigest()  # §14: hashlib.md5(data)

# ── §14: SHA-1 — WEAK (collision attacks) ────────────────────
# SHA-1 has known collision attacks (SHAttered, 2017).
# Replace: SHA-256 or SHA-3-256.
def compute_legacy_hash(data: bytes) -> str:
    """Legacy hash — weak collision resistance."""
    return hashlib.sha1(data).hexdigest()  # §14: hashlib.sha1(data)

# ── §14: AES-256 — HEALTHY (currently acceptable) ────────────
# AES-256 in GCM mode is quantum-adequate (Grover: 2^128 effective).
# No migration needed; acceptable for data at rest protection.
def encrypt_payment_data(plaintext: bytes) -> tuple:
    """Encrypt payment data — AES-256-GCM (HEALTHY)."""
    key = get_random_bytes(32)           # 256-bit key
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # §14: AES-256 healthy
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, key, nonce

# SHA-256 for payment audit log integrity (healthy)
def hash_audit_log(entry: str) -> str:
    """Hash audit log entry — SHA-256 (adequate)."""
    return hashlib.sha256(entry.encode()).hexdigest()
`,
  },

  // ── Authentication Service — TLS ─────────────────────────
  {
    service: 'Authentication Service',
    path: 'services/auth/src/tls/config.py',
    description: 'TLS 1.0 (obsolete), TLS 1.2, TLS 1.3',
    content: `"""
NovaBank Authentication Service — TLS Configuration
DEMO ONLY — Synthetic vulnerable example for Qrypto scanning.
"""
import ssl

# ── §14: TLS 1.0 — OBSOLETE (BEAST, POODLE attacks) ─────────
# TLS 1.0 deprecated by RFC 8996.
# Replace: TLS 1.3 (minimum: TLS 1.2 with strong cipher suites).
LEGACY_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # §14: ssl.PROTOCOL_TLSv1

# ── TLS 1.2 — Adequate (classical) ──────────────────────────
# TLS 1.2 is acceptable classically but prefer TLS 1.3.
# Plan: add X25519Kyber768 PQC hybrid cipher suite.
TLS_12_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
TLS_12_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_2

# ── TLS 1.3 — Current Best ───────────────────────────────────
# TLS 1.3 with PQC cipher suite support (evaluate X25519Kyber768).
TLS_13_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
TLS_13_CONTEXT.minimum_version = ssl.TLSVersion.TLSv1_3

def get_auth_tls_context(legacy_client: bool = False) -> ssl.SSLContext:
    """Return appropriate TLS context."""
    if legacy_client:
        return LEGACY_TLS_CONTEXT  # WARNING: TLS 1.0 — problematic
    return TLS_13_CONTEXT           # Preferred: TLS 1.3
`,
  },

  // ── Legacy Banking Service ────────────────────────────────
  {
    service: 'Legacy Banking Service',
    path: 'services/legacy/src/crypto/legacy_encrypt.py',
    description: '3DES (weak), MD5 (broken), TLS 1.0 (obsolete), RSA-2048 (quantum-vulnerable)',
    content: `"""
NovaBank Legacy Banking Service — LEGACY CRYPTOGRAPHY
DEMO ONLY — This service has not been updated since 2008.
Contains multiple critical and high-severity issues.
"""
import hashlib
import ssl
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA

# ── 3DES — WEAK (Sweet32 attack, legacy compliance issue) ────
# 3DES uses 112-bit effective key — vulnerable to Sweet32 attack.
# Replace: AES-256-GCM immediately.
LEGACY_KEY = b'NovaBank24ByteKey012345'  # 24 bytes for 3DES
def encrypt_legacy_record(data: bytes) -> bytes:
    """Encrypt using 3DES — LEGACY, must replace."""
    cipher = DES3.new(LEGACY_KEY, DES3.MODE_ECB)  # 3DES — weak
    return cipher.encrypt(data.ljust(8))

# ── MD5 for account record checksums (broken) ────────────────
def checksum_account_record(record: str) -> str:
    return hashlib.md5(record.encode()).hexdigest()

# ── RSA-2048 for inter-system authentication ─────────────────
# Quantum-vulnerable — plan hybrid ML-KEM/ML-DSA migration.
legacy_auth_key = RSA.generate(2048)

# ── TLS 1.0 for SWIFT/FTP connections ────────────────────────
# Long-lived financial data protected by TLS 1.0 — critical HNDL risk.
SWIFT_TLS_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLS 1.0 — obsolete

# Long-lived data: financial records must remain confidential for 25+ years.
# HNDL (Harvest Now, Decrypt Later) is a HIGH risk given TLS 1.0 + RSA usage.
DATA_RETENTION_YEARS = 25
`,
  },

  // ── Customer API ──────────────────────────────────────────
  {
    service: 'Customer API',
    path: 'services/customer-api/src/auth/verify.ts',
    description: 'RSA signature verification, hardcoded API key, TLS 1.2',
    content: `/**
 * NovaBank Customer API — Authentication & Signature Verification
 * DEMO ONLY — Synthetic vulnerable example for Qrypto scanning.
 */
import crypto from 'crypto';

// Hardcoded API key — must move to secrets manager
const API_KEY = "DEMO_SECRET_DO_NOT_USE";

// RSA signature verification (quantum-vulnerable)
export function verifyCustomerSignature(
  data: Buffer,
  signature: Buffer,
  publicKeyPem: string
): boolean {
  // RSA-SHA256 — quantum-vulnerable (RSA component)
  const verify = crypto.createVerify('RSA-SHA256');
  verify.update(data);
  return verify.verify(publicKeyPem, signature);
}

// MD5 for cache key hashing (broken — not security-sensitive but poor practice)
export function getCacheKey(customerId: string): string {
  return crypto.createHash('md5').update(customerId).digest('hex');
}

// TLS 1.2 for upstream calls (adequate, prefer 1.3)
export const TLS_OPTIONS = {
  minVersion: 'TLSv1.2' as const,
  maxVersion: 'TLSv1.3' as const,
};
`,
  },

  // ── Mobile Backend ────────────────────────────────────────
  {
    service: 'Mobile Backend',
    path: 'services/mobile/src/push/signing.py',
    description: 'ECDSA signing (quantum-vulnerable), SHA-256 (healthy)',
    content: `"""
NovaBank Mobile Backend — Push Notification Signing
DEMO ONLY — Synthetic vulnerable example for Qrypto scanning.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# ECDSA signing for push notifications (quantum-vulnerable signatures)
# Migration target: ML-DSA (FIPS 204) for post-quantum digital signatures
# Note: ECDSA (signatures) → ML-DSA; ECDH (key exchange) → ML-KEM (different!)

mobile_signing_key = ec.generate_private_key(ec.SECP384R1())

def sign_push_notification(payload: bytes) -> bytes:
    """Sign push notification with ECDSA-SHA256 (quantum-vulnerable)."""
    # ec.ECDSA(hashes.SHA256()) — quantum-vulnerable signature
    return mobile_signing_key.sign(payload, ec.ECDSA(hashes.SHA256()))

def verify_push_notification(payload: bytes, sig: bytes, pub_key) -> bool:
    """Verify ECDSA signature — quantum-vulnerable."""
    pub_key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
    return True

# SHA-256 for payload integrity (healthy)
import hashlib
def payload_integrity_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
`,
  },

  // ── Document Storage ──────────────────────────────────────
  {
    service: 'Document Storage',
    path: 'services/document-storage/src/encrypt.py',
    description: 'AES-256 for document encryption (healthy), RSA for key wrapping (quantum-vulnerable)',
    content: `"""
NovaBank Document Storage — Document Encryption
DEMO ONLY — Contains both healthy (AES-256) and vulnerable (RSA) patterns.

AES-256 for bulk document encryption — HEALTHY (quantum-adequate).
RSA-2048 for key wrapping — QUANTUM-VULNERABLE.
Long-lived financial documents: 25-year retention requirement.
"""
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib

# ── AES-256 Document Encryption — HEALTHY ───────────────────
# AES-256 is quantum-adequate (Grover: 2^128 effective security).
# No immediate migration needed for symmetric encryption.
def encrypt_document(document: bytes) -> dict:
    """Encrypt document with AES-256-GCM — HEALTHY."""
    key = get_random_bytes(32)       # 256-bit AES key
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(document)
    return {'ciphertext': ciphertext, 'tag': tag, 'key': key, 'nonce': nonce}

# ── RSA-2048 Key Wrapping — QUANTUM-VULNERABLE ───────────────
# RSA used to wrap (encrypt) the AES document key.
# Long-lived documents protected by RSA key wrapping = HIGH HNDL risk.
# Migration: Replace RSA key wrapping with ML-KEM (FIPS 203).
doc_master_key = RSA.generate(2048)
def wrap_document_key(aes_key: bytes) -> bytes:
    """Wrap document key with RSA-2048 — quantum-vulnerable."""
    from Crypto.Cipher import PKCS1_OAEP
    cipher = PKCS1_OAEP.new(doc_master_key)
    return cipher.encrypt(aes_key)

# Document integrity: SHA-256 (healthy)
def document_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
`,
  },

  // ── Internal Admin Portal ─────────────────────────────────
  {
    service: 'Internal Admin Portal',
    path: 'services/admin/src/auth/config.py',
    description: 'Hardcoded DB password, TLS 1.2, SHA-1 for legacy sessions',
    content: `"""
NovaBank Internal Admin Portal — Configuration
DEMO ONLY — Synthetic vulnerable example.
"""
import hashlib

# ── Hardcoded database password — critical (move to Vault) ───
DB_PASSWORD = "DEMO_ADMIN_PASSWORD_DO_NOT_USE"
DB_HOST = "postgres://admin:DEMO_ADMIN_PASSWORD_DO_NOT_USE@db.novabank.internal/admin"

# ── SHA-1 for legacy session tokens (weak) ───────────────────
def create_session_token(user_id: str, timestamp: str) -> str:
    """Create session token — SHA-1 (WEAK, should use SHA-256 + HMAC)."""
    return hashlib.sha1(f"{user_id}{timestamp}".encode()).hexdigest()

# ── JWT Secret (hardcoded) ────────────────────────────────────
JWT_SECRET = "DEMO_JWT_SECRET"

# ── API key for internal reporting service ────────────────────
API_KEY = "DEMO_SECRET_DO_NOT_USE"
`,
  },

  // ── PKI / Certificate Infrastructure ─────────────────────
  {
    service: 'Certificate Infrastructure',
    path: 'infrastructure/pki/gen_novabank_cert.sh',
    description: 'Certificate generation with SHA-1 (classically weak)',
    content: `#!/bin/bash
# NovaBank PKI — Certificate Generation
# DEMO ONLY — Synthetic vulnerable example.

# RSA-2048 key generation (quantum-vulnerable)
# Migration: Plan re-issuance with ML-DSA or hybrid algorithm
openssl genrsa 2048 -out novabank-ca.key

# Certificate signing with SHA-1 (classically weak — collision attacks known)
# Replace: SHA-256 or SHA-384 signing algorithm
openssl req -new -sha1 -key novabank-ca.key -out novabank-ca.csr

# Generate SHA1withRSA certificate (PROBLEMATIC)
openssl x509 -req -sha1 -days 365 -in novabank-ca.csr -signkey novabank-ca.key -out novabank-ca.crt

# TLS 1.2 configuration for web servers (adequate, plan TLS 1.3)
echo "ssl_protocols TLSv1.2 TLSv1.3;" > /etc/nginx/tls.conf

echo "sha1WithRSAEncryption" >> cert-algorithm.log
`,
  },

  // ── PQC Pilot (positive findings) ────────────────────────
  {
    service: 'NovaBank Payment Service',
    path: 'services/payment/src/crypto/pqc_pilot.py',
    description: 'ML-KEM pilot (quantum-resistant) — positive finding',
    content: `"""
NovaBank Payment Service — PQC Pilot (Phase 2 Proof of Concept)
This module explores ML-KEM integration for future key establishment.
NOT production-ready — evaluation only.
"""

# ML-KEM (CRYSTALS-Kyber) — Post-Quantum Key Encapsulation (FIPS 203)
# This is a positive finding — the team is already evaluating PQC.
# Migration status: in-progress (PoC phase)
# Target: Hybrid X25519+ML-KEM-768 for payment channel key establishment.

# from oqs import KeyEncapsulation  # requires liboqs
# ml_kem = KeyEncapsulation('Kyber768')  # ML-KEM-768 (FIPS 203)

# ML-DSA (CRYSTALS-Dilithium) pilot for signatures
# ml_dsa = Signature('Dilithium3')  # ML-DSA-65 (FIPS 204)

# For now: placeholder — implement when library support is stable
def mlkem_keygen_placeholder():
    """Placeholder for ML-KEM-768 key generation."""
    raise NotImplementedError(
        "ML-KEM integration pending. See FIPS 203 and liboqs documentation. "
        "Use hybrid X25519+ML-KEM-768 during transition period."
    )
`,
  },
];

// ─── File lookup by service ──────────────────────────────────

export function getNovaBankFilesByService(service: string): SampleSourceFile[] {
  return NOVABANK_SAMPLE_FILES.filter(f => f.service === service);
}

export function getAllNovaBankFiles(): { path: string; content: string }[] {
  return NOVABANK_SAMPLE_FILES.map(f => ({ path: f.path, content: f.content }));
}
