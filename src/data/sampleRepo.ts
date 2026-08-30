// ============================================================
// Qrypto AI Advisor — FinTech Corp Demo Dataset
// Synthetic repository representing a financial services company
// ============================================================

import type { Finding, ServiceNode } from '../types';
import { computeRiskScore } from '../engine/riskEngine';

// Helper to build a finding
function f(
  id: string,
  file: string,
  line: number,
  service: string,
  algorithm: string,
  category: string,
  quantumStatus: string,
  severity: string,
  usage: string,
  pattern: string,
  internetFacing: boolean,
  dataSensitivity: string,
  dataLifetime: number,
  isHardcoded: boolean,
  keySize?: number,
  remediationStatus: string = 'open',
): Finding {
  const riskBreakdown = computeRiskScore({
    quantumStatus: quantumStatus as any,
    baseSeverity: severity as any,
    internetFacing,
    dataSensitivity: dataSensitivity as any,
    dataLifetimeYears: dataLifetime,
    isHardcoded,
    service,
    keySize,
  });

  // Derive classical status independently of quantum status
  const deriveClassicalStatus = (alg: string, qs: string): import('../types').ClassicalStatus => {
    const a = alg.toUpperCase();
    if (['MD5', 'DES', 'RC4', 'SSLv2', 'SSLv3', 'SSLV2', 'SSLV3'].some(x => a.includes(x))) return 'broken';
    if (['SHA-1', 'SHA1', '3DES', 'TDES', 'DESEDE', 'TLS 1.0', 'TLS 1.1'].some(x => a.includes(x))) return 'weak';
    if (['AES-256', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-3', 'TLS 1.3', 'CHACHA20'].some(x => a.includes(x))) return 'strong';
    if (qs === 'classical-weak') return 'weak';
    if (qs === 'adequate' || qs === 'quantum-resistant') return 'adequate';
    return 'adequate';
  };

  return {
    id,
    file,
    line,
    repository: 'fintech-corp/platform',
    project: 'FinTech Corp Platform',
    service,
    language: file.endsWith('.py') ? 'python' : file.endsWith('.java') ? 'java' :
              file.endsWith('.ts') || file.endsWith('.tsx') ? 'typescript' :
              file.endsWith('.js') ? 'javascript' : file.endsWith('.go') ? 'go' : 'unknown',
    algorithm,
    keySize,
    category: category as any,
    usage,
    detectedPattern: pattern,
    confidence: 0.95,
    quantumStatus: quantumStatus as any,
    classicalStatus: deriveClassicalStatus(algorithm, quantumStatus),
    algorithmSeverity: severity as any,
    severity: severity as any,
    severityRationale: `Pre-computed sample finding for ${algorithm}.`,
    internetFacing,
    dataSensitivity: dataSensitivity as any,
    dataLifetimeYears: dataLifetime,
    isCryptoAgile: false,
    isHardcoded,
    riskScore: riskBreakdown.totalScore,
    riskBreakdown,
    remediationStatus: remediationStatus as any,
    migrationPriority: 0,
    recommendedAlgorithm: '',
    migrationStrategy: '',
    owner: service === 'Payment Service' ? 'payments-team' :
           service === 'Authentication Service' ? 'auth-team' :
           service === 'API Gateway' ? 'platform-team' : 'security-team',
    tags: [category, quantumStatus],
    detectedAt: '2026-08-08T04:00:00Z',
  };
}


export const SAMPLE_FINDINGS: Finding[] = [
  // ── PAYMENT SERVICE (Critical) ─────────────────────────────
  f('QG-0001', 'services/payment/src/crypto/signing.py', 83, 'Payment Service', 'RSA', 'public-key', 'vulnerable', 'critical', 'key establishment and signing', "rsa.generate_private_key(65537, 2048)", true, 'critical', 15, true, 2048),
  f('QG-0002', 'services/payment/src/crypto/signing.py', 142, 'Payment Service', 'SHA1withRSA', 'signature', 'classical-weak', 'critical', 'digital signature (weak)', '"SHA1withRSA"', true, 'critical', 15, true),
  f('QG-0003', 'services/payment/src/tls/config.py', 28, 'Payment Service', 'TLS 1.0', 'tls', 'classical-weak', 'critical', 'transport layer security (obsolete)', "'TLSv1'", true, 'critical', 15, true),
  f('QG-0004', 'services/payment/src/auth/verify.py', 67, 'Payment Service', 'MD5', 'hash', 'classical-weak', 'critical', 'hash function (broken)', 'hashlib.md5(data)', true, 'critical', 15, false),
  f('QG-0005', 'services/payment/config/secrets.py', 12, 'Payment Service', 'Stripe API Key', 'secret', 'unknown', 'critical', 'API credential (hardcoded)', 'sk_live_****...92', false, 'critical', 15, true),
  f('QG-0006', 'services/payment/config/secrets.py', 15, 'Payment Service', 'JWT Secret', 'secret', 'unknown', 'critical', 'JWT signing secret (hardcoded)', 'jwt_secret = "****"', false, 'critical', 1, true),
  f('QG-0007', 'services/payment/src/crypto/ecdh_exchange.py', 44, 'Payment Service', 'ECDH', 'key-exchange', 'vulnerable', 'high', 'key exchange', "ec.ECDH()", true, 'critical', 15, false),
  f('QG-0008', 'services/payment/src/crypto/ecdh_exchange.py', 91, 'Payment Service', 'secp256r1', 'public-key', 'vulnerable', 'high', 'elliptic curve', 'prime256v1', true, 'critical', 15, false),
  f('QG-0009', 'services/payment/src/legacy/processor.py', 203, 'Payment Service', '3DES', 'symmetric', 'classical-weak', 'high', 'symmetric encryption (weak)', 'DESede', true, 'critical', 15, true),
  f('QG-0010', 'services/payment/src/legacy/processor.py', 267, 'Payment Service', 'TLS 1.1', 'tls', 'classical-weak', 'critical', 'transport layer security (obsolete)', 'ssl.PROTOCOL_TLSv1_1', true, 'critical', 15, true),

  // ── AUTHENTICATION SERVICE ─────────────────────────────────
  f('QG-0011', 'services/auth/src/jwt/token_service.java', 34, 'Authentication Service', 'RSA', 'public-key', 'vulnerable', 'critical', 'JWT signing (RSA-2048)', 'KeyPairGenerator.getInstance("RSA")', true, 'critical', 5, true, 2048),
  f('QG-0012', 'services/auth/src/jwt/token_service.java', 89, 'Authentication Service', 'SHA-1', 'hash', 'classical-weak', 'high', 'hash function (weak collision resistance)', '"SHA-1"', true, 'high', 5, true),
  f('QG-0013', 'services/auth/src/session/manager.java', 156, 'Authentication Service', 'RSA', 'public-key', 'vulnerable', 'critical', 'session token signing', 'KeyPairGenerator.getInstance("RSA")', true, 'critical', 1, false, 2048),
  f('QG-0014', 'services/auth/src/oauth/handler.java', 77, 'Authentication Service', 'ECDSA', 'signature', 'vulnerable', 'high', 'OAuth token signature', '"ECDSA"', true, 'high', 5, false),
  f('QG-0015', 'services/auth/src/mfa/totp.java', 33, 'Authentication Service', 'SHA-256', 'hash', 'adequate', 'info', 'TOTP hash function', '"SHA-256"', true, 'medium', 1, false),
  f('QG-0016', 'services/auth/config/keys.properties', 8, 'Authentication Service', 'Private Key', 'secret', 'unknown', 'critical', 'private key material (embedded in source)', '-----BEGIN RSA PRIVATE KEY-----', false, 'critical', 5, true),
  f('QG-0017', 'services/auth/src/ldap/connector.java', 44, 'Authentication Service', 'TLS 1.2', 'tls', 'adequate', 'medium', 'LDAP over TLS', 'TLSv1_2', false, 'high', 5, true),
  f('QG-0018', 'services/auth/src/crypto/util.java', 201, 'Authentication Service', 'RSA', 'public-key', 'vulnerable', 'high', 'asymmetric encryption', '"RSA"', false, 'high', 5, true, 2048),

  // ── API GATEWAY ─────────────────────────────────────────────
  f('QG-0019', 'services/gateway/src/middleware/tls.ts', 18, 'API Gateway', 'TLS 1.2', 'tls', 'adequate', 'medium', 'transport layer security', 'TLSv1_2', true, 'medium', 5, true),
  f('QG-0020', 'services/gateway/src/middleware/tls.ts', 22, 'API Gateway', 'TLS 1.3', 'tls', 'adequate', 'info', 'transport layer security (current)', 'TLSv1_3', true, 'medium', 5, true),
  f('QG-0021', 'services/gateway/src/auth/verify.ts', 56, 'API Gateway', 'RSA', 'public-key', 'vulnerable', 'high', 'API signature verification', "'RSA'", true, 'high', 5, false, 2048),
  f('QG-0022', 'services/gateway/src/rate-limit/hash.ts', 34, 'API Gateway', 'MD5', 'hash', 'classical-weak', 'high', 'rate limit key hashing', 'crypto.createHash("md5")', true, 'medium', 1, false),
  f('QG-0023', 'services/gateway/config/cors.ts', 12, 'API Gateway', 'API Key', 'secret', 'unknown', 'critical', 'API credential (hardcoded)', 'api_key = "****...34"', false, 'high', 1, true),

  // ── TRANSACTION SERVICE ─────────────────────────────────────
  f('QG-0024', 'services/transactions/src/crypto/sign.py', 45, 'Transaction Service', 'ECDSA', 'signature', 'vulnerable', 'high', 'transaction signature', 'ec.ECDSA(hashes.SHA256())', true, 'critical', 25, false),
  f('QG-0025', 'services/transactions/src/crypto/sign.py', 88, 'Transaction Service', 'secp384r1', 'public-key', 'vulnerable', 'high', 'elliptic curve parameter', 'secp384r1', true, 'critical', 25, false),
  f('QG-0026', 'services/transactions/src/audit/logger.py', 33, 'Transaction Service', 'SHA-256', 'hash', 'adequate', 'info', 'audit log integrity', 'hashlib.sha256', false, 'high', 10, false),
  f('QG-0027', 'services/transactions/src/legacy/batch.py', 122, 'Transaction Service', 'DES', 'symmetric', 'classical-weak', 'critical', 'symmetric encryption (broken)', 'DES.new(key, DES.MODE_ECB)', false, 'critical', 15, true, 56),
  f('QG-0028', 'services/transactions/src/ledger/verify.py', 67, 'Transaction Service', 'RSA', 'public-key', 'vulnerable', 'high', 'ledger entry signature', "rsa.verify(sig, msg)", true, 'critical', 25, false, 2048),

  // ── USER SERVICE ─────────────────────────────────────────────
  f('QG-0029', 'services/users/src/password/hasher.js', 18, 'User Service', 'MD5', 'hash', 'classical-weak', 'critical', 'password hashing (broken)', "crypto.createHash('md5')", false, 'high', 10, false),
  f('QG-0030', 'services/users/src/password/hasher.js', 45, 'User Service', 'Password Hash', 'hash', 'adequate', 'info', 'password hashing', 'bcrypt.hash', false, 'high', 10, false),
  f('QG-0031', 'services/users/src/crypto/pii_encrypt.py', 78, 'User Service', 'AES-256', 'symmetric', 'adequate', 'info', 'PII encryption', 'AES-256', false, 'critical', 25, false, 256),
  f('QG-0032', 'services/users/src/profile/export.py', 134, 'User Service', 'RSA', 'public-key', 'vulnerable', 'medium', 'user data export signature', '"RSA"', false, 'medium', 10, true, 2048),
  f('QG-0033', 'services/users/config/email.env', 3, 'User Service', 'API Key', 'secret', 'unknown', 'high', 'API credential (hardcoded)', 'api_key = "****...77"', false, 'medium', 1, true),

  // ── DATA LAYER ──────────────────────────────────────────────
  f('QG-0034', 'services/database/src/migration/encrypt.py', 55, 'Data Layer', 'AES-128', 'symmetric', 'adequate', 'low', 'database field encryption', 'AES-128', false, 'critical', 25, false, 128),
  f('QG-0035', 'services/database/src/backup/encrypt.java', 34, 'Data Layer', 'RSA', 'public-key', 'vulnerable', 'high', 'backup encryption key wrapping', 'KeyPairGenerator.getInstance("RSA")', false, 'critical', 25, false, 4096, 'in-progress'),
  f('QG-0036', 'services/database/src/tls/pg_ssl.py', 22, 'Data Layer', 'TLS 1.2', 'tls', 'adequate', 'medium', 'database TLS connection', 'TLSv1_2', false, 'critical', 25, true),
  f('QG-0037', 'services/database/src/backup/encrypt.java', 78, 'Data Layer', 'SHA-256', 'hash', 'adequate', 'info', 'backup integrity hash', '"SHA-256"', false, 'critical', 25, false),
  f('QG-0038', 'services/database/config/db_config.py', 4, 'Data Layer', 'Hardcoded Password', 'secret', 'unknown', 'critical', 'credential (hardcoded)', 'password = "****"', false, 'critical', 1, true),

  // ── PKI/TLS LAYER ───────────────────────────────────────────
  f('QG-0039', 'infrastructure/pki/gen_cert.sh', 12, 'PKI/TLS Layer', 'RSA', 'public-key', 'vulnerable', 'high', 'certificate key generation', 'openssl genrsa 2048', false, 'high', 10, true, 2048),
  f('QG-0040', 'infrastructure/pki/gen_cert.sh', 18, 'PKI/TLS Layer', 'SHA1withRSA', 'signature', 'classical-weak', 'critical', 'certificate signature algorithm', 'sha1WithRSAEncryption', false, 'high', 10, true),
  f('QG-0041', 'infrastructure/tls/nginx.conf', 34, 'PKI/TLS Layer', 'TLS 1.2', 'tls', 'adequate', 'medium', 'web server TLS', 'TLSv1.2', true, 'medium', 5, true),
  f('QG-0042', 'infrastructure/tls/nginx.conf', 35, 'PKI/TLS Layer', 'TLS 1.3', 'tls', 'adequate', 'info', 'web server TLS (current)', 'TLSv1.3', true, 'medium', 5, true),
  f('QG-0043', 'infrastructure/pki/intermediate_ca.py', 89, 'PKI/TLS Layer', 'ECDSA', 'signature', 'vulnerable', 'high', 'CA signature key', 'ec.ECDSA(hashes.SHA256())', false, 'high', 10, false),

  // ── CRYPTO LIBRARY ──────────────────────────────────────────
  f('QG-0044', 'shared/crypto/lib/symmetric.py', 23, 'Crypto Library', 'AES-256', 'symmetric', 'adequate', 'info', 'symmetric encryption', 'AES-256', false, 'medium', 5, false, 256),
  f('QG-0045', 'shared/crypto/lib/symmetric.py', 45, 'Crypto Library', 'ChaCha20', 'symmetric', 'adequate', 'info', 'stream cipher', 'ChaCha20', false, 'medium', 5, false),
  f('QG-0046', 'shared/crypto/lib/hashing.py', 12, 'Crypto Library', 'SHA-256', 'hash', 'adequate', 'info', 'general purpose hash', 'hashlib.sha256', false, 'low', 1, false),
  f('QG-0047', 'shared/crypto/lib/hashing.py', 28, 'Crypto Library', 'SHA-512', 'hash', 'adequate', 'info', 'general purpose hash', 'hashlib.sha512', false, 'low', 1, false),
  f('QG-0048', 'shared/crypto/lib/asymmetric.py', 67, 'Crypto Library', 'RSA', 'public-key', 'vulnerable', 'high', 'asymmetric encryption helper', '"RSA"', false, 'medium', 5, true, 2048),
  f('QG-0049', 'shared/crypto/lib/asymmetric.py', 112, 'Crypto Library', 'ECDH', 'key-exchange', 'vulnerable', 'high', 'key exchange helper', 'ec.ECDH()', false, 'medium', 5, false),

  // ── CONFIGURATION ───────────────────────────────────────────
  f('QG-0050', 'config/security.yaml', 14, 'Configuration', 'TLS 1.2', 'tls', 'adequate', 'medium', 'application TLS config', 'min_tls_version: TLSv1.2', true, 'low', 5, true),
  f('QG-0051', 'config/security.yaml', 22, 'Configuration', 'AES-256', 'symmetric', 'adequate', 'info', 'encryption algorithm config', 'encryption_algorithm: AES-256', false, 'medium', 5, false, 256),
  f('QG-0052', 'config/app.env', 8, 'Configuration', 'AWS Access Key', 'secret', 'unknown', 'critical', 'AWS credential (hardcoded)', 'AKIA****...XZ', false, 'critical', 1, true),
  f('QG-0053', 'config/app.env', 9, 'Configuration', 'Hardcoded Password', 'secret', 'unknown', 'critical', 'credential (hardcoded)', 'DB_PASSWORD = "****"', false, 'critical', 1, true),

  // ── LEGACY / MIGRATION IN PROGRESS ──────────────────────────
  f('QG-0054', 'services/payment/src/crypto/pqc_poc.py', 5, 'Payment Service', 'ML-KEM', 'pqc', 'quantum-resistant', 'info', 'post-quantum key encapsulation (PoC)', 'kyber768.keygen()', true, 'critical', 15, false, undefined, 'in-progress'),
  f('QG-0055', 'services/auth/src/crypto/pqc_sig.java', 12, 'Authentication Service', 'ML-DSA', 'pqc', 'quantum-resistant', 'info', 'post-quantum digital signature (PoC)', 'dilithium.sign()', true, 'critical', 5, false, undefined, 'in-progress'),

  // ── TEST SUITE (lower risk) ──────────────────────────────────
  f('QG-0056', 'tests/unit/crypto/test_signing.py', 45, 'Test Suite', 'RSA', 'public-key', 'vulnerable', 'low', 'test key generation', '"RSA"', false, 'low', 1, true, 1024),
  f('QG-0057', 'tests/unit/crypto/test_hashing.py', 18, 'Test Suite', 'MD5', 'hash', 'classical-weak', 'low', 'test hash comparison', 'hashlib.md5', false, 'low', 1, false),
  f('QG-0058', 'tests/integration/payment/test_flow.py', 89, 'Test Suite', 'SHA-256', 'hash', 'adequate', 'info', 'test integrity check', 'hashlib.sha256', false, 'low', 1, false),
];

// Set migration priorities based on risk score
SAMPLE_FINDINGS.sort((a, b) => b.riskScore - a.riskScore);
SAMPLE_FINDINGS.forEach((f, i) => { f.migrationPriority = i + 1; });

// ─── Service Graph ────────────────────────────────────────────

export const SAMPLE_SERVICES: ServiceNode[] = [
  {
    id: 'internet',
    name: 'Internet',
    type: 'internet',
    internetFacing: true,
    dataSensitivity: 'low',
    cryptoFindings: [],
    riskScore: 0,
    dependencies: [],
    position: { x: 400, y: 20 },
  },
  {
    id: 'gateway',
    name: 'API Gateway',
    type: 'gateway',
    internetFacing: true,
    dataSensitivity: 'medium',
    cryptoFindings: ['QG-0019', 'QG-0020', 'QG-0021', 'QG-0022', 'QG-0023'],
    riskScore: 72,
    dependencies: ['internet'],
    position: { x: 400, y: 130 },
  },
  {
    id: 'auth',
    name: 'Authentication Service',
    type: 'auth',
    internetFacing: true,
    dataSensitivity: 'critical',
    cryptoFindings: ['QG-0011', 'QG-0012', 'QG-0013', 'QG-0014', 'QG-0016', 'QG-0018'],
    riskScore: 91,
    dependencies: ['gateway'],
    position: { x: 200, y: 260 },
  },
  {
    id: 'payment',
    name: 'Payment Service',
    type: 'service',
    internetFacing: true,
    dataSensitivity: 'critical',
    cryptoFindings: ['QG-0001', 'QG-0002', 'QG-0003', 'QG-0004', 'QG-0007', 'QG-0009'],
    riskScore: 96,
    dependencies: ['gateway', 'auth'],
    position: { x: 580, y: 260 },
  },
  {
    id: 'transactions',
    name: 'Transaction Service',
    type: 'service',
    internetFacing: true,
    dataSensitivity: 'critical',
    cryptoFindings: ['QG-0024', 'QG-0025', 'QG-0027', 'QG-0028'],
    riskScore: 88,
    dependencies: ['gateway', 'auth'],
    position: { x: 400, y: 390 },
  },
  {
    id: 'users',
    name: 'User Service',
    type: 'service',
    internetFacing: false,
    dataSensitivity: 'high',
    cryptoFindings: ['QG-0029', 'QG-0031', 'QG-0032'],
    riskScore: 65,
    dependencies: ['gateway', 'auth'],
    position: { x: 120, y: 390 },
  },
  {
    id: 'pki',
    name: 'PKI/TLS Layer',
    type: 'service',
    internetFacing: false,
    dataSensitivity: 'high',
    cryptoFindings: ['QG-0039', 'QG-0040', 'QG-0043'],
    riskScore: 78,
    dependencies: ['auth', 'payment'],
    position: { x: 680, y: 390 },
  },
  {
    id: 'database',
    name: 'Financial Database',
    type: 'database',
    internetFacing: false,
    dataSensitivity: 'critical',
    cryptoFindings: ['QG-0034', 'QG-0035', 'QG-0036', 'QG-0038'],
    riskScore: 82,
    dependencies: ['payment', 'transactions', 'users'],
    position: { x: 300, y: 520 },
  },
  {
    id: 'cryptolib',
    name: 'Crypto Library',
    type: 'service',
    internetFacing: false,
    dataSensitivity: 'medium',
    cryptoFindings: ['QG-0048', 'QG-0049'],
    riskScore: 55,
    dependencies: ['auth', 'payment', 'transactions'],
    position: { x: 560, y: 520 },
  },
];

// ─── Scan Statistics ──────────────────────────────────────────

export function computeSampleStats() {
  const findings = SAMPLE_FINDINGS;
  return {
    filesScanned: 47,
    linesScanned: 18432,
    findingsTotal: findings.length,
    criticalCount: findings.filter(f => f.severity === 'critical').length,
    highCount: findings.filter(f => f.severity === 'high').length,
    mediumCount: findings.filter(f => f.severity === 'medium').length,
    lowCount: findings.filter(f => f.severity === 'low' || f.severity === 'info').length,
    vulnerableAlgorithms: findings.filter(f => f.quantumStatus === 'vulnerable').length,
    secretsFound: findings.filter(f => f.category === 'secret').length,
    affectedServices: new Set(findings.map(f => f.service)).size,
  };
}
