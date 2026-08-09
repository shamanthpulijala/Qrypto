// ============================================================
// QuantumGuard AI — NovaBank Demo Dataset (§15 & §16)
// Fictional organization representing NovaBank enterprise architecture
// ============================================================

import type { Finding, ServiceNode, ScanStats, Asset, Certificate } from '../types';
import { computeRiskScore } from '../engine/riskEngine';

function nbFinding(
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

  const deriveClassicalStatus = (alg: string, qs: string): import('../types').ClassicalStatus => {
    const a = alg.toUpperCase();
    if (['MD5', 'DES', 'RC4', 'SSLv2', 'SSLv3'].some(x => a.includes(x))) return 'broken';
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
    repository: 'novabank/core-banking',
    project: 'NovaBank Platform',
    service,
    language: file.endsWith('.py') ? 'python' : file.endsWith('.java') ? 'java' :
              file.endsWith('.ts') || file.endsWith('.tsx') ? 'typescript' :
              file.endsWith('.js') ? 'javascript' : file.endsWith('.sh') ? 'unknown' : 'python',
    algorithm,
    keySize,
    category: category as any,
    usage,
    detectedPattern: pattern,
    confidence: 0.96,
    quantumStatus: quantumStatus as any,
    classicalStatus: deriveClassicalStatus(algorithm, quantumStatus),
    severity: severity as any,
    internetFacing,
    dataSensitivity: dataSensitivity as any,
    dataLifetimeYears: dataLifetime,
    isCryptoAgile: false,
    isHardcoded,
    riskScore: riskBreakdown.totalScore,
    riskBreakdown,
    remediationStatus: remediationStatus as any,
    migrationPriority: 0,
    recommendedAlgorithm: getRec(algorithm, category),
    migrationStrategy: getStrat(algorithm, category),
    owner: service.includes('Payment') ? 'payments-engineering' :
           service.includes('Auth') ? 'identity-team' :
           service.includes('Customer') ? 'api-team' : 'secops',
    tags: [category, quantumStatus],
    detectedAt: '2026-08-08T05:00:00Z',
  };
}

function getRec(algorithm: string, category: string): string {
  if (algorithm === 'RSA') return 'ML-KEM (key encapsulation) or ML-DSA (signatures) depending on usage context';
  if (algorithm === 'ECDH') return 'ML-KEM-768 (FIPS 203) — evaluate hybrid X25519+ML-KEM during transition';
  if (algorithm === 'ECDSA') return 'ML-DSA-65 (FIPS 204) for quantum-resistant digital signatures';
  if (algorithm === 'SHA-1') return 'SHA-256 or SHA-3-256';
  if (algorithm === 'MD5') return 'Remove from security usage; use SHA-256 for integrity or Argon2 for passwords';
  if (algorithm.includes('TLS 1.0')) return 'Upgrade to TLS 1.3 (minimum TLS 1.2)';
  if (category === 'secret') return 'Rotate credential immediately and migrate to Vault / AWS Secrets Manager';
  if (algorithm === 'AES-256') return 'Healthy algorithm; no action needed';
  return 'Evaluate modern NIST/PQC alternative';
}

function getStrat(algorithm: string, category: string): string {
  if (category === 'secret') return 'Immediate rotation + secrets manager adoption';
  if (algorithm.includes('TLS')) return 'Configuration change to enforce TLS 1.3';
  if (['MD5', 'SHA-1', '3DES'].includes(algorithm)) return 'Refactor to modern algorithm replacement';
  return 'Phased hybrid migration: maintain classical protection while introducing PQC layer';
}

export const NOVABANK_FINDINGS: Finding[] = [
  // ── 1. PAYMENT SERVICE (Critical) ──────────────────────────
  nbFinding('NB-0001', 'services/payment/src/crypto/exchange.py', 18, 'NovaBank Payment Service', 'ECDH', 'key-exchange', 'vulnerable', 'critical', 'payment channel key exchange', 'ec.ECDH()', true, 'critical', 25, false),
  nbFinding('NB-0002', 'services/payment/src/crypto/exchange.py', 26, 'NovaBank Payment Service', 'secp256r1', 'public-key', 'vulnerable', 'high', 'elliptic curve parameter', 'SECP256R1()', true, 'critical', 25, false),
  nbFinding('NB-0003', 'services/payment/src/crypto/hashing.py', 21, 'NovaBank Payment Service', 'MD5', 'hash', 'classical-weak', 'critical', 'legacy transaction checksum (broken)', 'hashlib.md5(data)', true, 'critical', 25, false),
  nbFinding('NB-0004', 'services/payment/src/crypto/hashing.py', 29, 'NovaBank Payment Service', 'SHA-1', 'hash', 'classical-weak', 'high', 'legacy hash (weak)', 'hashlib.sha1(data)', true, 'critical', 25, false),
  nbFinding('NB-0005', 'services/payment/src/crypto/hashing.py', 37, 'NovaBank Payment Service', 'AES-256', 'symmetric', 'adequate', 'info', 'payment payload encryption (healthy)', 'AES.new(key, AES.MODE_GCM)', true, 'critical', 25, false, 256),
  nbFinding('NB-0006', 'services/payment/src/crypto/pqc_pilot.py', 12, 'NovaBank Payment Service', 'ML-KEM', 'pqc', 'quantum-resistant', 'info', 'post-quantum key encapsulation (pilot)', 'Kyber768', true, 'critical', 25, false, undefined, 'in-progress'),

  // ── 2. AUTHENTICATION SERVICE ──────────────────────────────
  nbFinding('NB-0007', 'services/auth/src/signing.py', 15, 'Authentication Service', 'RSA', 'public-key', 'vulnerable', 'critical', 'JWT private key generation', 'RSA.generate(2048)', true, 'critical', 5, true, 2048),
  nbFinding('NB-0008', 'services/auth/src/signing.py', 24, 'Authentication Service', 'SHA-1', 'hash', 'classical-weak', 'high', 'token signature hash', 'SHA1.new(payload)', true, 'critical', 5, true),
  nbFinding('NB-0009', 'services/auth/src/signing.py', 36, 'Authentication Service', 'JWT Secret', 'secret', 'unknown', 'critical', 'JWT signing secret (hardcoded)', 'JWT_SECRET = "DEMO_JWT_SECRET"', true, 'critical', 1, true),
  nbFinding('NB-0010', 'services/auth/src/signing.py', 39, 'Authentication Service', 'API Key', 'secret', 'unknown', 'critical', 'hardcoded API credential', 'API_KEY = "DEMO_SECRET_DO_NOT_USE"', true, 'critical', 1, true),
  nbFinding('NB-0011', 'services/auth/src/tls/config.py', 12, 'Authentication Service', 'TLS 1.0', 'tls', 'classical-weak', 'critical', 'obsolete transport security', 'ssl.PROTOCOL_TLSv1', true, 'critical', 5, true),
  nbFinding('NB-0012', 'services/auth/src/tls/config.py', 18, 'Authentication Service', 'TLS 1.2', 'tls', 'adequate', 'medium', 'transport layer security', 'TLSVersion.TLSv1_2', true, 'critical', 5, true),
  nbFinding('NB-0013', 'services/auth/src/tls/config.py', 24, 'Authentication Service', 'TLS 1.3', 'tls', 'adequate', 'info', 'current transport security', 'TLSVersion.TLSv1_3', true, 'critical', 5, true),

  // ── 3. LEGACY BANKING SERVICE ──────────────────────────────
  nbFinding('NB-0014', 'services/legacy/src/crypto/legacy_encrypt.py', 15, 'Legacy Banking Service', '3DES', 'symmetric', 'classical-weak', 'critical', 'financial record encryption (weak)', 'DES3.new(LEGACY_KEY, DES3.MODE_ECB)', false, 'critical', 25, true),
  nbFinding('NB-0015', 'services/legacy/src/crypto/legacy_encrypt.py', 21, 'Legacy Banking Service', 'MD5', 'hash', 'classical-weak', 'critical', 'account record checksum', 'hashlib.md5(record.encode())', false, 'critical', 25, false),
  nbFinding('NB-0016', 'services/legacy/src/crypto/legacy_encrypt.py', 26, 'Legacy Banking Service', 'RSA', 'public-key', 'vulnerable', 'critical', 'inter-system auth key', 'RSA.generate(2048)', false, 'critical', 25, true, 2048),
  nbFinding('NB-0017', 'services/legacy/src/crypto/legacy_encrypt.py', 30, 'Legacy Banking Service', 'TLS 1.0', 'tls', 'classical-weak', 'critical', 'SWIFT/FTP tunnel security', 'ssl.PROTOCOL_TLSv1', false, 'critical', 25, true),

  // ── 4. CUSTOMER API ────────────────────────────────────────
  nbFinding('NB-0018', 'services/customer-api/src/auth/verify.ts', 8, 'Customer API', 'API Key', 'secret', 'unknown', 'critical', 'hardcoded API key', 'API_KEY = "DEMO_SECRET_DO_NOT_USE"', true, 'high', 1, true),
  nbFinding('NB-0019', 'services/customer-api/src/auth/verify.ts', 17, 'Customer API', 'RSA', 'public-key', 'vulnerable', 'high', 'customer signature verification', "crypto.createVerify('RSA-SHA256')", true, 'high', 5, false, 2048),
  nbFinding('NB-0020', 'services/customer-api/src/auth/verify.ts', 24, 'Customer API', 'MD5', 'hash', 'classical-weak', 'medium', 'cache key hash', "crypto.createHash('md5')", true, 'high', 1, false),

  // ── 5. MOBILE BACKEND ──────────────────────────────────────
  nbFinding('NB-0021', 'services/mobile/src/push/signing.py', 16, 'Mobile Backend', 'ECDSA', 'signature', 'vulnerable', 'high', 'push notification signature', 'ec.ECDSA(hashes.SHA256())', true, 'high', 5, false),
  nbFinding('NB-0022', 'services/mobile/src/push/signing.py', 27, 'Mobile Backend', 'SHA-256', 'hash', 'adequate', 'info', 'payload integrity hash', 'hashlib.sha256(data)', true, 'high', 5, false),

  // ── 6. DOCUMENT STORAGE ────────────────────────────────────
  nbFinding('NB-0023', 'services/document-storage/src/encrypt.py', 20, 'Document Storage', 'AES-256', 'symmetric', 'adequate', 'info', 'document bulk encryption (healthy)', 'AES.new(key, AES.MODE_GCM)', false, 'critical', 25, false, 256),
  nbFinding('NB-0024', 'services/document-storage/src/encrypt.py', 31, 'Document Storage', 'RSA', 'public-key', 'vulnerable', 'critical', 'document key wrapping (long-lived data)', 'RSA.generate(2048)', false, 'critical', 25, true, 2048),

  // ── 7. INTERNAL ADMIN PORTAL ──────────────────────────────
  nbFinding('NB-0025', 'services/admin/src/auth/config.py', 9, 'Internal Admin Portal', 'Hardcoded Password', 'secret', 'unknown', 'critical', 'database credential in source', 'DB_PASSWORD = "DEMO_ADMIN_PASSWORD..."', false, 'high', 1, true),
  nbFinding('NB-0026', 'services/admin/src/auth/config.py', 14, 'Internal Admin Portal', 'SHA-1', 'hash', 'classical-weak', 'high', 'session token hash', 'hashlib.sha1(...)', false, 'high', 1, false),

  // ── 8. CERTIFICATE INFRASTRUCTURE ─────────────────────────
  nbFinding('NB-0027', 'infrastructure/pki/gen_novabank_cert.sh', 7, 'Certificate Infrastructure', 'RSA', 'public-key', 'vulnerable', 'high', 'CA key generation', 'openssl genrsa 2048', false, 'critical', 10, true, 2048),
  nbFinding('NB-0028', 'infrastructure/pki/gen_novabank_cert.sh', 11, 'Certificate Infrastructure', 'SHA1withRSA', 'signature', 'classical-weak', 'critical', 'CA certificate signature (weak)', 'openssl req -new -sha1', false, 'critical', 10, true),
];

// Sort findings by risk score and assign migration priorities
NOVABANK_FINDINGS.sort((a, b) => b.riskScore - a.riskScore);
NOVABANK_FINDINGS.forEach((f, i) => { f.migrationPriority = i + 1; });

// ─── NovaBank Service Topology (§15) ──────────────────────────
// Internet ↓ API Gateway ↓ Authentication ↓ Payment ↓ Customer DB

export const NOVABANK_SERVICES: ServiceNode[] = [
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
    name: 'NovaBank API Gateway',
    type: 'gateway',
    internetFacing: true,
    dataSensitivity: 'high',
    cryptoFindings: ['NB-0018', 'NB-0019'],
    riskScore: 78,
    dependencies: ['internet'],
    position: { x: 400, y: 120 },
  },
  {
    id: 'customer-api',
    name: 'Customer API',
    type: 'service',
    internetFacing: true,
    dataSensitivity: 'high',
    cryptoFindings: ['NB-0018', 'NB-0019', 'NB-0020'],
    riskScore: 82,
    dependencies: ['gateway'],
    position: { x: 220, y: 220 },
  },
  {
    id: 'mobile-backend',
    name: 'Mobile Backend',
    type: 'service',
    internetFacing: true,
    dataSensitivity: 'high',
    cryptoFindings: ['NB-0021', 'NB-0022'],
    riskScore: 70,
    dependencies: ['gateway'],
    position: { x: 580, y: 220 },
  },
  {
    id: 'auth',
    name: 'Authentication Service',
    type: 'auth',
    internetFacing: true,
    dataSensitivity: 'critical',
    cryptoFindings: ['NB-0007', 'NB-0008', 'NB-0009', 'NB-0010', 'NB-0011', 'NB-0012', 'NB-0013'],
    riskScore: 94,
    dependencies: ['gateway', 'customer-api', 'mobile-backend'],
    position: { x: 400, y: 320 },
  },
  {
    id: 'payment',
    name: 'NovaBank Payment Service',
    type: 'service',
    internetFacing: true,
    dataSensitivity: 'critical',
    cryptoFindings: ['NB-0001', 'NB-0002', 'NB-0003', 'NB-0004', 'NB-0005', 'NB-0006'],
    riskScore: 98,
    dependencies: ['auth'],
    position: { x: 400, y: 440 },
  },
  {
    id: 'legacy-banking',
    name: 'Legacy Banking Service',
    type: 'service',
    internetFacing: false,
    dataSensitivity: 'critical',
    cryptoFindings: ['NB-0014', 'NB-0015', 'NB-0016', 'NB-0017'],
    riskScore: 91,
    dependencies: ['payment'],
    position: { x: 180, y: 440 },
  },
  {
    id: 'doc-storage',
    name: 'Document Storage',
    type: 'storage',
    internetFacing: false,
    dataSensitivity: 'critical',
    cryptoFindings: ['NB-0023', 'NB-0024'],
    riskScore: 86,
    dependencies: ['payment', 'legacy-banking'],
    position: { x: 620, y: 440 },
  },
  {
    id: 'admin-portal',
    name: 'Internal Admin Portal',
    type: 'service',
    internetFacing: false,
    dataSensitivity: 'high',
    cryptoFindings: ['NB-0025', 'NB-0026'],
    riskScore: 75,
    dependencies: ['auth'],
    position: { x: 180, y: 320 },
  },
  {
    id: 'cert-infra',
    name: 'Certificate Infrastructure',
    type: 'service',
    internetFacing: false,
    dataSensitivity: 'critical',
    cryptoFindings: ['NB-0027', 'NB-0028'],
    riskScore: 89,
    dependencies: ['auth', 'payment'],
    position: { x: 620, y: 320 },
  },
  {
    id: 'customer-db',
    name: 'Customer DB',
    type: 'database',
    internetFacing: false,
    dataSensitivity: 'critical',
    cryptoFindings: [],
    riskScore: 85,
    dependencies: ['payment', 'legacy-banking'],
    position: { x: 400, y: 560 },
  },
];

// ─── NovaBank §10 Core Entity Samples ──────────────────────────

export const NOVABANK_ASSETS: Asset[] = [
  { id: 'ast-01', projectId: 'novabank-corp', type: 'service', name: 'NovaBank Payment Service', location: 'services/payment/src', environment: 'production', criticality: 'critical', internetFacing: true, dataSensitivity: 'critical' },
  { id: 'ast-02', projectId: 'novabank-corp', type: 'service', name: 'Authentication Service', location: 'services/auth/src', environment: 'production', criticality: 'critical', internetFacing: true, dataSensitivity: 'critical' },
  { id: 'ast-03', projectId: 'novabank-corp', type: 'service', name: 'Legacy Banking Service', location: 'services/legacy/src', environment: 'production', criticality: 'critical', internetFacing: false, dataSensitivity: 'critical' },
  { id: 'ast-04', projectId: 'novabank-corp', type: 'infrastructure', name: 'Certificate Infrastructure', location: 'infrastructure/pki', environment: 'production', criticality: 'critical', internetFacing: false, dataSensitivity: 'critical' },
  { id: 'ast-05', projectId: 'novabank-corp', type: 'database', name: 'Customer DB', location: 'services/customer-db', environment: 'production', criticality: 'critical', internetFacing: false, dataSensitivity: 'critical' },
  { id: 'ast-06', projectId: 'novabank-corp', type: 'database', name: 'Document Storage', location: 'services/document-storage', environment: 'production', criticality: 'high', internetFacing: false, dataSensitivity: 'critical' },
  { id: 'ast-07', projectId: 'novabank-corp', type: 'service', name: 'Customer API', location: 'services/customer-api', environment: 'production', criticality: 'high', internetFacing: true, dataSensitivity: 'high' },
  { id: 'ast-08', projectId: 'novabank-corp', type: 'service', name: 'Mobile Backend', location: 'services/mobile', environment: 'production', criticality: 'high', internetFacing: true, dataSensitivity: 'high' },
  { id: 'ast-09', projectId: 'novabank-corp', type: 'service', name: 'Internal Admin Portal', location: 'services/admin', environment: 'production', criticality: 'medium', internetFacing: false, dataSensitivity: 'high' },
  { id: 'ast-10', projectId: 'novabank-corp', type: 'infrastructure', name: 'NovaBank API Gateway', location: 'services/gateway', environment: 'production', criticality: 'high', internetFacing: true, dataSensitivity: 'high' },
  { id: 'ast-11', projectId: 'novabank-corp', type: 'config', name: 'Payment Config Secrets', location: 'services/payment/config', environment: 'production', criticality: 'critical', internetFacing: false, dataSensitivity: 'critical' },
  { id: 'ast-12', projectId: 'novabank-corp', type: 'config', name: 'Auth Key Properties', location: 'services/auth/config', environment: 'production', criticality: 'critical', internetFacing: false, dataSensitivity: 'critical' },
  { id: 'ast-13', projectId: 'novabank-corp', type: 'library', name: 'Crypto Shared Library', location: 'shared/crypto', environment: 'production', criticality: 'medium', internetFacing: false, dataSensitivity: 'medium' },
  { id: 'ast-14', projectId: 'novabank-corp', type: 'certificate', name: 'NovaBank Root & Sub-CAs', location: 'infrastructure/pki/certs', environment: 'production', criticality: 'critical', internetFacing: false, dataSensitivity: 'critical' },
];

export const NOVABANK_CERTIFICATES: Certificate[] = [
  {
    id: 'cert-nb-01',
    assetId: 'ast-14',
    subject: 'CN=NovaBank Internal Root CA',
    issuer: 'CN=NovaBank Internal Root CA',
    algorithm: 'SHA1withRSA',
    keySize: 2048,
    validFrom: '2020-01-01T00:00:00Z',
    validTo: '2030-01-01T00:00:00Z',
    tlsVersion: 'TLS 1.0 / TLS 1.2',
    status: 'valid',
  },
  {
    id: 'cert-nb-02',
    assetId: 'ast-14',
    subject: 'CN=payment.novabank.internal',
    issuer: 'CN=NovaBank Internal Root CA',
    algorithm: 'SHA256withRSA',
    keySize: 2048,
    validFrom: '2024-06-01T00:00:00Z',
    validTo: '2026-06-01T00:00:00Z',
    tlsVersion: 'TLS 1.2',
    status: 'expiring',
  },
];

export function computeNovaBankStats(): ScanStats {
  const findings = NOVABANK_FINDINGS;
  return {
    filesScanned: 28,
    linesScanned: 12450,
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
