// ============================================================
// Qrypto — X.509 Certificate Parser
//
// Uses Node.js built-in crypto.X509Certificate for real parsing.
// Falls back to regex for environments without X509Certificate
// (browsers, older Node.js).
//
// Extracts only actual certificate information — never invents values.
// ============================================================

import type { Finding } from '../types';

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  publicKeyAlgorithm: string;
  keySize: number | undefined;
  signatureAlgorithm: string;
  sans: string[];
  isExpired: boolean;
  isExpiringSoon: boolean; // within 30 days
  daysUntilExpiry: number;
  weakSignature: boolean;
  rawPem: string;
}

// ─── Weak signature algorithms ───────────────────────────────

const WEAK_SIGNATURES = new Set([
  'md5', 'md5withrsa', 'sha1', 'sha1withrsa', 'sha1withrsaoaevp',
  'sha1withdsa', 'dsaWithSHA1', 'ecdsaWithSHA1',
]);

// ─── Parser using Node.js X509Certificate ────────────────────

function parseWithX509Class(pem: string): CertificateInfo | null {
  try {
    // Node.js 15+ has X509Certificate
    const X509Certificate = (globalThis as any).crypto?.X509Certificate
      || require('crypto').X509Certificate;

    if (!X509Certificate) return null;

    const cert = new X509Certificate(pem);

    const subject = cert.subject || '';
    const issuer = cert.issuer || '';
    const serialNumber = cert.serialNumber || '';
    const validFrom = cert.validFrom || '';
    const validTo = cert.validTo || '';

    // Parse key info from public key
    let publicKeyAlgorithm = 'unknown';
    let keySize: number | undefined;

    try {
      const keyInfo = cert.publicKey?.asymmetricKeyType;
      if (keyInfo) publicKeyAlgorithm = keyInfo;

      const keyDetail = cert.publicKey?.asymmetricKeySize;
      if (keyDetail) keySize = keyDetail;
    } catch { /* key info not available */ }

    // Signature algorithm
    const sigAlg = cert.signatureAlgorithm?.name || cert.sigAlg || 'unknown';

    // SANs
    const sans: string[] = [];
    try {
      const sanExt = cert.subjectAltName;
      if (sanExt) {
        // Parse "DNS:example.com, IP Address:1.2.3.4" format
        const parts = sanExt.split(',').map((s: string) => s.trim());
        for (const part of parts) {
          const value = part.replace(/^(DNS|IP Address|URI|email):/i, '').trim();
          if (value) sans.push(value);
        }
      }
    } catch { /* SANs not available */ }

    // Expiry check
    const now = new Date();
    const expiryDate = new Date(validTo);
    const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    const isExpired = daysUntilExpiry < 0;
    const isExpiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;

    // Weak signature check
    const weakSignature = WEAK_SIGNATURES.has(sigAlg.toLowerCase()) ||
      WEAK_SIGNATURES.has(publicKeyAlgorithm.toLowerCase());

    return {
      subject,
      issuer,
      serialNumber,
      validFrom,
      validTo,
      publicKeyAlgorithm,
      keySize,
      signatureAlgorithm: sigAlg,
      sans,
      isExpired,
      isExpiringSoon,
      daysUntilExpiry,
      weakSignature,
      rawPem: pem,
    };
  } catch {
    return null;
  }
}

// ─── Regex fallback for environments without X509Certificate ──

function parseWithRegex(pem: string): CertificateInfo | null {
  try {
    // Extract base64 content between PEM markers
    const base64Match = pem.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
    if (!base64Match) return null;

    // Basic regex extraction from PEM text (limited but functional)
    const subjectMatch = pem.match(/Subject:.*?CN\s*=\s*([^\n\/]+)/i);
    const issuerMatch = pem.match(/Issuer:.*?CN\s*=\s*([^\n\/]+)/i);
    const serialMatch = pem.match(/Serial Number:\s*\n?\s*([0-9a-fA-F:\s]+)/i);
    const notBeforeMatch = pem.match(/Not Before:\s*(.+)/i);
    const notAfterMatch = pem.match(/Not After\s*:\s*(.+)/i);
    const sigAlgMatch = pem.match(/Signature Algorithm:\s*(\S+)/i);

    const subject = subjectMatch?.[1]?.trim() || 'unknown';
    const issuer = issuerMatch?.[1]?.trim() || 'unknown';
    const serialNumber = serialMatch?.[1]?.trim()?.replace(/\s/g, '') || 'unknown';
    const validFrom = notBeforeMatch?.[1]?.trim() || '';
    const validTo = notAfterMatch?.[1]?.trim() || '';
    const signatureAlgorithm = sigAlgMatch?.[1]?.trim() || 'unknown';

    if (!validTo) return null;

    const now = new Date();
    const expiryDate = new Date(validTo);
    const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    const isExpired = daysUntilExpiry < 0;
    const isExpiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;

    const weakSignature = WEAK_SIGNATURES.has(signatureAlgorithm.toLowerCase());

    return {
      subject,
      issuer,
      serialNumber,
      validFrom,
      validTo,
      publicKeyAlgorithm: 'unknown',
      keySize: undefined,
      signatureAlgorithm,
      sans: [],
      isExpired,
      isExpiringSoon,
      daysUntilExpiry,
      weakSignature,
      rawPem: pem,
    };
  } catch {
    return null;
  }
}

// ─── Main parser ──────────────────────────────────────────────

export function parseCertificate(pem: string): CertificateInfo | null {
  // Try X509Certificate first (real parsing)
  const x509Result = parseWithX509Class(pem);
  if (x509Result) return x509Result;

  // Fallback to regex (limited but functional)
  return parseWithRegex(pem);
}

// ─── Extract certificates from file content ───────────────────

export function extractCertificates(content: string, filePath: string): CertificateInfo[] {
  const certs: CertificateInfo[] = [];

  // Match PEM certificates
  const pemRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match;

  while ((match = pemRegex.exec(content)) !== null) {
    const pem = match[0];
    const cert = parseCertificate(pem);
    if (cert) {
      certs.push(cert);
    }
  }

  return certs;
}

// ─── Create findings from certificate info ────────────────────

export function createCertificateFindings(
  certs: CertificateInfo[],
  filePath: string,
  repository: string,
  project: string,
): Partial<Finding>[] {
  const findings: Partial<Finding>[] = [];

  for (const cert of certs) {
    // Determine severity based on certificate properties
    let severity: Finding['severity'] = 'info';
    let quantumStatus: Finding['quantumStatus'] = 'adequate';
    let usage = 'X.509 certificate';

    if (cert.isExpired) {
      severity = 'critical';
      usage = 'X.509 certificate (EXPIRED)';
    } else if (cert.isExpiringSoon) {
      severity = 'high';
      usage = `X.509 certificate (expires in ${cert.daysUntilExpiry} days)`;
    }

    if (cert.weakSignature) {
      severity = severity === 'info' ? 'high' : severity;
      quantumStatus = 'classical-weak';
      usage += ' [weak signature algorithm]';
    }

    // Check key algorithm
    const alg = cert.publicKeyAlgorithm.toLowerCase();
    if (alg.includes('rsa') || alg.includes('ec') || alg.includes('dsa')) {
      quantumStatus = 'vulnerable';
      if (severity === 'info') severity = 'low';
    }

    findings.push({
      file: filePath,
      line: 1, // PEM certs are typically whole-file
      repository,
      project,
      service: 'PKI/TLS Layer',
      language: 'unknown',
      algorithm: cert.publicKeyAlgorithm !== 'unknown' ? cert.publicKeyAlgorithm.toUpperCase() : 'X.509',
      keySize: cert.keySize,
      category: 'certificate',
      usage,
      detectedPattern: `Subject: ${cert.subject}, Issuer: ${cert.issuer}`,
      confidence: 0.95,
      quantumStatus,
      classicalStatus: cert.weakSignature ? 'weak' : 'adequate',
      algorithmSeverity: severity,
      severity,
      severityRationale: `Certificate ${cert.isExpired ? 'is expired' : cert.isExpiringSoon ? `expires in ${cert.daysUntilExpiry} days` : 'is valid'}. ${cert.weakSignature ? 'Uses weak signature algorithm.' : ''}`,
      internetFacing: false,
      dataSensitivity: 'medium',
      dataLifetimeYears: 1,
      isCryptoAgile: false,
      isHardcoded: false,
      riskScore: cert.isExpired ? 90 : cert.isExpiringSoon ? 70 : cert.weakSignature ? 60 : 20,
      riskBreakdown: {
        algorithmRisk: cert.weakSignature ? 80 : 20,
        businessCriticality: 50,
        internetExposure: 30,
        dataLifetime: 10,
        dataSensitivity: 50,
        migrationDifficulty: 30,
        totalScore: cert.isExpired ? 90 : cert.isExpiringSoon ? 70 : cert.weakSignature ? 60 : 20,
      },
      remediationStatus: 'open',
      migrationPriority: 0,
      recommendedAlgorithm: cert.weakSignature
        ? 'Upgrade to SHA-256 or stronger signature algorithm'
        : 'Monitor expiration and renew before expiry',
      migrationStrategy: cert.isExpired
        ? 'Immediate renewal required'
        : cert.isExpiringSoon
          ? 'Schedule certificate renewal'
          : 'Monitor and plan renewal',
      tags: ['certificate', ...(cert.isExpired ? ['expired'] : []), ...(cert.weakSignature ? ['weak-signature'] : [])],
      contextSource: 'EXPLICIT', // from actual certificate data
      detectedAt: new Date().toISOString(),
      evidence: {
        detectionLayers: ['certificate'],
        matchedText: `Subject: ${cert.subject}`,
        confidenceDerivation: `Certificate parsed from PEM. Subject: ${cert.subject}, Issuer: ${cert.issuer}, Expires: ${cert.validTo}.`,
      },
    });
  }

  return findings;
}
