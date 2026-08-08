// ============================================================
// QuantumGuard AI — HNDL (Harvest Now, Decrypt Later) Analyzer
// ============================================================

import type { HNDLAssessment, Finding } from '../types';

const DATA_CATEGORIES = [
  { category: 'Payment Card Data (PCI)', defaultLifetime: '10–25 years', sensitiveLifetime: true },
  { category: 'Customer Financial Records', defaultLifetime: '10–25 years', sensitiveLifetime: true },
  { category: 'Authentication Credentials', defaultLifetime: '1–5 years', sensitiveLifetime: false },
  { category: 'Personal Identifiable Information (PII)', defaultLifetime: '5–10 years', sensitiveLifetime: true },
  { category: 'Medical/Health Records (PHI)', defaultLifetime: '25+ years', sensitiveLifetime: true },
  { category: 'Intellectual Property / Trade Secrets', defaultLifetime: '25+ years', sensitiveLifetime: true },
  { category: 'Communications / Messages', defaultLifetime: '5–10 years', sensitiveLifetime: false },
  { category: 'Session Tokens / API Keys', defaultLifetime: '<1 year', sensitiveLifetime: false },
  { category: 'Audit Logs', defaultLifetime: '5–10 years', sensitiveLifetime: false },
  { category: 'Encryption Keys', defaultLifetime: '1–5 years', sensitiveLifetime: true },
];

function lifetimeToRisk(lifetime: string, protectedBy: string): 'very-high' | 'high' | 'medium' | 'low' {
  const isVulnerable = protectedBy.includes('RSA') || protectedBy.includes('ECC') ||
    protectedBy.includes('ECDH') || protectedBy.includes('ECDSA') || protectedBy.includes('DH');

  if (!isVulnerable) return 'low';

  if (lifetime === '25+ years') return 'very-high';
  if (lifetime === '10–25 years') return 'high';
  if (lifetime === '5–10 years') return 'medium';
  return 'low';
}

export function generateHNDLAssessments(findings: Finding[]): HNDLAssessment[] {
  const vulnerableAlgs = findings.filter(
    f => f.quantumStatus === 'vulnerable'
  );

  const protectedBy = [...new Set(vulnerableAlgs.map(f => f.algorithm))].join(', ') || 'RSA/ECC-based infrastructure';

  return DATA_CATEGORIES.map(dc => {
    const hndlRisk = lifetimeToRisk(dc.defaultLifetime, protectedBy);
    const affectedFindings = vulnerableAlgs
      .filter(f => {
        if (dc.category.includes('Payment') && f.service === 'Payment Service') return true;
        if (dc.category.includes('Authentication') && f.service === 'Authentication Service') return true;
        if (dc.category.includes('Encryption Keys') && f.category === 'secret') return true;
        return dc.sensitiveLifetime && f.dataSensitivity === 'critical';
      })
      .map(f => f.id)
      .slice(0, 5);

    return {
      dataCategory: dc.category,
      confidentialityLifetime: dc.defaultLifetime,
      currentProtection: protectedBy || 'Not determined',
      hndlRisk,
      explanation: generateExplanation(dc.category, dc.defaultLifetime, hndlRisk, protectedBy),
      affectedFindings,
    };
  });
}

function generateExplanation(category: string, lifetime: string, risk: string, protection: string): string {
  const prefix = risk === 'very-high' ? 'Very High HNDL Concern' :
                 risk === 'high'      ? 'High HNDL Concern' :
                 risk === 'medium'    ? 'Moderate HNDL Concern' : 'Low HNDL Concern';

  if (risk === 'low') {
    return `${category} has a short confidentiality lifetime (${lifetime}). Even if adversaries are collecting encrypted data today, the data is unlikely to retain significant value by the time cryptographically relevant quantum capabilities may become available.`;
  }

  return `${prefix}: ${category} requires confidentiality for ${lifetime}. Data currently protected by ${protection} may be at risk under a "harvest now, decrypt later" scenario, where adversaries collect encrypted data today and retain it for potential future decryption. This is not a current threat, but represents a forward-looking migration priority for long-lived sensitive data.`;
}
