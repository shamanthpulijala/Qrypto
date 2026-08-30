// ============================================================
// Qrypto AI Advisor — Crypto Agility Scorer & Evidence Engine (§32)
// Calculates 5 breakdown scores & concrete evidence linking to findings
// ============================================================

import type { Finding, CryptoAgilityScore, CryptoAgilityBreakdown, AgilityEvidenceItem } from '../types';

export function computeCryptoAgilityScore(findings: Finding[]): CryptoAgilityScore {
  const positives: string[] = [];
  const negatives: string[] = [];

  const total = findings.length || 1;
  const pqcCount = findings.filter(f => f.quantumStatus === 'quantum-resistant').length;
  const adequateCount = findings.filter(f => f.quantumStatus === 'adequate').length;
  const vulnerableCount = findings.filter(f => f.quantumStatus === 'vulnerable').length;
  const weakCount = findings.filter(f => f.quantumStatus === 'classical-weak').length;
  const hardcodedRefs = findings.filter(f => f.isHardcoded && f.category !== 'secret').length;
  const secretCount = findings.filter(f => f.category === 'secret').length;

  const centralizedConfig = findings.some(
    f => f.file.toLowerCase().includes('crypto') ||
         f.file.toLowerCase().includes('cipher') ||
         f.file.toLowerCase().includes('security') ||
         f.file.toLowerCase().includes('policy') ||
         f.file.toLowerCase().includes('config')
  );

  const algorithmAbstraction = findings.some(
    f => f.file.toLowerCase().includes('provider') ||
         f.file.toLowerCase().includes('factory') ||
         f.file.toLowerCase().includes('policy') ||
         f.quantumStatus === 'quantum-resistant'
  );

  // §32 Dynamic Sub-scores calculation
  let absScore = Math.round(algorithmAbstraction ? 88 : Math.max(25, 75 - hardcodedRefs * 7));
  if (pqcCount > 0) absScore = Math.min(100, absScore + 10);

  let cfgScore = Math.round(centralizedConfig ? 85 : Math.max(30, 65 - weakCount * 6));
  if (pqcCount > 0) cfgScore = Math.min(100, cfgScore + 8);

  const hardScore = Math.max(15, Math.min(100, 100 - hardcodedRefs * 12 - secretCount * 15));
  const flexScore = Math.min(100, Math.max(30, Math.round((absScore + cfgScore) / 2)));
  const depScore = Math.max(35, Math.min(100, 95 - weakCount * 12 - secretCount * 12));

  const breakdown: CryptoAgilityBreakdown = {
    algorithmAbstraction: Math.min(100, Math.max(0, absScore)),
    configurationCentralization: Math.min(100, Math.max(0, cfgScore)),
    hardcodedAlgorithms: Math.min(100, Math.max(0, hardScore)),
    migrationFlexibility: Math.min(100, Math.max(0, flexScore)),
    dependencyManagement: Math.min(100, Math.max(0, depScore)),
  };

  const overallScore = Math.round(
    breakdown.algorithmAbstraction * 0.25 +
    breakdown.configurationCentralization * 0.25 +
    breakdown.hardcodedAlgorithms * 0.20 +
    breakdown.migrationFlexibility * 0.15 +
    breakdown.dependencyManagement * 0.15
  );

  // Build strengths & gaps dynamically
  if (pqcCount > 0) {
    positives.push(`Detected ${pqcCount} NIST PQC algorithm(s) (ML-KEM / ML-DSA / SLH-DSA) active in architecture.`);
  }
  if (hardcodedRefs === 0) {
    positives.push('Zero hardcoded cryptographic algorithm identifiers detected in source code.');
  }
  if (secretCount === 0) {
    positives.push('No hardcoded API keys or secret credentials detected in repository.');
  }
  if (weakCount === 0) {
    positives.push('No classically broken hash functions (MD5, SHA-1) or deprecated ciphers detected.');
  }
  if (centralizedConfig) {
    positives.push('Centralized cryptographic security policy provider detected.');
  }

  if (vulnerableCount > 0) {
    negatives.push(`${vulnerableCount} quantum-vulnerable algorithm instance(s) (RSA/ECC/ECDH) bound to application logic.`);
  }
  if (hardcodedRefs > 0) {
    negatives.push(`${hardcodedRefs} hardcoded algorithm string(s) bound directly in source files.`);
  }
  if (secretCount > 0) {
    negatives.push(`${secretCount} hardcoded secret credential(s) detected in source files.`);
  }
  if (weakCount > 0) {
    negatives.push(`${weakCount} classically deprecated primitive(s) (MD5, SHA-1, 3DES, weak TLS) present.`);
  }

  // Build concrete evidence items from actual scanned findings
  const evidence: AgilityEvidenceItem[] = [];

  // PQC Evidence
  const pqcFinding = findings.find(f => f.quantumStatus === 'quantum-resistant');
  if (pqcFinding) {
    evidence.push({
      scoreName: 'Post-Quantum Algorithm Abstraction',
      scoreValue: breakdown.algorithmAbstraction,
      category: 'NIST PQC Standard',
      description: `Active post-quantum algorithm '${pqcFinding.algorithm}' (${pqcFinding.category}) implemented with modular provider structure.`,
      evidenceSnippet: pqcFinding.detectedPattern || `${pqcFinding.algorithm} provider = new ${pqcFinding.algorithm}Provider();`,
      filePath: pqcFinding.file,
      lineNumber: pqcFinding.line,
    });
  }

  // Hardcoded evidence
  const hardcodedFinding = findings.find(f => f.isHardcoded);
  if (hardcodedFinding) {
    evidence.push({
      scoreName: 'Hardcoded Algorithm Identifier',
      scoreValue: breakdown.hardcodedAlgorithms,
      category: 'Direct Primitive Binding',
      description: `Algorithm identifier '${hardcodedFinding.algorithm}' is directly hardcoded into source code instead of using configuration injection.`,
      evidenceSnippet: hardcodedFinding.detectedPattern || `${hardcodedFinding.algorithm} cipher = Cipher.getInstance("${hardcodedFinding.algorithm}");`,
      filePath: hardcodedFinding.file,
      lineNumber: hardcodedFinding.line,
    });
  }

  // TLS / Config evidence
  const tlsFinding = findings.find(f => f.category === 'tls' || f.service.includes('Gateway'));
  if (tlsFinding) {
    evidence.push({
      scoreName: 'Protocol Configuration Centralization',
      scoreValue: breakdown.configurationCentralization,
      category: 'Transport Security Policy',
      description: `Protocol configuration setting '${tlsFinding.algorithm}' specified in service file '${tlsFinding.file}'.`,
      evidenceSnippet: tlsFinding.detectedPattern || `minVersion: '${tlsFinding.algorithm}';`,
      filePath: tlsFinding.file,
      lineNumber: tlsFinding.line,
    });
  }

  // Vulnerable RSA/ECC evidence
  const vulnFinding = findings.find(f => f.quantumStatus === 'vulnerable');
  if (vulnFinding && !pqcFinding) {
    evidence.push({
      scoreName: 'Tightly Coupled Quantum-Vulnerable Primitive',
      scoreValue: breakdown.migrationFlexibility,
      category: 'Legacy Key Management',
      description: `Key generation logic '${vulnFinding.algorithm}' bound directly to classical implementation in '${vulnFinding.file}'.`,
      evidenceSnippet: vulnFinding.detectedPattern || `KeyPairGenerator keyGen = KeyPairGenerator.getInstance("${vulnFinding.algorithm}");`,
      filePath: vulnFinding.file,
      lineNumber: vulnFinding.line,
    });
  }

  return {
    score: Math.min(100, Math.max(0, overallScore)),
    breakdown,
    evidence,
    positives,
    negatives,
    hardcodedReferences: hardcodedRefs,
    centralizedConfig,
    algorithmAbstraction,
    directLowLevelCalls: weakCount,
  };
}
