// ============================================================
// QuantumGuard AI — Crypto Agility Scorer & Evidence Engine (§32)
// Calculates 5 breakdown scores & concrete evidence linking to findings
// ============================================================

import type { Finding, CryptoAgilityScore, CryptoAgilityBreakdown, AgilityEvidenceItem } from '../types';

export function computeCryptoAgilityScore(findings: Finding[]): CryptoAgilityScore {
  const positives: string[] = [];
  const negatives: string[] = [];

  const hardcodedRefs = findings.filter(
    f => f.isHardcoded && f.category !== 'secret'
  ).length;

  const directLowLevelCalls = findings.filter(
    f => ['DES', 'MD5', 'SHA-1', 'RC4'].includes(f.algorithm) && f.isHardcoded
  ).length;

  const centralizedConfig = findings.some(
    f => f.file.toLowerCase().includes('crypto') ||
         f.file.toLowerCase().includes('cipher') ||
         f.file.toLowerCase().includes('security-config') ||
         f.file.toLowerCase().includes('cryptoconfig')
  );

  const algorithmAbstraction = findings.filter(
    f => f.file.toLowerCase().includes('factory') ||
         f.file.toLowerCase().includes('provider') ||
         f.file.toLowerCase().includes('config')
  ).length > 2;

  // §32 Sub-scores calculation
  const absScore = algorithmAbstraction ? 82 : Math.max(30, 72 - hardcodedRefs * 4);
  const cfgScore = centralizedConfig ? 81 : 45;
  const hardScore = Math.max(15, 75 - hardcodedRefs * 6 - directLowLevelCalls * 8);
  const flexScore = Math.max(35, Math.round((absScore + cfgScore) / 2 - 5));
  const depScore = Math.max(40, 74 - findings.filter(f => f.category === 'tls').length * 5);

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

  // Build concrete evidence items
  const evidence: AgilityEvidenceItem[] = [];

  // Finding evidence for Hardcoded Algorithms
  const hardcodedFinding = findings.find(f => f.isHardcoded);
  if (hardcodedFinding) {
    evidence.push({
      scoreName: 'Hardcoded Algorithms',
      scoreValue: breakdown.hardcodedAlgorithms,
      category: 'Direct Primitive Binding',
      description: `Algorithm identifier '${hardcodedFinding.algorithm}' is directly hardcoded into source code instead of using configuration injection.`,
      evidenceSnippet: hardcodedFinding.codeSnippet || `${hardcodedFinding.algorithm} cipher = Cipher.getInstance("${hardcodedFinding.algorithm}");`,
      filePath: hardcodedFinding.file,
      lineNumber: hardcodedFinding.line,
    });
  }

  // Finding evidence for Configuration Centralization
  const tlsFinding = findings.find(f => f.category === 'tls' || f.service.includes('Gateway'));
  if (tlsFinding) {
    evidence.push({
      scoreName: 'Configuration Centralization',
      scoreValue: breakdown.configurationCentralization,
      category: 'Decentralized TLS Config',
      description: `Protocol configuration setting '${tlsFinding.algorithm}' specified in service file instead of central security policy provider.`,
      evidenceSnippet: tlsFinding.codeSnippet || `ssl_protocols ${tlsFinding.algorithm};`,
      filePath: tlsFinding.file,
      lineNumber: tlsFinding.line,
    });
  }

  // Finding evidence for Algorithm Abstraction
  const rsaFinding = findings.find(f => f.algorithm.startsWith('RSA'));
  if (rsaFinding) {
    evidence.push({
      scoreName: 'Algorithm Abstraction',
      scoreValue: breakdown.algorithmAbstraction,
      category: 'Tightly Coupled Primitive',
      description: `Key generation and signing logic bound directly to RSA implementation, preventing drop-in substitution of ML-DSA / ML-KEM.`,
      evidenceSnippet: rsaFinding.codeSnippet || `KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");`,
      filePath: rsaFinding.file,
      lineNumber: rsaFinding.line,
    });
  }

  // Positives & Negatives
  if (centralizedConfig) positives.push('Centralized cryptographic configuration module detected.');
  else negatives.push('No centralized cryptographic configuration found.');

  if (algorithmAbstraction) positives.push('Provider pattern / factory abstraction present for cryptography.');
  else negatives.push('Algorithms referenced directly without provider abstraction layers.');

  if (hardcodedRefs > 0) negatives.push(`${hardcodedRefs} hardcoded algorithm reference(s) detected.`);
  if (directLowLevelCalls > 0) negatives.push(`${directLowLevelCalls} direct call(s) to deprecated low-level crypto APIs.`);

  return {
    score: Math.min(100, Math.max(0, overallScore)),
    breakdown,
    evidence,
    positives,
    negatives,
    hardcodedReferences: hardcodedRefs,
    centralizedConfig,
    algorithmAbstraction,
    directLowLevelCalls,
  };
}
