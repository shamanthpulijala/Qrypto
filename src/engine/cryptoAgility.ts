// ============================================================
// QuantumGuard AI — Crypto Agility Scorer
// ============================================================

import type { Finding, CryptoAgilityScore } from '../types';

export function computeCryptoAgilityScore(findings: Finding[]): CryptoAgilityScore {
  const positives: string[] = [];
  const negatives: string[] = [];

  const hardcodedRefs = findings.filter(
    f => f.isHardcoded && f.category !== 'secret'
  ).length;

  const directLowLevelCalls = findings.filter(
    f => ['DES', 'MD5', 'SHA-1', 'RC4'].includes(f.algorithm) && f.isHardcoded
  ).length;

  // Check for centralized crypto config patterns
  const centralizedConfig = findings.some(
    f => f.file.toLowerCase().includes('crypto') ||
         f.file.toLowerCase().includes('cipher') ||
         f.file.toLowerCase().includes('security-config') ||
         f.file.toLowerCase().includes('cryptoconfig')
  );

  // Algorithm abstraction: finding algo names only in config/factory files
  const algorithmAbstraction = findings.filter(
    f => f.file.toLowerCase().includes('factory') ||
         f.file.toLowerCase().includes('provider') ||
         f.file.toLowerCase().includes('config')
  ).length > 2;

  // Score computation
  let score = 50; // baseline

  if (centralizedConfig) {
    score += 15;
    positives.push('Centralized cryptographic configuration detected');
  } else {
    negatives.push('No centralized cryptographic configuration found');
  }

  if (algorithmAbstraction) {
    score += 15;
    positives.push('Algorithm abstraction patterns detected (factory/provider pattern)');
  } else {
    negatives.push('Algorithms appear to be referenced directly rather than through abstractions');
  }

  if (hardcodedRefs === 0) {
    score += 10;
    positives.push('No hard-coded algorithm references detected');
  } else {
    const penalty = Math.min(30, hardcodedRefs * 3);
    score -= penalty;
    negatives.push(`${hardcodedRefs} hard-coded algorithm reference${hardcodedRefs > 1 ? 's' : ''} detected`);
  }

  if (directLowLevelCalls > 0) {
    const penalty = Math.min(20, directLowLevelCalls * 5);
    score -= penalty;
    negatives.push(`${directLowLevelCalls} direct call${directLowLevelCalls > 1 ? 's' : ''} to deprecated cryptographic APIs`);
  } else {
    positives.push('No direct calls to deprecated low-level crypto APIs');
  }

  // Check for PQC readiness indicators
  const pqcFindings = findings.filter(f => f.quantumStatus === 'quantum-resistant').length;
  if (pqcFindings > 0) {
    score += 10;
    positives.push(`${pqcFindings} post-quantum algorithm reference${pqcFindings > 1 ? 's' : ''} found — PQC awareness present`);
  }

  // Check for protocol hardcoding
  const tlsHardcoded = findings.filter(
    f => f.category === 'tls' && f.quantumStatus === 'classical-weak'
  ).length;
  if (tlsHardcoded > 0) {
    score -= tlsHardcoded * 5;
    negatives.push(`${tlsHardcoded} hard-coded weak TLS version${tlsHardcoded > 1 ? 's' : ''}`);
  }

  return {
    score: Math.min(100, Math.max(0, Math.round(score))),
    positives,
    negatives,
    hardcodedReferences: hardcodedRefs,
    centralizedConfig,
    algorithmAbstraction,
    directLowLevelCalls,
  };
}
