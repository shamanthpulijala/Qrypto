import type { Finding, AlgorithmCategory, QuantumStatus, ClassicalStatus, Severity, Language, RiskBreakdown } from '../../types';

// Define known cryptographic dependencies
const CRYPTO_DEPENDENCIES: Record<string, { name: string, isPqcReady: boolean, recommendation: string, category: AlgorithmCategory, severity: Severity, quantumStatus: QuantumStatus, classicalStatus: ClassicalStatus }> = {
  // Python
  'cryptography': { name: 'cryptography', isPqcReady: false, recommendation: 'Monitor for PQC support; consider aws-lc-python for PQC TLS.', category: 'symmetric', severity: 'medium', quantumStatus: 'vulnerable', classicalStatus: 'adequate' },
  'pycryptodome': { name: 'pycryptodome', isPqcReady: false, recommendation: 'Legacy algorithms present; transition to cryptography module.', category: 'symmetric', severity: 'high', quantumStatus: 'vulnerable', classicalStatus: 'weak' },
  // Node
  'crypto-js': { name: 'crypto-js', isPqcReady: false, recommendation: 'No PQC algorithms supported. Use native crypto module where possible.', category: 'symmetric', severity: 'high', quantumStatus: 'vulnerable', classicalStatus: 'weak' },
  'bcrypt': { name: 'bcrypt', isPqcReady: true, recommendation: 'Bcrypt is generally quantum-resistant for password hashing.', category: 'hash', severity: 'low', quantumStatus: 'adequate', classicalStatus: 'strong' },
  'jsonwebtoken': { name: 'jsonwebtoken', isPqcReady: false, recommendation: 'Ensure RSA keys are 3072+ bits, or migrate to ECDSA/EdDSA (though ECDSA is quantum vulnerable). PQC signatures needed.', category: 'signature', severity: 'medium', quantumStatus: 'vulnerable', classicalStatus: 'adequate' },
  // Java
  'bouncycastle': { name: 'bouncycastle', isPqcReady: true, recommendation: 'Bouncy Castle supports PQC (Kyber, Dilithium). Upgrade to latest BC version.', category: 'public-key', severity: 'low', quantumStatus: 'quantum-resistant', classicalStatus: 'strong' },
};

export function detectDependencies(path: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lowerPath = path.toLowerCase();

  try {
    if (lowerPath.endsWith('package.json')) {
      const pkg = JSON.parse(content);
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      
      for (const [depName, version] of Object.entries(deps)) {
        if (CRYPTO_DEPENDENCIES[depName]) {
          const info = CRYPTO_DEPENDENCIES[depName];
          findings.push({
            id: `dep-${Math.random().toString(36).substr(2, 9)}`,
            file: path,
            repository: 'unknown',
            project: 'unknown',
            line: 1, // Rough approximation
            algorithm: depName,
            category: info.category,
            usage: `Included via ${depName}@${version}`,
            detectedPattern: `"${depName}": "${version}"`,
            confidence: 0.99,
            quantumStatus: info.quantumStatus,
            classicalStatus: info.classicalStatus,
            algorithmSeverity: info.severity,
            severity: info.severity,
            severityRationale: `Dependency ${depName} detected in manifest.`,
            riskScore: info.severity === 'high' ? 85 : info.severity === 'medium' ? 65 : 30,
            riskBreakdown: { algorithmRisk: 0, businessCriticality: 0, internetExposure: 0, dataLifetime: 0, dataSensitivity: 0, migrationDifficulty: 0, totalScore: 0 },
            service: 'App',
            language: 'json',
            internetFacing: false,
            dataSensitivity: 'unknown' as any,
            dataLifetimeYears: 0,
            isCryptoAgile: info.isPqcReady,
            isHardcoded: false,
            migrationPriority: info.severity === 'high' ? 1 : 2,
            remediationStatus: 'open',
            recommendedAlgorithm: info.recommendation,
            tags: ['dependency', 'supply-chain'],
            evidence: {
              detectionLayers: ['dependency'],
              matchedText: `"${depName}": "${version}"`,
              confidenceDerivation: 'Exact match in package.json dependencies.'
            },
            detectedAt: new Date().toISOString()
          });
        }
      }
    } else if (lowerPath.endsWith('requirements.txt')) {
      const lines = content.split('\n');
      lines.forEach((line, index) => {
        const pkgName = line.split(/[=<>!~]/)[0].trim().toLowerCase();
        if (CRYPTO_DEPENDENCIES[pkgName]) {
          const info = CRYPTO_DEPENDENCIES[pkgName];
          findings.push({
            id: `dep-${Math.random().toString(36).substr(2, 9)}`,
            file: path,
            repository: 'unknown',
            project: 'unknown',
            line: index + 1,
            algorithm: pkgName,
            category: info.category,
            usage: `Included via ${line}`,
            detectedPattern: line,
            confidence: 0.99,
            quantumStatus: info.quantumStatus,
            classicalStatus: info.classicalStatus,
            algorithmSeverity: info.severity,
            severity: info.severity,
            severityRationale: `Dependency ${pkgName} detected in requirements manifest.`,
            riskScore: info.severity === 'high' ? 85 : info.severity === 'medium' ? 65 : 30,
            riskBreakdown: { algorithmRisk: 0, businessCriticality: 0, internetExposure: 0, dataLifetime: 0, dataSensitivity: 0, migrationDifficulty: 0, totalScore: 0 },
            service: 'App',
            language: 'python',
            internetFacing: false,
            dataSensitivity: 'unknown' as any,
            dataLifetimeYears: 0,
            isCryptoAgile: info.isPqcReady,
            isHardcoded: false,
            migrationPriority: info.severity === 'high' ? 1 : 2,
            remediationStatus: 'open',
            recommendedAlgorithm: info.recommendation,
            tags: ['dependency', 'supply-chain'],
            evidence: {
              detectionLayers: ['dependency'],
              matchedText: line,
              confidenceDerivation: 'Exact match in requirements.txt.'
            },
            detectedAt: new Date().toISOString()
          });
        }
      });
    }
  } catch (error) {
    console.warn(`Failed to parse dependencies for ${path}:`, error);
  }

  return findings;
}
