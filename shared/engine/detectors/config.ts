import type { Finding } from '../../types';

export function detectConfigWeaknesses(path: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lowerPath = path.toLowerCase();
  
  // Basic Nginx / SSH config scanning
  if (lowerPath.endsWith('nginx.conf') || lowerPath.endsWith('default.conf')) {
    const lines = content.split('\n');
    lines.forEach((line, index) => {
      const lowerLine = line.trim().toLowerCase();
      
      if (lowerLine.startsWith('ssl_protocols')) {
        if (lowerLine.includes('tls1.0') || lowerLine.includes('tls1.1')) {
          findings.push({
            id: `cfg-${Math.random().toString(36).substr(2, 9)}`,
            file: path,
            repository: 'unknown',
            project: 'unknown',
            line: index + 1,
            algorithm: 'TLS <1.2',
            category: 'tls',
            usage: 'Web Server Configuration',
            detectedPattern: line.trim(),
            confidence: 0.95,
            quantumStatus: 'vulnerable',
            classicalStatus: 'weak',
            algorithmSeverity: 'high',
            severity: 'high',
            severityRationale: 'Deprecated TLS version detected in server configuration.',
            riskScore: 85,
            riskBreakdown: { algorithmRisk: 0, businessCriticality: 0, internetExposure: 0, dataLifetime: 0, dataSensitivity: 0, migrationDifficulty: 0, totalScore: 0 },
            service: 'Web Server',
            language: 'unknown',
            internetFacing: true,
            dataSensitivity: 'unknown' as any,
            dataLifetimeYears: 0,
            isCryptoAgile: false,
            isHardcoded: true,
            migrationPriority: 1,
            remediationStatus: 'open',
            recommendedAlgorithm: 'TLS 1.3 or TLS 1.2',
            tags: ['config', 'tls', 'network'],
            evidence: {
              detectionLayers: ['config-regex'],
              matchedText: line.trim(),
              confidenceDerivation: 'Exact config directive match for deprecated TLS versions.'
            },
            detectedAt: new Date().toISOString()
          });
        }
      }

      if (lowerLine.startsWith('ssl_ciphers')) {
        if (lowerLine.includes('rc4') || lowerLine.includes('3des') || lowerLine.includes('des')) {
          findings.push({
            id: `cfg-${Math.random().toString(36).substr(2, 9)}`,
            file: path,
            repository: 'unknown',
            project: 'unknown',
            line: index + 1,
            algorithm: 'Weak Ciphers (RC4/3DES/DES)',
            category: 'symmetric',
            usage: 'Web Server Configuration',
            detectedPattern: line.trim(),
            confidence: 0.95,
            quantumStatus: 'vulnerable',
            classicalStatus: 'broken',
            algorithmSeverity: 'critical',
            severity: 'critical',
            severityRationale: 'Broken cipher suite (RC4/3DES/DES) detected in server configuration.',
            riskScore: 95,
            riskBreakdown: { algorithmRisk: 0, businessCriticality: 0, internetExposure: 0, dataLifetime: 0, dataSensitivity: 0, migrationDifficulty: 0, totalScore: 0 },
            service: 'Web Server',
            language: 'unknown',
            internetFacing: true,
            dataSensitivity: 'unknown' as any,
            dataLifetimeYears: 0,
            isCryptoAgile: false,
            isHardcoded: true,
            migrationPriority: 1,
            remediationStatus: 'open',
            recommendedAlgorithm: 'AESGCM or CHACHA20',
            tags: ['config', 'tls', 'ciphers'],
            evidence: {
              detectionLayers: ['config-regex'],
              matchedText: line.trim(),
              confidenceDerivation: 'Exact config directive match for broken cipher suites.'
            },
            detectedAt: new Date().toISOString()
          });
        }
      }
    });
  }

  return findings;
}
