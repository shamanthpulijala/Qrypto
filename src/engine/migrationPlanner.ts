// ============================================================
// QuantumGuard AI — Migration Planner
// Generates a prioritized 4-phase roadmap from findings
// §17: Usage-aware recommendations (key establishment ≠ signature)
// ============================================================

import type { Finding, MigrationTask, ServiceNode } from '../types';

let taskCounter = 0;
function taskId(): string {
  return `MT-${String(++taskCounter).padStart(3, '0')}`;
}

// ─── §17 Usage-Aware Migration Mapping ───────────────────────

/**
 * §17 — Do not automatically rewrite everything.
 * Recommendation must depend on the usage context.
 */
export function getUsageAwareRecommendation(
  algorithm: string,
  usage: string,
): { replacement: string; strategy: string; notes: string } {
  const alg = algorithm.toUpperCase();
  const usageLower = usage.toLowerCase();

  // RSA used for key establishment → ML-KEM / hybrid
  if (alg.startsWith('RSA') && (usageLower.includes('key') || usageLower.includes('encrypt') || usageLower.includes('wrap'))) {
    return {
      replacement: 'ML-KEM (FIPS 203)',
      strategy: 'Evaluate hybrid X25519+ML-KEM-768 migration. Maintain classical RSA alongside PQC during transition.',
      notes: 'Key establishment and key wrapping use cases should migrate to ML-KEM. Hybrid approach maintains backward compatibility.',
    };
  }

  // RSA / ECDSA used for signatures → ML-DSA / SLH-DSA
  if ((alg.startsWith('RSA') || alg === 'ECDSA' || alg === 'DSA') &&
      (usageLower.includes('sign') || usageLower.includes('auth') || usageLower.includes('cert'))) {
    return {
      replacement: 'ML-DSA (FIPS 204)',
      strategy: 'Evaluate ML-DSA-65 for balanced security/performance. SLH-DSA as secondary option for maximum security diversity.',
      notes: 'Signature schemes need different PQC successors from key establishment. ML-DSA replaces RSA/ECDSA signatures.',
    };
  }

  // RSA general (no clear usage) → context-dependent
  if (alg.startsWith('RSA')) {
    return {
      replacement: 'ML-KEM (key encapsulation) or ML-DSA (signatures)',
      strategy: 'Determine usage context before recommending specific PQC algorithm. Evaluate hybrid approach during migration.',
      notes: 'Usage context must be established before selecting PQC successor. Different operations require different algorithms.',
    };
  }

  // ECDH used for key establishment → ML-KEM / hybrid
  if (alg === 'ECDH' || usageLower.includes('key exchange') || usageLower.includes('key establishment')) {
    return {
      replacement: 'ML-KEM (FIPS 203)',
      strategy: 'Hybrid X25519+ML-KEM-768 provides backward compatibility during transition. Target pure ML-KEM-768 or ML-KEM-1024 for long-term.',
      notes: 'ECDH key exchange should migrate to ML-KEM. Hybrid approach is strongly preferred during the transition period.',
    };
  }

  // SHA-1 → replace with modern hash
  if (alg === 'SHA-1' || alg.includes('SHA1')) {
    return {
      replacement: 'SHA-256 or SHA-3-256',
      strategy: 'Replace with SHA-256 where appropriate. Check for protocol constraints before replacement.',
      notes: 'SHA-1 has known collision vulnerabilities. Quantum risk (Grover) is secondary to existing classical collision attacks.',
    };
  }

  // MD5 → remove from security-sensitive usage
  if (alg === 'MD5') {
    return {
      replacement: 'SHA-256 (integrity) or Argon2/bcrypt (password)',
      strategy: 'Remove MD5 from all security-sensitive usage. SHA-256 for integrity. Argon2id for passwords.',
      notes: 'MD5 is classically broken. Remove rather than migrate — quantum risk is moot given classical attacks.',
    };
  }

  // TLS 1.0 / 1.1 → upgrade
  if (alg.includes('TLS 1.0') || alg.includes('TLS 1.1') || alg.includes('SSL')) {
    return {
      replacement: 'TLS 1.3 (minimum TLS 1.2 with strong cipher suites)',
      strategy: 'Upgrade TLS configuration. Set minimum_version = TLS 1.2, prefer TLS 1.3. Evaluate X25519Kyber768 hybrid cipher suite.',
      notes: 'Weak TLS is a classical security problem, not quantum-specific. Fix immediately regardless of PQC timeline.',
    };
  }

  // Hardcoded secret → secrets manager
  if (alg.toLowerCase().includes('secret') || alg.toLowerCase().includes('key') || alg.toLowerCase().includes('password') || alg.toLowerCase().includes('credential')) {
    return {
      replacement: 'Managed secret storage',
      strategy: 'Rotate immediately. Move to HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.',
      notes: 'Hardcoded secrets are an immediate operational risk unrelated to quantum computing. Rotation is mandatory.',
    };
  }

  // 3DES, DES → AES-256
  if (alg === '3DES' || alg === 'DES') {
    return {
      replacement: 'AES-256-GCM',
      strategy: 'Replace with AES-256-GCM. Test for protocol-level dependencies before migration.',
      notes: 'DES/3DES is classically weak. Quantum risk is moot given existing classical attacks.',
    };
  }

  return {
    replacement: 'Context-dependent — evaluate usage before selecting successor',
    strategy: 'Assess compatibility requirements. Plan migration with testing phase.',
    notes: 'Usage context must be established to determine the appropriate PQC or classical successor.',
  };
}

// ─── Due Date Helpers ─────────────────────────────────────────

function daysFromNow(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().split('T')[0];
}

// ─── Main Generator ───────────────────────────────────────────

export function generateMigrationRoadmap(findings: Finding[], services: ServiceNode[]): MigrationTask[] {
  taskCounter = 0;
  const tasks: MigrationTask[] = [];

  // ── PHASE 1: Immediate Security Cleanup ──────────────────
  // Hardcoded secrets, broken algorithms, obsolete TLS

  const secrets = findings.filter(f => f.category === 'secret');
  if (secrets.length > 0) {
    tasks.push({
      id: taskId(),
      findingId: secrets[0].id,
      phase: 1,
      title: 'Remove Hardcoded Secrets and Credentials',
      description: `${secrets.length} hardcoded secret${secrets.length > 1 ? 's' : ''} detected in source code. Migrate to a secrets management solution immediately.`,
      priority: 'critical',
      effort: 'weeks',
      effortValue: 2,
      estimatedEffort: '2 weeks',
      affectedServices: [...new Set(secrets.map(f => f.service))],
      affectedFindings: secrets.map(f => f.id),
      reason: 'Hardcoded credentials pose immediate operational security risk regardless of quantum computing threats. These should be rotated and moved to a secrets manager.',
      dependencies: [],
      dueDate: daysFromNow(14),
      status: 'todo',
      tags: ['secrets', 'immediate', 'compliance'],
    });
  }

  const brokenAlgos = findings.filter(
    f => ['MD5', 'DES', 'RC4', 'SHA1withRSA', 'SSLv2', 'SSLv3'].includes(f.algorithm)
  );
  if (brokenAlgos.length > 0) {
    tasks.push({
      id: taskId(),
      findingId: brokenAlgos[0].id,
      phase: 1,
      title: 'Replace Broken/Deprecated Cryptographic Algorithms',
      description: `${brokenAlgos.length} occurrence${brokenAlgos.length > 1 ? 's' : ''} of deprecated algorithms (MD5, DES, RC4, SHA1withRSA) detected. These have known classical attacks and must be replaced.`,
      priority: 'critical',
      effort: 'weeks',
      effortValue: 3,
      estimatedEffort: '3 weeks',
      affectedServices: [...new Set(brokenAlgos.map(f => f.service))],
      affectedFindings: brokenAlgos.map(f => f.id),
      reason: 'MD5, DES, and RC4 have known cryptanalytic attacks that do not require quantum computing. SHA1withRSA certificates are flagged by modern browsers and compliance frameworks.',
      dependencies: [],
      dueDate: daysFromNow(21),
      status: 'todo',
      tags: ['classical-weak', 'immediate', 'compliance'],
    });
  }

  const weakTls = findings.filter(
    f => f.category === 'tls' && ['TLS 1.0', 'TLS 1.1', 'SSLv2', 'SSLv3'].includes(f.algorithm)
  );
  if (weakTls.length > 0) {
    tasks.push({
      id: taskId(),
      findingId: weakTls[0].id,
      phase: 1,
      title: 'Enforce Minimum TLS 1.2 (Prefer TLS 1.3)',
      description: `${weakTls.length} weak TLS configuration${weakTls.length > 1 ? 's' : ''} detected (TLS 1.0/1.1/SSL). Upgrade to TLS 1.3.`,
      priority: 'critical',
      effort: 'weeks',
      effortValue: 2,
      estimatedEffort: '2 weeks',
      affectedServices: [...new Set(weakTls.map(f => f.service))],
      affectedFindings: weakTls.map(f => f.id),
      reason: 'TLS 1.0 and 1.1 are deprecated by RFC 8996. They are vulnerable to known attacks (BEAST, POODLE) that do not require quantum computing.',
      dependencies: [],
      dueDate: daysFromNow(21),
      status: 'todo',
      tags: ['tls', 'immediate', 'compliance', 'pci-dss'],
    });
  }

  // ── PHASE 2: High-Risk Quantum Migration ────────────────
  // Critical/internet-facing quantum-vulnerable assets

  const criticalQuantumVuln = findings.filter(
    f => f.quantumStatus === 'vulnerable' &&
    (f.severity === 'critical' || f.severity === 'high') &&
    f.internetFacing
  );

  const criticalServices = [...new Set(criticalQuantumVuln.map(f => f.service))];

  if (criticalQuantumVuln.length > 0) {
    tasks.push({
      id: taskId(),
      phase: 2,
      title: 'Inventory and Plan PQC Migration for Critical Internet-Facing Services',
      description: `${criticalQuantumVuln.length} quantum-vulnerable cryptographic assets in internet-facing critical services (${criticalServices.join(', ')}). Begin migration planning and proof-of-concept evaluation.`,
      priority: 'high',
      effort: 'months',
      effortValue: 3,
      estimatedEffort: '3 months',
      affectedServices: criticalServices,
      affectedFindings: criticalQuantumVuln.map(f => f.id),
      reason: 'Internet-facing services using quantum-vulnerable public-key algorithms (RSA, ECC, ECDH) are the highest priority for migration planning. Long-lived data processed by these services may be at risk under harvest-now-decrypt-later scenarios.',
      dependencies: ['MT-001', 'MT-002'],
      dueDate: daysFromNow(90),
      status: 'todo',
      tags: ['quantum', 'planning', 'high-priority'],
    });
  }

  // §17: Payment Service — RSA key establishment → ML-KEM (usage-aware)
  const paymentKeyFindings = findings.filter(
    f => f.service === 'Payment Service' && f.quantumStatus === 'vulnerable' &&
    (f.usage.toLowerCase().includes('key') || f.usage.toLowerCase().includes('encrypt'))
  );
  const paymentSigFindings = findings.filter(
    f => f.service === 'Payment Service' && f.quantumStatus === 'vulnerable' &&
    f.usage.toLowerCase().includes('sign')
  );

  if (paymentKeyFindings.length > 0) {
    const rec = getUsageAwareRecommendation('RSA', 'key establishment');
    tasks.push({
      id: taskId(),
      findingId: paymentKeyFindings[0].id,
      phase: 2,
      title: 'Payment Service — Evaluate Hybrid Key Establishment (ML-KEM)',
      description: `${rec.strategy} Protects long-lived financial data against harvest-now-decrypt-later attacks.`,
      priority: 'high',
      effort: 'months',
      effortValue: 4,
      estimatedEffort: '4 months',
      affectedServices: ['Payment Service'],
      affectedFindings: paymentKeyFindings.map(f => f.id),
      reason: `Payment data may need to remain confidential for 10–25 years. ${rec.notes}`,
      dependencies: [],
      dueDate: daysFromNow(120),
      status: 'todo',
      tags: ['quantum', 'payment', 'hybrid', 'ml-kem', 'pci-dss'],
    });
  }

  if (paymentSigFindings.length > 0) {
    const rec = getUsageAwareRecommendation('RSA', 'digital signature');
    tasks.push({
      id: taskId(),
      findingId: paymentSigFindings[0].id,
      phase: 2,
      title: 'Payment Service — Plan Post-Quantum Signature Migration (ML-DSA)',
      description: `${rec.strategy} Evaluate ML-DSA-65 for transaction and audit log signing.`,
      priority: 'high',
      effort: 'months',
      effortValue: 3,
      estimatedEffort: '3 months',
      affectedServices: ['Payment Service'],
      affectedFindings: paymentSigFindings.map(f => f.id),
      reason: `${rec.notes} RSA/ECDSA signatures require a different PQC successor (ML-DSA) from key establishment (ML-KEM).`,
      dependencies: [],
      dueDate: daysFromNow(120),
      status: 'todo',
      tags: ['quantum', 'payment', 'signatures', 'ml-dsa'],
    });
  }

  // §17: Auth Service — signatures → ML-DSA (usage-aware)
  const authFindings = findings.filter(f => f.service === 'Authentication Service' && f.quantumStatus === 'vulnerable');
  if (authFindings.length > 0) {
    const rec = getUsageAwareRecommendation('RSA', 'digital signature signing auth');
    tasks.push({
      id: taskId(),
      findingId: authFindings[0].id,
      phase: 2,
      title: 'Authentication Service — Plan Post-Quantum Signature Migration (ML-DSA)',
      description: `Evaluate ML-DSA (CRYSTALS-Dilithium) as a replacement for RSA/ECDSA-based authentication signatures. ${rec.strategy}`,
      priority: 'high',
      effort: 'months',
      effortValue: 3,
      estimatedEffort: '3 months',
      affectedServices: ['Authentication Service'],
      affectedFindings: authFindings.map(f => f.id),
      reason: `Authentication relies on public-key signatures (RSA, ECDSA) that are quantum-vulnerable. ${rec.notes}`,
      dependencies: [],
      dueDate: daysFromNow(120),
      status: 'todo',
      tags: ['quantum', 'authentication', 'signatures', 'ml-dsa'],
    });
  }

  // §17: ECDH / key exchange findings → ML-KEM (usage-aware)
  const ecdhFindings = findings.filter(
    f => (f.algorithm === 'ECDH' || f.category === 'key-exchange') && f.quantumStatus === 'vulnerable'
  );
  if (ecdhFindings.length > 0) {
    const rec = getUsageAwareRecommendation('ECDH', 'key exchange');
    tasks.push({
      id: taskId(),
      findingId: ecdhFindings[0].id,
      phase: 2,
      title: 'Replace ECDH Key Exchange with ML-KEM (Hybrid Approach)',
      description: `${ecdhFindings.length} ECDH key exchange instance${ecdhFindings.length > 1 ? 's' : ''} identified. ${rec.strategy}`,
      priority: 'high',
      effort: 'months',
      effortValue: 3,
      estimatedEffort: '3 months',
      affectedServices: [...new Set(ecdhFindings.map(f => f.service))],
      affectedFindings: ecdhFindings.map(f => f.id),
      reason: `${rec.notes} Note: ECDH for key exchange and ECDSA for signatures require different PQC successors (ML-KEM vs ML-DSA).`,
      dependencies: [],
      dueDate: daysFromNow(90),
      status: 'todo',
      tags: ['quantum', 'ecdh', 'ml-kem', 'key-exchange', 'hybrid'],
    });
  }

  // ── PHASE 3: Hybrid PQC Adoption ────────────────────────

  tasks.push({
    id: taskId(),
    phase: 3,
    title: 'Implement ML-KEM Hybrid Key Encapsulation (Pilot)',
    description: 'Implement hybrid key establishment combining X25519 + ML-KEM-768 as a pilot in the Payment API to maintain backward compatibility during transition.',
    priority: 'medium',
    effort: 'months',
    effortValue: 6,
    estimatedEffort: '6 months',
    affectedServices: ['Payment Service', 'API Gateway'],
    affectedFindings: [],
    reason: 'NIST has standardized ML-KEM (FIPS 203) for post-quantum key encapsulation. A hybrid approach allows backward compatibility while providing quantum migration protection.',
    dependencies: [],
    dueDate: daysFromNow(180),
    status: 'todo',
    tags: ['pqc', 'ml-kem', 'hybrid', 'pilot'],
  });

  tasks.push({
    id: taskId(),
    phase: 3,
    title: 'Adopt ML-DSA for Digital Signatures (Pilot)',
    description: 'Evaluate and pilot ML-DSA (FIPS 204) for code signing, API authentication, and certificate signing as a post-quantum signature replacement. Note: ML-DSA replaces RSA/ECDSA signatures, not key establishment — different use cases require different PQC algorithms.',
    priority: 'medium',
    effort: 'months',
    effortValue: 4,
    estimatedEffort: '4 months',
    affectedServices: ['Authentication Service', 'PKI/TLS Layer'],
    affectedFindings: [],
    reason: 'NIST has standardized ML-DSA (FIPS 204) as a post-quantum digital signature algorithm. Piloting in non-production environments builds capability for full adoption.',
    dependencies: [],
    dueDate: daysFromNow(180),
    status: 'todo',
    tags: ['pqc', 'ml-dsa', 'signatures', 'pilot'],
  });

  tasks.push({
    id: taskId(),
    phase: 3,
    title: 'Update TLS Configuration for PQC Cipher Suite Support',
    description: 'Configure TLS to support post-quantum hybrid cipher suites (X25519Kyber768) where supported by the runtime/library.',
    priority: 'medium',
    effort: 'months',
    effortValue: 2,
    estimatedEffort: '2 months',
    affectedServices: ['API Gateway', 'PKI/TLS Layer'],
    affectedFindings: [],
    reason: 'Major TLS libraries and browsers are adding support for hybrid PQC cipher suites. Early adoption enables protection of data in transit.',
    dependencies: [],
    dueDate: daysFromNow(180),
    status: 'todo',
    tags: ['tls', 'pqc', 'cipher-suite'],
  });

  // ── PHASE 4: Crypto Agility ──────────────────────────────

  tasks.push({
    id: taskId(),
    phase: 4,
    title: 'Centralize Cryptographic Algorithm Selection',
    description: 'Refactor codebase to centralize all cryptographic algorithm selection through a single abstraction layer, enabling future algorithm changes without modifying business logic.',
    priority: 'medium',
    effort: 'months',
    effortValue: 3,
    estimatedEffort: '3 months',
    affectedServices: services.map(s => s.name),
    affectedFindings: [],
    reason: 'Crypto agility — the ability to swap algorithms without widespread code changes — is essential for long-term resilience. The current codebase has algorithm names scattered across many files.',
    dependencies: [],
    dueDate: daysFromNow(365),
    status: 'todo',
    tags: ['crypto-agility', 'architecture', 'refactor'],
  });

  tasks.push({
    id: taskId(),
    phase: 4,
    title: 'Implement Automated Cryptographic Inventory Monitoring',
    description: 'Integrate cryptographic discovery into CI/CD pipeline to detect new vulnerable algorithm usages before they reach production.',
    priority: 'low',
    effort: 'weeks',
    effortValue: 3,
    estimatedEffort: '3 weeks',
    affectedServices: [],
    affectedFindings: [],
    reason: 'Continuous cryptographic inventory monitoring prevents regression and provides ongoing visibility into the organization\'s quantum readiness posture.',
    dependencies: [],
    dueDate: daysFromNow(365),
    status: 'todo',
    tags: ['crypto-agility', 'cicd', 'monitoring'],
  });

  tasks.push({
    id: taskId(),
    phase: 4,
    title: 'Full PQC Migration and Classical Algorithm Deprecation',
    description: 'Complete migration away from RSA/ECC for all services. Deprecate hybrid approach and fully adopt ML-KEM/ML-DSA across the stack.',
    priority: 'low',
    effort: 'months',
    effortValue: 12,
    estimatedEffort: '12 months',
    affectedServices: services.map(s => s.name),
    affectedFindings: [],
    reason: 'Final state of the migration plan: all services operating exclusively with post-quantum algorithms, with no dependency on quantum-vulnerable public-key cryptography.',
    dependencies: [],
    dueDate: daysFromNow(730),
    status: 'todo',
    tags: ['pqc', 'full-migration', 'long-term'],
  });

  return tasks;
}
