// ============================================================
// QuantumGuard AI — Migration Planner
// Generates a prioritized 4-phase roadmap from findings
// ============================================================

import type { Finding, MigrationTask, ServiceNode } from '../types';

let taskCounter = 0;
function taskId(): string {
  return `MT-${String(++taskCounter).padStart(3, '0')}`;
}

export function generateMigrationRoadmap(findings: Finding[], services: ServiceNode[]): MigrationTask[] {
  taskCounter = 0;
  const tasks: MigrationTask[] = [];

  // ── PHASE 1: Immediate Security Cleanup ──────────────────
  // Hardcoded secrets, broken algorithms, obsolete TLS

  const secrets = findings.filter(f => f.category === 'secret');
  if (secrets.length > 0) {
    tasks.push({
      id: taskId(),
      phase: 1,
      title: 'Remove Hardcoded Secrets and Credentials',
      description: `${secrets.length} hardcoded secret${secrets.length > 1 ? 's' : ''} detected in source code. Migrate to a secrets management solution immediately.`,
      priority: 'critical',
      effort: 'weeks',
      effortValue: 2,
      affectedServices: [...new Set(secrets.map(f => f.service))],
      affectedFindings: secrets.map(f => f.id),
      reason: 'Hardcoded credentials pose immediate operational security risk regardless of quantum computing threats. These should be rotated and moved to a secrets manager.',
      dependencies: [],
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
      phase: 1,
      title: 'Replace Broken/Deprecated Cryptographic Algorithms',
      description: `${brokenAlgos.length} occurrence${brokenAlgos.length > 1 ? 's' : ''} of deprecated algorithms (MD5, DES, RC4, SHA1withRSA) detected. These have known classical attacks and must be replaced.`,
      priority: 'critical',
      effort: 'weeks',
      effortValue: 3,
      affectedServices: [...new Set(brokenAlgos.map(f => f.service))],
      affectedFindings: brokenAlgos.map(f => f.id),
      reason: 'MD5, DES, and RC4 have known cryptanalytic attacks that do not require quantum computing. SHA1withRSA certificates are flagged by modern browsers and compliance frameworks.',
      dependencies: [],
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
      phase: 1,
      title: 'Enforce Minimum TLS 1.2 (Prefer TLS 1.3)',
      description: `${weakTls.length} weak TLS configuration${weakTls.length > 1 ? 's' : ''} detected (TLS 1.0/1.1/SSL). Upgrade to TLS 1.3.`,
      priority: 'critical',
      effort: 'weeks',
      effortValue: 2,
      affectedServices: [...new Set(weakTls.map(f => f.service))],
      affectedFindings: weakTls.map(f => f.id),
      reason: 'TLS 1.0 and 1.1 are deprecated by RFC 8996. They are vulnerable to known attacks (BEAST, POODLE) that do not require quantum computing.',
      dependencies: [],
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
      affectedServices: criticalServices,
      affectedFindings: criticalQuantumVuln.map(f => f.id),
      reason: 'Internet-facing services using quantum-vulnerable public-key algorithms (RSA, ECC, ECDH) are the highest priority for migration planning. Long-lived data processed by these services may be at risk under harvest-now-decrypt-later scenarios.',
      dependencies: ['MT-001', 'MT-002'],
      status: 'todo',
      tags: ['quantum', 'planning', 'high-priority'],
    });
  }

  const paymentFindings = findings.filter(f => f.service === 'Payment Service' && f.quantumStatus === 'vulnerable');
  if (paymentFindings.length > 0) {
    tasks.push({
      id: taskId(),
      phase: 2,
      title: 'Payment Service — Evaluate Hybrid Key Establishment',
      description: 'Evaluate adoption of a hybrid key establishment approach (classical + ML-KEM) for the Payment Service to protect long-lived financial data.',
      priority: 'high',
      effort: 'months',
      effortValue: 4,
      affectedServices: ['Payment Service'],
      affectedFindings: paymentFindings.map(f => f.id),
      reason: 'Payment data may need to remain confidential for 10–25 years. Financial industry regulators are beginning to publish PQC readiness guidance. Early planning is advisable.',
      dependencies: [],
      status: 'todo',
      tags: ['quantum', 'payment', 'hybrid', 'pci-dss'],
    });
  }

  const authFindings = findings.filter(f => f.service === 'Authentication Service' && f.quantumStatus === 'vulnerable');
  if (authFindings.length > 0) {
    tasks.push({
      id: taskId(),
      phase: 2,
      title: 'Authentication Service — Plan Post-Quantum Signature Migration',
      description: 'Evaluate ML-DSA (CRYSTALS-Dilithium) as a replacement for RSA/ECDSA-based authentication signatures.',
      priority: 'high',
      effort: 'months',
      effortValue: 3,
      affectedServices: ['Authentication Service'],
      affectedFindings: authFindings.map(f => f.id),
      reason: 'Authentication relies on public-key signatures (RSA, ECDSA) that are quantum-vulnerable. Migrating authentication to post-quantum signatures is a prerequisite for broader PQC adoption.',
      dependencies: [],
      status: 'todo',
      tags: ['quantum', 'authentication', 'signatures', 'ml-dsa'],
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
    affectedServices: ['Payment Service', 'API Gateway'],
    affectedFindings: [],
    reason: 'NIST has standardized ML-KEM (FIPS 203) for post-quantum key encapsulation. A hybrid approach allows backward compatibility while providing quantum migration protection.',
    dependencies: [],
    status: 'todo',
    tags: ['pqc', 'ml-kem', 'hybrid', 'pilot'],
  });

  tasks.push({
    id: taskId(),
    phase: 3,
    title: 'Adopt ML-DSA for Digital Signatures (Pilot)',
    description: 'Evaluate and pilot ML-DSA (FIPS 204) for code signing, API authentication, and certificate signing as a post-quantum signature replacement.',
    priority: 'medium',
    effort: 'months',
    effortValue: 4,
    affectedServices: ['Authentication Service', 'PKI/TLS Layer'],
    affectedFindings: [],
    reason: 'NIST has standardized ML-DSA (FIPS 204) as a post-quantum digital signature algorithm. Piloting in non-production environments builds capability for full adoption.',
    dependencies: [],
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
    affectedServices: ['API Gateway', 'PKI/TLS Layer'],
    affectedFindings: [],
    reason: 'Major TLS libraries and browsers are adding support for hybrid PQC cipher suites. Early adoption enables protection of data in transit.',
    dependencies: [],
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
    affectedServices: services.map(s => s.name),
    affectedFindings: [],
    reason: 'Crypto agility — the ability to swap algorithms without widespread code changes — is essential for long-term resilience. The current codebase has algorithm names scattered across many files.',
    dependencies: [],
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
    affectedServices: [],
    affectedFindings: [],
    reason: 'Continuous cryptographic inventory monitoring prevents regression and provides ongoing visibility into the organization\'s quantum readiness posture.',
    dependencies: [],
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
    affectedServices: services.map(s => s.name),
    affectedFindings: [],
    reason: 'Final state of the migration plan: all services operating exclusively with post-quantum algorithms, with no dependency on quantum-vulnerable public-key cryptography.',
    dependencies: [],
    status: 'todo',
    tags: ['pqc', 'full-migration', 'long-term'],
  });

  return tasks;
}
