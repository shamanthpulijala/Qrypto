// ============================================================
// QuantumGuard AI — Migration Planner Engine
// Generates prioritized 4-phase PQC migration roadmap from findings
// §17: Usage-aware recommendations (key establishment ≠ signature)
// §31: Standard migration tasks with Owner, Priority, Effort, Dependencies, Status
// ============================================================

import type { Finding, MigrationTask, ServiceNode } from '../types';

let taskCounter = 0;
function taskId(): string {
  return `MT-${String(++taskCounter).padStart(3, '0')}`;
}

function daysFromNow(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().split('T')[0];
}

// ─── §17 Usage-Aware Migration Mapping ───────────────────────

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

  // RSA general → context-dependent
  if (alg.startsWith('RSA')) {
    return {
      replacement: 'ML-KEM (key encapsulation) or ML-DSA (signatures)',
      strategy: 'Determine usage context before recommending specific PQC algorithm. Evaluate hybrid approach during migration.',
      notes: 'Usage context must be established before selecting PQC successor.',
    };
  }

  // ECDH used for key establishment → ML-KEM / hybrid
  if (alg === 'ECDH' || usageLower.includes('key exchange') || usageLower.includes('key establishment')) {
    return {
      replacement: 'ML-KEM (FIPS 203)',
      strategy: 'Hybrid X25519+ML-KEM-768 provides backward compatibility during transition. Target pure ML-KEM-768 for long-term.',
      notes: 'ECDH key exchange should migrate to ML-KEM.',
    };
  }

  // SHA-1 → replace with modern hash
  if (alg === 'SHA-1' || alg.includes('SHA1')) {
    return {
      replacement: 'SHA-256 or SHA-3-256',
      strategy: 'Replace with SHA-256 where appropriate.',
      notes: 'SHA-1 has known collision vulnerabilities.',
    };
  }

  // MD5 → remove
  if (alg === 'MD5') {
    return {
      replacement: 'SHA-256 (integrity) or Argon2id (password)',
      strategy: 'Remove MD5 from all security-sensitive usage.',
      notes: 'MD5 is classically broken.',
    };
  }

  // TLS 1.0 / 1.1 → upgrade
  if (alg.includes('TLS 1.0') || alg.includes('TLS 1.1') || alg.includes('SSL')) {
    return {
      replacement: 'TLS 1.3 (minimum TLS 1.2)',
      strategy: 'Upgrade TLS configuration. Set minimum_version = TLS 1.2, prefer TLS 1.3.',
      notes: 'Weak TLS is a classical security problem. Upgrade immediately.',
    };
  }

  // Hardcoded secret → secrets manager
  if (alg.toLowerCase().includes('secret') || alg.toLowerCase().includes('key') || alg.toLowerCase().includes('password')) {
    return {
      replacement: 'Managed secret storage',
      strategy: 'Rotate immediately. Move to HashiCorp Vault or AWS Secrets Manager.',
      notes: 'Hardcoded secrets are an immediate operational risk.',
    };
  }

  return {
    replacement: 'NIST PQC Standard (FIPS 203/204/205)',
    strategy: 'Evaluate algorithm usage context and replace with appropriate NIST PQC standard.',
    notes: 'General PQC migration required.',
  };
}

// ─── Roadmap Generator ───────────────────────────────────────

export function generateMigrationRoadmap(
  findings: Finding[],
  services: ServiceNode[]
): MigrationTask[] {
  taskCounter = 0;
  const tasks: MigrationTask[] = [];

  // §31 Task 1: Remove SHA-1 from Legacy API
  const sha1Findings = findings.filter(f => f.algorithm.includes('SHA1') || f.algorithm.includes('SHA-1'));
  tasks.push({
    id: taskId(),
    findingId: sha1Findings[0]?.id,
    phase: 1,
    title: 'Remove SHA-1 from Legacy API',
    description: 'Deprecate SHA-1 hashing in legacy API integrations. Upgrade to SHA-256 / SHA-3 to eliminate classical collision vulnerabilities.',
    priority: 'high',
    effort: 'weeks',
    effortValue: 2,
    estimatedEffort: '2 weeks',
    affectedServices: ['Legacy API Service', 'API Gateway'],
    affectedFindings: sha1Findings.map(f => f.id),
    reason: 'SHA-1 is classically broken due to collision attacks. Deprecation is required by NIST and PCI-DSS compliance.',
    dependencies: [],
    owner: 'DevSecOps Team',
    dueDate: daysFromNow(14),
    status: 'done',
    tags: ['sha-1', 'legacy-api', 'compliance'],
  });

  // §31 Task 2: Upgrade TLS configuration
  const tlsFindings = findings.filter(f => f.category === 'tls');
  tasks.push({
    id: taskId(),
    findingId: tlsFindings[0]?.id,
    phase: 1,
    title: 'Upgrade TLS configuration',
    description: 'Disable TLS 1.0/1.1 across all load balancers and API endpoints. Enforce minimum TLS 1.2 with preference for TLS 1.3 cipher suites.',
    priority: 'critical',
    effort: 'weeks',
    effortValue: 2,
    estimatedEffort: '2 weeks',
    affectedServices: ['API Gateway', 'Payment Service', 'Auth Service'],
    affectedFindings: tlsFindings.map(f => f.id),
    reason: 'Weak TLS protocols expose communications to POODLE/BEAST attacks. Upgrade is mandatory before PQC transition.',
    dependencies: ['MT-001'],
    owner: 'Core Infrastructure Team',
    dueDate: daysFromNow(21),
    status: 'done',
    tags: ['tls', 'infrastructure', 'security'],
  });

  // §31 Task 3: Rotate exposed secret
  const secretFindings = findings.filter(f => f.category === 'secret');
  tasks.push({
    id: taskId(),
    findingId: secretFindings[0]?.id,
    phase: 1,
    title: 'Rotate exposed secret',
    description: 'Revoke and rotate hardcoded cryptographic keys and credentials detected in source code. Inject via HashiCorp Vault.',
    priority: 'critical',
    effort: 'days',
    effortValue: 1,
    estimatedEffort: '3 days',
    affectedServices: ['Payment Service', 'Auth Service'],
    affectedFindings: secretFindings.map(f => f.id),
    reason: 'Hardcoded secrets in source repositories represent immediate compromise vectors regardless of quantum computing timeline.',
    dependencies: [],
    owner: 'Security Engineering',
    dueDate: daysFromNow(5),
    status: 'in-progress',
    tags: ['secrets', 'immediate', 'credentials'],
  });

  // §31 Task 4: Assess RSA payment certificate
  const paymentCertFindings = findings.filter(f => f.service.includes('Payment') || f.algorithm.includes('RSA'));
  tasks.push({
    id: taskId(),
    findingId: paymentCertFindings[0]?.id,
    phase: 2,
    title: 'Assess RSA payment certificate',
    description: 'Audit 2048-bit and 4096-bit RSA TLS certificates used in Payment Service. Formulate PQC CA migration timeline.',
    priority: 'high',
    effort: 'months',
    effortValue: 3,
    estimatedEffort: '1 month',
    affectedServices: ['Payment Service'],
    affectedFindings: paymentCertFindings.map(f => f.id),
    reason: 'RSA certificates protecting high-value transactions must transition to post-quantum signatures (ML-DSA / SLH-DSA).',
    dependencies: ['MT-002', 'MT-003'],
    owner: 'Payment Engineering',
    dueDate: daysFromNow(45),
    status: 'todo',
    tags: ['rsa', 'payment', 'pqc-assessment'],
  });

  // §31 Task 5: Evaluate hybrid key establishment
  const keyEstFindings = findings.filter(f => f.usage.toLowerCase().includes('key') || f.quantumStatus === 'vulnerable');
  tasks.push({
    id: taskId(),
    findingId: keyEstFindings[0]?.id,
    phase: 2,
    title: 'Evaluate hybrid key establishment',
    description: 'Benchmark hybrid X25519 + ML-KEM-768 key encapsulation in staging environment for internet-facing data paths.',
    priority: 'high',
    effort: 'months',
    effortValue: 4,
    estimatedEffort: '2 months',
    affectedServices: ['API Gateway', 'Payment Service'],
    affectedFindings: keyEstFindings.map(f => f.id),
    reason: 'Hybrid key encapsulation protects long-lived sensitive data against Harvest-Now-Decrypt-Later attacks while preserving classical safety.',
    dependencies: ['MT-004'],
    owner: 'Cryptography Research Team',
    dueDate: daysFromNow(60),
    status: 'todo',
    tags: ['ml-kem', 'hybrid', 'hndl-mitigation'],
  });

  // §31 Task 6: Centralize crypto configuration
  tasks.push({
    id: taskId(),
    phase: 3,
    title: 'Centralize crypto configuration',
    description: 'Refactor direct low-level cryptographic library calls into a unified crypto-provider interface to support seamless algorithm agility.',
    priority: 'medium',
    effort: 'months',
    effortValue: 5,
    estimatedEffort: '3 months',
    affectedServices: ['User Service', 'Account Database', 'Auth Service'],
    affectedFindings: [],
    reason: 'Decentralized crypto implementations complicate algorithm replacement during future PQC upgrades.',
    dependencies: ['MT-005'],
    owner: 'Architecture Guild',
    dueDate: daysFromNow(90),
    status: 'todo',
    tags: ['crypto-agility', 'architecture', 'refactoring'],
  });

  return tasks;
}
