// ============================================================
// QuantumGuard AI — Migration Planner Engine
// Generates prioritized 4-phase PQC migration roadmap from findings
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
      strategy: 'Replace with SHA-256 or SHA-3-256 where appropriate.',
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

// ─── Dynamic Roadmap Generator ───────────────────────────────

export function generateMigrationRoadmap(
  findings: Finding[],
  services: ServiceNode[]
): MigrationTask[] {
  taskCounter = 0;
  const tasks: MigrationTask[] = [];

  const vulnerableFindings = findings.filter(f => f.quantumStatus === 'vulnerable');
  const weakFindings = findings.filter(f => f.quantumStatus === 'classical-weak');
  const secretFindings = findings.filter(f => f.category === 'secret');
  const tlsFindings = findings.filter(f => f.category === 'tls' && f.quantumStatus !== 'adequate');
  const pqcFindings = findings.filter(f => f.quantumStatus === 'quantum-resistant');

  // Case A: High Readiness / PQC-Migrated Repo (0 critical/vulnerable findings or mostly PQC)
  // All tasks start as 'todo' with no fabricated owner. A freshly scanned repo must not
  // contain tasks marked 'done' unless derived from actual persisted state.
  if (vulnerableFindings.length === 0 && weakFindings.length === 0 && secretFindings.length === 0) {
    if (pqcFindings.length > 0) {
      tasks.push({
        id: taskId(),
        phase: 1,
        title: `Verify ${pqcFindings.length} PQC Algorithm(s) for Correct Configuration`,
        description: `Audit the ${pqcFindings.length} detected post-quantum algorithm(s) to verify correct parameter sets and usage patterns.`,
        priority: 'low',
        effort: 'days',
        effortValue: 1,
        estimatedEffort: '1-3 days',
        affectedServices: [...new Set(pqcFindings.map(f => f.service))],
        affectedFindings: pqcFindings.map(f => f.id),
        reason: 'Repository is PQC-compliant. Verify correct algorithm configuration to prevent misuse.',
        dependencies: [],
        dueDate: daysFromNow(14),
        status: 'todo',
        tags: ['pqc-verified', 'compliance'],
      });
    }

    tasks.push({
      id: taskId(),
      phase: 2,
      title: 'Establish Continuous Cryptographic Monitoring',
      description: 'Set up automated scanning to detect regressions — new classical-vulnerable algorithms introduced in code changes.',
      priority: 'medium',
      effort: 'weeks',
      effortValue: 2,
      estimatedEffort: '1-2 weeks',
      affectedServices: services.map(s => s.name).slice(0, 5),
      affectedFindings: [],
      reason: 'Prevent reintroduction of quantum-vulnerable or classically-weak algorithms.',
      dependencies: [],
      dueDate: daysFromNow(30),
      status: 'todo',
      tags: ['monitoring', 'regression-prevention'],
    });

    return tasks;
  }

  // Case B: Standard Scanned Repository with Detected Vulnerabilities

  // Phase 1: Rotate Secrets if detected
  if (secretFindings.length > 0) {
    const affectedServs = [...new Set(secretFindings.map(f => f.service))];
    tasks.push({
      id: taskId(),
      findingId: secretFindings[0]?.id,
      phase: 1,
      title: `Rotate ${secretFindings.length} Hardcoded Secret(s)`,
      description: `Revoke and rotate hardcoded credentials detected in ${affectedServs.join(', ')}. Inject via Vault / AWS Secrets Manager.`,
      priority: 'critical',
      effort: 'days',
      effortValue: 1,
      estimatedEffort: '3 days',
      affectedServices: affectedServs,
      affectedFindings: secretFindings.map(f => f.id),
      reason: 'Hardcoded secrets represent an immediate compromise vector.',
      dependencies: [],
      dueDate: daysFromNow(3),
      status: 'todo',
      tags: ['secrets', 'immediate', 'credentials'],
    });
  }

  // Phase 1: Deprecate Classically Weak Algorithms (MD5, SHA-1, Weak TLS)
  if (weakFindings.length > 0 || tlsFindings.length > 0) {
    const weakList = [...new Set([...weakFindings, ...tlsFindings])];
    const weakAlgos = [...new Set(weakList.map(f => f.algorithm))].join(', ');
    const affectedServs = [...new Set(weakList.map(f => f.service))];
    // Categorize replacements by type for accurate description
    const replacements = weakList.map(f => {
      const alg = f.algorithm.toUpperCase();
      if (alg.includes('MD5')) return 'SHA-256 or Argon2id';
      if (alg.includes('SHA-1') || alg.includes('SHA1')) return 'SHA-256 or SHA-3-256';
      if (alg.includes('DES') || alg.includes('3DES')) return 'AES-256-GCM';
      if (alg.includes('RC4')) return 'AES-256-GCM or ChaCha20-Poly1305';
      if (alg.includes('TLS 1.0') || alg.includes('TLS 1.1') || alg.includes('SSL')) return 'TLS 1.3';
      return 'modern replacement';
    });
    const uniqueReplacements = [...new Set(replacements)].join(', ');
    tasks.push({
      id: taskId(),
      findingId: weakList[0]?.id,
      phase: 1,
      title: `Deprecate Classically Weak Algorithms (${weakAlgos})`,
      description: `Replace deprecated primitives (${weakAlgos}) in ${affectedServs.join(', ')} with ${uniqueReplacements}.`,
      priority: 'high',
      effort: 'weeks',
      effortValue: 2,
      estimatedEffort: '2 weeks',
      affectedServices: affectedServs,
      affectedFindings: weakList.map(f => f.id),
      reason: 'Classically weak primitives are vulnerable to immediate collision or decryption attacks.',
      dependencies: [],
      dueDate: daysFromNow(14),
      status: 'todo',
      tags: ['legacy-crypto', 'deprecation', 'sha1-md5'],
    });
  }

  // Phase 2: Migrate RSA / ECC Key Establishment to ML-KEM (FIPS 203)
  // NOTE: Exclude signature findings — they are handled in Phase 3.
  const sigFindingsFilter = (f: Finding) => {
    const usage = f.usage.toLowerCase();
    return usage.includes('sign') || usage.includes('auth') || usage.includes('cert') || usage.includes('verify');
  };
  const keyEstFindings = vulnerableFindings.filter(f => {
    // Skip signature findings — they go to Phase 3
    if (sigFindingsFilter(f)) return false;
    return f.algorithm.startsWith('RSA') || f.algorithm === 'ECDH' || f.algorithm === 'DH' || f.category === 'public-key' || f.category === 'key-exchange';
  });
  if (keyEstFindings.length > 0) {
    const affectedServs = [...new Set(keyEstFindings.map(f => f.service))];
    tasks.push({
      id: taskId(),
      findingId: keyEstFindings[0]?.id,
      phase: 2,
      title: `Migrate ${keyEstFindings.length} Key Establishment Instance(s) to ML-KEM-768`,
      description: `Implement hybrid X25519 + ML-KEM-768 key encapsulation for key exchange in ${affectedServs.join(', ')}.`,
      priority: 'critical',
      effort: 'months',
      effortValue: 3,
      estimatedEffort: '1 month',
      affectedServices: affectedServs,
      affectedFindings: keyEstFindings.map(f => f.id),
      reason: 'Public key encryption and key exchange are vulnerable to Shor\'s algorithm (Harvest-Now-Decrypt-Later).',
      dependencies: tasks.length > 0 ? [tasks[0].id] : [],
      dueDate: daysFromNow(45),
      status: 'todo',
      tags: ['ml-kem', 'fips-203', 'hybrid-kem'],
    });
  }

  // Phase 3: Migrate RSA / ECDSA Signatures to ML-DSA (FIPS 204)
  // Catches ALL signature usage: RSA-for-signing, ECDSA, DSA, Ed25519
  const sigFindings = vulnerableFindings.filter(f => {
    const usage = f.usage.toLowerCase();
    const isSignatureUsage = usage.includes('sign') || usage.includes('auth') || usage.includes('cert') || usage.includes('verify');
    if (!isSignatureUsage) return false;
    return f.algorithm === 'ECDSA' || f.algorithm === 'DSA' || f.algorithm === 'Ed25519' ||
           (f.algorithm.startsWith('RSA') && f.category !== 'key-exchange') ||
           f.category === 'signature';
  });
  if (sigFindings.length > 0) {
    const affectedServs = [...new Set(sigFindings.map(f => f.service))];
    tasks.push({
      id: taskId(),
      findingId: sigFindings[0]?.id,
      phase: 3,
      title: `Migrate Digital Signatures to ML-DSA-65 (FIPS 204)`,
      description: `Replace classical digital signatures in ${affectedServs.join(', ')} with ML-DSA-65 post-quantum signatures.`,
      priority: 'high',
      effort: 'months',
      effortValue: 4,
      estimatedEffort: '2 months',
      affectedServices: affectedServs,
      affectedFindings: sigFindings.map(f => f.id),
      reason: 'Digital signatures must be post-quantum secure to prevent transaction forging.',
      dependencies: tasks.length > 0 ? [tasks[tasks.length - 1].id] : [],
      dueDate: daysFromNow(75),
      status: 'todo',
      tags: ['ml-dsa', 'fips-204', 'signatures'],
    });
  }

  // Phase 4: Centralize Crypto-Agility Abstraction Layer
  tasks.push({
    id: taskId(),
    phase: 4,
    title: 'Centralize Cryptographic Abstraction & Provider Layer',
    description: `Refactor direct cryptographic library calls across ${services.map(s => s.name).slice(0, 3).join(', ')} into a central Security Policy Provider.`,
    priority: 'medium',
    effort: 'months',
    effortValue: 5,
    estimatedEffort: '3 months',
    affectedServices: services.map(s => s.name),
    affectedFindings: findings.filter(f => f.isHardcoded).map(f => f.id),
    reason: 'Centralized algorithm management ensures future PQC algorithm swaps require zero application code changes.',
    dependencies: tasks.length > 0 ? [tasks[tasks.length - 1].id] : [],
    dueDate: daysFromNow(120),
    status: 'todo',
    tags: ['crypto-agility', 'refactoring', 'architecture'],
  });

  return tasks;
}
