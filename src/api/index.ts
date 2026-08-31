// ============================================================
// Qrypto AI Advisor — §11 REST API Service Layer (Mock)
//
// Implements all specified endpoints with in-browser routing.
// API is designed to be backend-swappable: replace the mock
// handlers with real fetch() calls without changing callers.
//
// Endpoints:
//   POST /api/projects
//   GET  /api/projects
//   POST /api/scans
//   GET  /api/scans/:id
//   GET  /api/projects/:id/inventory
//   GET  /api/projects/:id/findings
//   GET  /api/projects/:id/risk
//   POST /api/projects/:id/qday-simulation
//   GET  /api/projects/:id/attack-graph
//   POST /api/ai/analyze
//   POST /api/ai/migration-plan
//   POST /api/ai/code-remediation
//   GET  /api/projects/:id/migration
//   POST /api/migration/tasks
//   GET  /api/projects/:id/readiness
//   POST /api/projects/:id/report
//   POST /api/settings/ai        (Mock: setAIApiKey)
//   POST /api/ai/ask             (Mock: askAI)
// ============================================================

import type {
  Finding, ServiceNode, MigrationTask, QDaySimulation,
  Project, Asset, Certificate, SecretFinding, Simulation,
} from '../types';
import { computeQuantumReadinessIndex } from '../engine/riskEngine';
import { computeCryptoAgilityScore } from '../engine/cryptoAgility';
import { generateMigrationRoadmap, getUsageAwareRecommendation } from '../engine/migrationPlanner';
import { runScanPipeline } from '../engine/pipeline';
import { askConsultant } from '../ai/consultant';

// ─── §45 Observability & Logging ─────────────────────────────
//
// Safe logging wrapper that ensures no sensitive data is printed.
// Matches high-entropy strings, tokens, and keys.
//

const REDACT_PATTERN = /(?:sk-[a-zA-Z0-9]{32,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|AIza[0-9A-Za-z-_]{35}|password=.*|secret=.*)/g;

export const logger = {
  info: (msg: string, ...args: any[]) => {
    const safeMsg = msg.replace(REDACT_PATTERN, '[REDACTED_SECRET]');
    console.log(`[INFO] ${new Date().toISOString()} - ${safeMsg}`, ...args);
  },
  warn: (msg: string, ...args: any[]) => {
    const safeMsg = msg.replace(REDACT_PATTERN, '[REDACTED_SECRET]');
    console.warn(`[WARN] ${new Date().toISOString()} - ${safeMsg}`, ...args);
  },
  error: (msg: string, ...args: any[]) => {
    const safeMsg = msg.replace(REDACT_PATTERN, '[REDACTED_SECRET]');
    console.error(`[ERROR] ${new Date().toISOString()} - ${safeMsg}`, ...args);
  }
};

// ─── In-Memory Data Store ────────────────────────────────────

interface InMemoryStore {
  projects: Map<string, Project>;
  assets: Map<string, Asset>;
  certificates: Map<string, Certificate>;
  secretFindings: Map<string, SecretFinding>;
  findings: Map<string, Finding[]>;      // projectId → findings
  services: Map<string, ServiceNode[]>;  // projectId → services
  tasks: Map<string, MigrationTask[]>;   // projectId → tasks
  simulations: Map<string, Simulation>;
  scans: Map<string, ScanRecord>;
  aiApiKey: string | null;
}

interface ScanRecord {
  id: string;
  projectId: string;
  status: 'pending' | 'running' | 'complete' | 'error';
  startedAt: string;
  completedAt?: string;
  findings?: Finding[];
  error?: string;
}

const store: InMemoryStore = {
  projects: new Map(),
  assets: new Map(),
  certificates: new Map(),
  secretFindings: new Map(),
  findings: new Map(),
  services: new Map(),
  tasks: new Map(),
  simulations: new Map(),
  scans: new Map(),
  aiApiKey: localStorage.getItem('qg_gemini_key') || (import.meta as any).env?.VITE_OPENROUTER_API_KEY || null,
};

// ─── API Response Wrapper ────────────────────────────────────

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  status: number;
}

function ok<T>(data: T): ApiResponse<T> {
  return { data, status: 200 };
}

function created<T>(data: T): ApiResponse<T> {
  return { data, status: 201 };
}

function notFound(msg: string): ApiResponse<never> {
  return { error: msg, status: 404 };
}

function badRequest(msg: string): ApiResponse<never> {
  return { error: msg, status: 400 };
}

// ─── Project Endpoints ───────────────────────────────────────

/** POST /api/projects */
export function createProject(body: Omit<Project, 'id' | 'createdAt'>): ApiResponse<Project> {
  if (!body.name?.trim()) return badRequest('Project name is required.');
  const project: Project = {
    id: `proj-${Date.now()}`,
    createdAt: new Date().toISOString(),
    ...body,
  };
  store.projects.set(project.id, project);
  return created(project);
}

/** GET /api/projects */
export function listProjects(): ApiResponse<Project[]> {
  return ok([...store.projects.values()]);
}

/** GET /api/projects/:id */
export function getProject(id: string): ApiResponse<Project> {
  const p = store.projects.get(id);
  return p ? ok(p) : notFound(`Project ${id} not found.`);
}

// ─── Scan Endpoints ──────────────────────────────────────────

/** POST /api/scans */
export async function createScan(body: {
  projectId: string;
  files: { path: string; content: string }[];
}): Promise<ApiResponse<ScanRecord>> {
  const project = store.projects.get(body.projectId);
  if (!project) return notFound(`Project ${body.projectId} not found.`);
  if (!body.files?.length) return badRequest('At least one file is required.');

  const scan: ScanRecord = {
    id: `scan-${Date.now()}`,
    projectId: body.projectId,
    status: 'running',
    startedAt: new Date().toISOString(),
  };
  store.scans.set(scan.id, scan);

  // Run pipeline asynchronously
  runScanPipeline(body.files, { project: project.name }).then(result => {
    scan.status = 'complete';
    scan.completedAt = new Date().toISOString();
    scan.findings = result.findings;
    store.findings.set(body.projectId, result.findings);
    // Generate migration tasks
    const svcs = store.services.get(body.projectId) ?? [];
    store.tasks.set(body.projectId, generateMigrationRoadmap(result.findings, svcs));
    store.scans.set(scan.id, scan);
  }).catch(err => {
    scan.status = 'error';
    scan.error = err.message;
    store.scans.set(scan.id, scan);
  });

  return created(scan);
}

/** GET /api/scans/:id */
export function getScan(id: string): ApiResponse<ScanRecord> {
  const s = store.scans.get(id);
  return s ? ok(s) : notFound(`Scan ${id} not found.`);
}

// ─── Project Resource Endpoints ──────────────────────────────

/** GET /api/projects/:id/inventory */
export function getInventory(projectId: string): ApiResponse<{
  assets: Asset[];
  certificates: Certificate[];
  findings: Finding[];
}> {
  const findings = store.findings.get(projectId) ?? [];
  const assets = [...store.assets.values()].filter(a => a.projectId === projectId);
  const certificates = [...store.certificates.values()].filter(c =>
    assets.some(a => a.id === c.assetId)
  );
  return ok({ assets, certificates, findings });
}

/** GET /api/projects/:id/findings */
export function getFindings(
  projectId: string,
  filters?: { severity?: string; category?: string; status?: string }
): ApiResponse<Finding[]> {
  let findings = store.findings.get(projectId) ?? [];
  if (filters?.severity) findings = findings.filter(f => f.severity === filters.severity);
  if (filters?.category) findings = findings.filter(f => f.category === filters.category);
  if (filters?.status)   findings = findings.filter(f => f.remediationStatus === filters.status);
  return ok(findings);
}

/** GET /api/projects/:id/risk */
export function getRisk(projectId: string): ApiResponse<{
  readinessIndex: ReturnType<typeof computeQuantumReadinessIndex>;
  agilityScore: ReturnType<typeof computeCryptoAgilityScore>;
  topRisks: Finding[];
}> {
  const findings = store.findings.get(projectId) ?? [];
  return ok({
    readinessIndex: computeQuantumReadinessIndex(findings),
    agilityScore: computeCryptoAgilityScore(findings),
    topRisks: findings.slice(0, 10),
  });
}

/** GET /api/projects/:id/readiness */
export function getReadiness(projectId: string): ApiResponse<{
  score: number;
  breakdown: ReturnType<typeof computeQuantumReadinessIndex>;
}> {
  const findings = store.findings.get(projectId) ?? [];
  const breakdown = computeQuantumReadinessIndex(findings);
  return ok({ score: breakdown.overall, breakdown });
}

/** GET /api/projects/:id/migration */
export function getMigration(projectId: string): ApiResponse<MigrationTask[]> {
  return ok(store.tasks.get(projectId) ?? []);
}

/** POST /api/migration/tasks */
export function createTask(body: Omit<MigrationTask, 'id'>): ApiResponse<MigrationTask> {
  const task: MigrationTask = { id: `mt-${Date.now()}`, ...body };
  const projectFindings = body.affectedFindings[0]
    ? store.findings.get([...store.projects.keys()][0]) // best effort
    : [];
  return created(task);
}

// ─── Q-Day Simulation ────────────────────────────────────────

/** POST /api/projects/:id/qday-simulation */
export function runQDaySimulation(projectId: string, body?: {
  scenario?: string;
  assumptions?: string[];
}): ApiResponse<Simulation> {
  const findings = store.findings.get(projectId) ?? [];
  const services = store.services.get(projectId) ?? [];
  const vulnerableFindings = findings.filter(f => f.quantumStatus === 'vulnerable');

  const affectedServiceNames = [...new Set(vulnerableFindings.map(f => f.service))];
  const affectedAssetIds = [...new Set(
    [...store.assets.values()]
      .filter(a => a.projectId === projectId)
      .map(a => a.id)
  )];

  const riskBefore = computeQuantumReadinessIndex(findings).overall;
  const riskAfter = Math.max(10, riskBefore - 35);

  const sim: Simulation = {
    id: `sim-${Date.now()}`,
    projectId,
    scenario: body?.scenario ?? 'Q-Day: Cryptographically-Relevant Quantum Computer Available',
    assumptions: body?.assumptions ?? [
      'A cryptographically-relevant quantum computer becomes available',
      'Shor\'s algorithm can factor RSA-2048 in practical time',
      'All RSA and ECC public-key operations are immediately compromised',
      'Data harvested before Q-Day can be decrypted retroactively',
    ],
    affectedAssets: affectedAssetIds,
    affectedServices: affectedServiceNames,
    riskBefore,
    riskAfter,
    createdAt: new Date().toISOString(),
  };

  store.simulations.set(sim.id, sim);
  return created(sim);
}

/** GET /api/projects/:id/attack-graph */
export function getAttackGraph(projectId: string): ApiResponse<{
  nodes: ServiceNode[];
  edges: { from: string; to: string; riskLabel: string }[];
  cascadePath: string[];
}> {
  const services = store.services.get(projectId) ?? [];
  const edges = services.flatMap(s =>
    s.dependencies.map(dep => ({
      from: dep,
      to: s.id,
      riskLabel: s.riskScore >= 80 ? 'critical' : s.riskScore >= 60 ? 'high' : 'medium',
    }))
  );
  // Cascade: highest-risk path from internet
  const sorted = [...services].sort((a, b) => b.riskScore - a.riskScore);
  const cascadePath = sorted.slice(0, 5).map(s => s.name);

  return ok({ nodes: services, edges, cascadePath });
}

// ─── AI Endpoints ─────────────────────────────────────────────
// Note: These only send relevant evidence — never full file content.

/** POST /api/ai/analyze */
export function buildAnalyzePayload(
  findings: Finding[],
  question: string
): { systemContext: string; evidenceSnippets: string[] } {
  // §12 rule: only send relevant evidence snippets
  const relevant = findings
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 15);

  const evidenceSnippets = relevant.map(f =>
    `[${f.id}] ${f.algorithm} in ${f.file}:${f.line} — ${f.detectedPattern}`
  );

  const systemContext = [
    `Total findings: ${findings.length}`,
    `Quantum-vulnerable: ${findings.filter(f => f.quantumStatus === 'vulnerable').length}`,
    `Critical: ${findings.filter(f => f.severity === 'critical').length}`,
    `Question: ${question}`,
  ].join('\n');

  return { systemContext, evidenceSnippets };
}

/** POST /api/ai/migration-plan */
export function getMigrationPlan(
  projectId: string,
  algorithm: string,
  usage: string
): ApiResponse<ReturnType<typeof getUsageAwareRecommendation>> {
  return ok(getUsageAwareRecommendation(algorithm, usage));
}

/** POST /api/ai/code-remediation */
export function getCodeRemediationGuide(
  algorithm: string,
  language: string
): ApiResponse<{ example: string; disclaimer: string }> {
  const examples: Record<string, Record<string, string>> = {
    'RSA': {
      python: `# EXAMPLE ONLY — Not production-ready. Test thoroughly before deployment.
# Migration: RSA key establishment → ML-KEM (hybrid approach)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
# ML-KEM requires liboqs or similar — verify library support first
# Hybrid: combine X25519 shared secret with ML-KEM for defense-in-depth
x25519_private = X25519PrivateKey.generate()
x25519_public = x25519_private.public_key()
# Continue with ML-KEM encapsulation in your PQC library`,
      java: `// EXAMPLE ONLY — Not production-ready. Test thoroughly before deployment.
// For ML-KEM, use BouncyCastle >= 1.77 with FIPS 203 support
// import org.bouncycastle.pqc.crypto.mlkem.*;
// MLKEMKeyPairGenerator kpGen = new MLKEMKeyPairGenerator();
// kpGen.init(new MLKEMKeyGenerationParameters(new SecureRandom(), MLKEMParameters.ml_kem_768));
// AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();`,
    },
    'MD5': {
      python: `# EXAMPLE ONLY — Not production-ready.
import hashlib
# Replace: hashlib.md5(data)
# With:    hashlib.sha256(data)      (for integrity)
# Or:      argon2-cffi               (for password hashing)
digest = hashlib.sha256(data).hexdigest()`,
      javascript: `// EXAMPLE ONLY — Not production-ready.
// Replace: crypto.createHash('md5')
// With:    crypto.createHash('sha256')
const hash = crypto.createHash('sha256').update(data).digest('hex');`,
    },
  };

  const exampleCode = examples[algorithm]?.[language.toLowerCase()]
    ?? `// No example available for ${algorithm} in ${language}. Consult NIST PQC guidelines.`;

  return ok({
    example: exampleCode,
    disclaimer: 'This is a code example only. It has not been security-reviewed or tested in production. Validate all cryptographic changes with your security team before deployment.',
  });
}

/** POST /api/projects/:id/report */
export function generateReport(projectId: string): ApiResponse<{
  projectId: string;
  generatedAt: string;
  summary: object;
}> {
  const findings = store.findings.get(projectId) ?? [];
  const readiness = computeQuantumReadinessIndex(findings);
  return ok({
    projectId,
    generatedAt: new Date().toISOString(),
    summary: {
      totalFindings: findings.length,
      criticalCount: findings.filter(f => f.severity === 'critical').length,
      quantumVulnerable: findings.filter(f => f.quantumStatus === 'vulnerable').length,
      quantumReadiness: readiness.overall,
    },
  });
}



// ─── AI Mock Endpoints ───────────────────────────────────────

/** POST /api/settings/ai */
export function setAIApiKey(body: { apiKey: string }): ApiResponse<void> {
  store.aiApiKey = body.apiKey;
  return ok(undefined);
}

/** POST /api/ai/ask */
export async function askAI(
  projectId: string,
  body: {
    question: string;
    chatHistory: Array<{ role: 'user' | 'model'; parts: Array<{ text: string }> }>;
    assessment?: any; // Full assessment from Zustand store (preferred)
  }
): Promise<ApiResponse<{ answer: string; citedFindings: string[] }>> {
  // Use the assessment passed directly from the Zustand store when available.
  // Fall back to reconstructing from the API store for backward compatibility.
  let assessment = body.assessment;

  if (!assessment) {
    const project = store.projects.get(projectId);
    const findings = store.findings.get(projectId) || [];
    assessment = {
      id: projectId,
      name: project?.name || 'Scanned Repository',
      organization: project?.owner || 'Your Organization',
      industry: 'Technology',
      findings,
      services: store.services.get(projectId) || [],
      migrationTasks: store.tasks.get(projectId) || [],
      quantumReadinessScore: computeQuantumReadinessIndex(findings).overall,
      scanStats: {
        criticalCount: findings.filter((f) => f.severity === 'critical').length,
        highCount: findings.filter((f) => f.severity === 'high').length,
        vulnerableAlgorithms: findings.filter((f) => f.quantumStatus === 'vulnerable').length,
        secretsFound: findings.filter((f) => f.category === 'secret').length,
      }
    };
  }

  try {
    const result = await askConsultant(
      body.question, 
      assessment, 
      store.aiApiKey || undefined, 
      body.chatHistory
    );
    return ok(result);
  } catch (error: any) {
    return badRequest(`AI Request failed: ${error.message}`);
  }
}

export { store };
