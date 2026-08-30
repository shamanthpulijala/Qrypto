// ============================================================
// Qrypto AI Advisor — Core Type Definitions
// ============================================================

export type Language = 'python' | 'java' | 'javascript' | 'typescript' | 'go' | 'yaml' | 'json' | 'xml' | 'unknown';

export type AlgorithmCategory =
  | 'public-key'
  | 'hash'
  | 'symmetric'
  | 'tls'
  | 'signature'
  | 'secret'
  | 'key-exchange'
  | 'certificate'
  | 'pqc'
  | 'hardware-module'   // P1: HSM/PKCS#11/TPM
  | 'cloud-kms'         // P1: Cloud KMS services
  | 'container-config'  // P1: Dockerfile/container configuration
  | 'binary-artifact';  // P1: Binary crypto artifacts

export type QuantumStatus =
  | 'vulnerable'       // RSA, ECC, ECDH, ECDSA, DH, DSA
  | 'classical-weak'   // MD5, SHA-1, DES, 3DES, weak TLS
  | 'adequate'         // AES-256, SHA-256, SHA-3
  | 'quantum-resistant' // ML-KEM, ML-DSA, SLH-DSA
  | 'unknown';

export type ClassicalStatus =
  | 'broken'           // MD5, DES, RC4, SSL — classically compromised
  | 'weak'             // SHA-1, 3DES, TLS 1.0/1.1 — deprecated
  | 'adequate'         // RSA-2048, AES-128, TLS 1.2 — acceptable classically
  | 'strong'           // AES-256, SHA-256, TLS 1.3 — classically strong
  | 'unknown';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RemediationStatus = 'open' | 'in-progress' | 'remediated' | 'accepted-risk' | 'wont-fix';

// ============================================================
// §10 — Core Entity: Project
// ============================================================

export interface Project {
  id: string;
  name: string;
  description: string;
  repository: string;
  language: Language;
  owner: string;
  createdAt: string; // ISO date
}

// ============================================================
// §10 — Core Entity: Asset
// ============================================================

export type AssetType = 'service' | 'database' | 'library' | 'infrastructure' | 'certificate' | 'config';
export type AssetEnvironment = 'production' | 'staging' | 'development' | 'test';
export type AssetCriticality = 'critical' | 'high' | 'medium' | 'low';

export interface Asset {
  id: string;
  projectId: string;
  type: AssetType;
  name: string;
  location: string;        // e.g. "services/payment/src"
  environment: AssetEnvironment;
  criticality: AssetCriticality;
  internetFacing: boolean;
  dataSensitivity: 'critical' | 'high' | 'medium' | 'low';
}

// ============================================================
// §10 — Core Entity: Certificate
// ============================================================

export type CertificateStatus = 'valid' | 'expiring' | 'expired' | 'revoked' | 'unknown';

export interface Certificate {
  id: string;
  assetId: string;
  subject: string;
  issuer: string;
  algorithm: string;       // e.g. "SHA256withRSA", "SHA1withRSA"
  keySize: number;
  validFrom: string;       // ISO date
  validTo: string;         // ISO date
  tlsVersion: string;      // e.g. "TLS 1.3", "TLS 1.2"
  status: CertificateStatus;
}

// ============================================================
// §10 — Core Entity: SecretFinding
// ============================================================

export type SecretType =
  | 'api-key'
  | 'jwt-secret'
  | 'private-key'
  | 'password'
  | 'oauth-token'
  | 'aws-key'
  | 'database-credential'
  | 'certificate-material'
  | 'unknown';

export interface SecretFinding {
  id: string;
  projectId: string;
  file: string;
  line: number;
  type: SecretType;
  maskedValue: string;     // e.g. "sk_live_****...92"
  severity: Severity;
  rotationRequired: boolean;
  status: RemediationStatus;
}

// ============================================================
// §10 — Core Entity: Simulation
// ============================================================

export interface Simulation {
  id: string;
  projectId: string;
  scenario: string;        // e.g. "Q-Day: Cryptographically-Relevant Quantum Computer"
  assumptions: string[];
  affectedAssets: string[];   // asset IDs
  affectedServices: string[]; // service names
  riskBefore: number;      // 0-100
  riskAfter: number;       // 0-100
  createdAt: string;       // ISO date
}

export interface RiskBreakdown {
  algorithmRisk: number;        // 0-100
  businessCriticality: number;  // 0-100
  internetExposure: number;     // 0-100
  dataLifetime: number;         // 0-100
  dataSensitivity: number;      // 0-100
  migrationDifficulty: number;  // 0-100
  totalScore: number;           // 0-100 weighted
}

export type CryptoMode = 'ECB' | 'CBC' | 'GCM' | 'CTR' | 'CFB' | 'OFB' | 'CCM' | 'unknown' | '';

export interface Finding {
  id: string;
  // Location
  file: string;
  line: number;
  endLine?: number;
  repository: string;
  project: string;
  service: string;
  language: Language;
  // Detection
  algorithm: string;
  keySize?: number;
  category: AlgorithmCategory;
  usage: string;            // e.g. "key establishment", "digital signature", "password hashing"
  detectedPattern: string;  // exact matched code snippet (masked if secret)
  confidence: number;       // 0.0 - 1.0
  // Classification (P0-10)
  mode?: CryptoMode;        // cipher mode if detected (GCM, CBC, etc.)
  library?: string;         // e.g. "cryptography", "crypto-js", "java.security"
  libraryVersion?: string;  // e.g. "42.0.0" if extracted from manifest
  protocol?: string;        // e.g. "TLS 1.3", "SSH", "IPsec"
  variant?: string;         // e.g. "ML-KEM-768", "AES-256-GCM", "secp256r1"
  // Classification
  quantumStatus: QuantumStatus;
  classicalStatus: ClassicalStatus; // §10 — independent classical security posture
  /**
   * Intrinsic severity of the primitive and its parameters, independent of
   * where it was found. The same algorithm always reports the same value here.
   * See shared/engine/severity.ts for the model and its invariants.
   */
  algorithmSeverity: Severity;
  /**
   * Effective severity for display and sorting: algorithmSeverity adjusted by
   * bounded deployment context. Never below algorithmSeverity, and never
   * escalated for quantum-resistant primitives.
   */
  severity: Severity;
  /** Human-readable derivation of `severity`, so the value is auditable. */
  severityRationale: string;
  // Context
  internetFacing: boolean;
  dataSensitivity: 'critical' | 'high' | 'medium' | 'low';
  dataLifetimeYears: number; // estimated years data must remain confidential
  isCryptoAgile: boolean;
  isHardcoded: boolean;
  /**
   * How the context fields were derived.
   * - INFERRED: from file path / service name heuristics
   * - OVERRIDE: from analyst-supplied context override
   * - EXPLICIT: from repository/project metadata or manifest
   * - UNKNOWN: context could not be determined
   */
  contextSource?: 'INFERRED' | 'OVERRIDE' | 'EXPLICIT' | 'UNKNOWN';
  // Risk
  riskScore: number;         // 0-100
  riskBreakdown: RiskBreakdown;
  // Remediation
  remediationStatus: RemediationStatus;
  migrationPriority: number; // 1 = highest
  recommendedAlgorithm?: string;
  migrationStrategy?: string;
  // Metadata
  owner?: string;
  tags: string[];
  cweId?: string;
  detectedAt: string; // ISO date
  /**
   * Stable fingerprint for this finding. Used for upsert on rescan so
   * suppressions and triage state survive across scans. Generated from
   * normalized path, algorithm, usage, and code context (not line numbers).
   */
  fingerprint?: string;
  /** When this finding was first observed across all scans. */
  firstSeen?: string;
  /** When this finding was most recently observed. */
  lastSeen?: string;
  evidence?: {
    detectionLayers: string[];
    matchedText: string;
    astContext?: any;
    confidenceDerivation: string;
  };
}

export interface CBOMEntry {
  algorithm: string;
  category: AlgorithmCategory;
  quantumStatus: QuantumStatus;
  occurrences: number;
  affectedFiles: string[];
  affectedServices: string[];
  maxSeverity: Severity;
  avgRiskScore: number;
  findings: Finding[];
}

export interface ServiceNode {
  id: string;
  name: string;
  type: 'gateway' | 'service' | 'database' | 'external' | 'queue' | 'storage' | 'auth' | 'internet';
  internetFacing: boolean;
  dataSensitivity: 'critical' | 'high' | 'medium' | 'low';
  cryptoFindings: string[]; // finding IDs
  riskScore: number;
  dependencies: string[]; // service IDs this depends on
  position: { x: number; y: number };
}

export interface MigrationTask {
  id: string;
  findingId?: string;       // §10 — optional link to triggering CryptoFinding
  phase: 1 | 2 | 3 | 4;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  effort: 'days' | 'weeks' | 'months';
  effortValue: number;
  estimatedEffort: string;  // §10 — human-readable, e.g. "2 weeks"
  affectedServices: string[];
  affectedFindings: string[];
  reason: string;
  dependencies: string[];
  owner?: string;
  dueDate?: string;         // §10 — ISO date for scheduling
  status: 'todo' | 'in-progress' | 'done';
  tags: string[];
}

export interface QDaySimulation {
  active: boolean;
  vulnerableFindings: Finding[];
  affectedServices: ServiceNode[];
  cascadeDepth: number;
  hndlExposure: 'critical' | 'high' | 'medium' | 'low';
  simulatedBusinessImpact: string;
  exposureSummary: string;
  beforeReadiness: number;
  afterReadiness: number;
}

export interface HNDLAssessment {
  dataCategory: string;
  confidentialityLifetime: string;
  currentProtection: string;
  hndlRisk: 'very-high' | 'high' | 'medium' | 'low';
  explanation: string;
  affectedFindings: string[];
}

export interface CryptoAgilityBreakdown {
  algorithmAbstraction: number;
  configurationCentralization: number;
  hardcodedAlgorithms: number;
  migrationFlexibility: number;
  dependencyManagement: number;
}

export interface AgilityEvidenceItem {
  scoreName: string;
  scoreValue: number;
  category: string;
  description: string;
  evidenceSnippet: string;
  filePath: string;
  lineNumber: number;
}

export interface CryptoAgilityScore {
  score: number; // 0-100 (e.g. 67 / 100)
  breakdown: CryptoAgilityBreakdown;
  evidence: AgilityEvidenceItem[];
  positives: string[];
  negatives: string[];
  hardcodedReferences: number;
  centralizedConfig: boolean;
  algorithmAbstraction: boolean;
  directLowLevelCalls: number;
}

export interface ScannedFileDetail {
  path: string;
  lineCount: number;
  sizeBytes: number;
  language: string;
  findingsCount: number;
  criticalCount: number;
  vulnerableCount: number;
}

export interface Assessment {
  id: string;
  name: string;
  organization: string;
  industry: string;
  createdAt: string;
  scannedAt?: string;
  status: 'idle' | 'scanning' | 'complete' | 'error';
  scanProgress: number; // 0-100
  findings: Finding[];
  services: ServiceNode[];
  migrationTasks: MigrationTask[];
  qDaySimulation: QDaySimulation | null;
  hndlAssessments: HNDLAssessment[];
  cryptoAgilityScore: CryptoAgilityScore | null;
  quantumReadinessScore: number;
  chatHistory: ChatMessage[];
  scanStats: ScanStats;
  scannedFiles?: ScannedFileDetail[];
}

export interface ScanStats {
  filesScanned: number;
  linesScanned: number;
  findingsTotal: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  vulnerableAlgorithms: number;
  secretsFound: number;
  affectedServices: number;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  citedFindings?: string[]; // finding IDs
}

export interface RiskWeights {
  algorithmRisk: number;
  businessCriticality: number;
  internetExposure: number;
  dataLifetime: number;
  dataSensitivity: number;
  migrationDifficulty: number;
}

export const DEFAULT_RISK_WEIGHTS: RiskWeights = {
  algorithmRisk: 0.30,
  businessCriticality: 0.20,
  internetExposure: 0.15,
  dataLifetime: 0.15,
  dataSensitivity: 0.10,
  migrationDifficulty: 0.10,
};

export interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  controls: ComplianceControl[];
}

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-assessed';
  relatedFindings: string[];
  notes: string;
}
