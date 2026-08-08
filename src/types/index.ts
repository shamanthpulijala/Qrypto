// ============================================================
// QuantumGuard AI — Core Type Definitions
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
  | 'pqc';

export type QuantumStatus =
  | 'vulnerable'       // RSA, ECC, ECDH, ECDSA, DH, DSA
  | 'classical-weak'   // MD5, SHA-1, DES, 3DES, weak TLS
  | 'adequate'         // AES-256, SHA-256, SHA-3
  | 'quantum-resistant' // ML-KEM, ML-DSA, SLH-DSA
  | 'unknown';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RemediationStatus = 'open' | 'in-progress' | 'remediated' | 'accepted-risk' | 'wont-fix';

export interface RiskBreakdown {
  algorithmRisk: number;        // 0-100
  businessCriticality: number;  // 0-100
  internetExposure: number;     // 0-100
  dataLifetime: number;         // 0-100
  dataSensitivity: number;      // 0-100
  migrationDifficulty: number;  // 0-100
  totalScore: number;           // 0-100 weighted
}

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
  // Classification
  quantumStatus: QuantumStatus;
  severity: Severity;
  // Context
  internetFacing: boolean;
  dataSensitivity: 'critical' | 'high' | 'medium' | 'low';
  dataLifetimeYears: number; // estimated years data must remain confidential
  isCryptoAgile: boolean;
  isHardcoded: boolean;
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
  phase: 1 | 2 | 3 | 4;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  effort: 'days' | 'weeks' | 'months';
  effortValue: number;
  affectedServices: string[];
  affectedFindings: string[];
  reason: string;
  dependencies: string[];
  owner?: string;
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

export interface CryptoAgilityScore {
  score: number; // 0-100
  positives: string[];
  negatives: string[];
  hardcodedReferences: number;
  centralizedConfig: boolean;
  algorithmAbstraction: boolean;
  directLowLevelCalls: number;
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
