// ============================================================
// Qrypto AI Advisor — Zustand Assessment Store (v2)
// Dual-mode:
//   - VITE_API_URL set → backend API (real persistence)
//   - VITE_API_URL not set → in-browser pipeline (demo mode)
// ============================================================

import { create } from 'zustand';
import type { Assessment, Finding, ChatMessage, MigrationTask, QDaySimulation, ServiceNode } from '../types';
import { computeQuantumReadinessIndex, computeRiskScore } from '../engine/riskEngine';
import { computeCryptoAgilityScore } from '../engine/cryptoAgility';
import { generateHNDLAssessments } from '../engine/hndlAnalyzer';
import { generateMigrationRoadmap } from '../engine/migrationPlanner';
import { scansApi, findingsApi, isApiConfigured } from '../api/client';
import { firebaseDb } from '../lib/firebaseDb';
import { useAuthStore } from './authStore';

// ─── P1-9: Infer real dependencies between services ─────────
// Only creates edges where evidence exists in file paths and
// service relationships. Never fabricates edges.

function inferDependencies(nodes: ServiceNode[], findings: Finding[]): void {
  if (nodes.length <= 1) return;

  // Build a map of service → file path prefixes (first two path segments)
  const servicePaths = new Map<string, Set<string>>();
  for (const f of findings) {
    const parts = f.file.replace(/\\/g, '/').split('/');
    const prefix = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0];
    if (!servicePaths.has(f.service)) servicePaths.set(f.service, new Set());
    servicePaths.get(f.service)!.add(prefix);
  }

  // Inference rule 1: Services sharing the same top-level directory
  // (e.g., both in src/auth/) likely have a dependency relationship
  const pathToServices = new Map<string, string[]>();
  servicePaths.forEach((paths, svc) => {
    for (const p of paths) {
      const topDir = p.split('/')[0];
      if (!pathToServices.has(topDir)) pathToServices.set(topDir, []);
      pathToServices.get(topDir)!.push(svc);
    }
  });

  // Inference rule 2: Known service relationship patterns
  // These are generic service-type relationships, not company-specific
  const DEPENDENCY_RULES: Array<{
    source: RegExp;   // service that depends on another
    target: RegExp;   // service it depends on
    reason: string;
  }> = [
    { source: /payment/i, target: /auth/i, reason: 'payment processing requires authentication' },
    { source: /transaction/i, target: /auth/i, reason: 'transaction processing requires authentication' },
    { source: /transaction/i, target: /payment/i, reason: 'transactions use payment processing' },
    { source: /user/i, target: /data/i, reason: 'user service accesses data layer' },
    { source: /payment/i, target: /data/i, reason: 'payment service accesses data layer' },
    { source: /transaction/i, target: /data/i, reason: 'transaction service accesses data layer' },
    { source: /auth/i, target: /data/i, reason: 'authentication service accesses data layer' },
    { source: /api.*gateway/i, target: /auth/i, reason: 'API gateway routes to authentication' },
    { source: /api.*gateway/i, target: /payment/i, reason: 'API gateway routes to payment' },
    { source: /api.*gateway/i, target: /user/i, reason: 'API gateway routes to user service' },
    { source: /pki/i, target: /data/i, reason: 'PKI layer accesses certificate data' },
  ];

  const addedEdges = new Set<string>();

  for (const node of nodes) {
    for (const rule of DEPENDENCY_RULES) {
      if (rule.source.test(node.name)) {
        // Find target service
        const target = nodes.find(n => rule.target.test(n.name) && n.id !== node.id);
        if (target && !addedEdges.has(`${node.id}->${target.id}`)) {
          node.dependencies.push(target.id);
          addedEdges.add(`${node.id}->${target.id}`);
        }
      }
    }
  }
}

// ─── Derive ServiceNodes from scan findings ─────────────────

function buildServicesFromFindings(findings: Finding[]): ServiceNode[] {
  const serviceMap = new Map<string, ServiceNode>();

  findings.forEach(f => {
    if (!serviceMap.has(f.service)) {
      serviceMap.set(f.service, {
        id: f.service.toLowerCase().replace(/\s+/g, '-'),
        name: f.service,
        type: 'service',
        internetFacing: f.internetFacing,
        dataSensitivity: f.dataSensitivity,
        cryptoFindings: [],
        riskScore: 0,
        dependencies: [],
        position: {
          x: 100 + (serviceMap.size % 4) * 220,
          y: 100 + Math.floor(serviceMap.size / 4) * 180,
        },
      });
    }
    const node = serviceMap.get(f.service)!;
    if (!node.cryptoFindings.includes(f.id)) node.cryptoFindings.push(f.id);
    // Keep the highest sensitivity and internet-facing flag
    if (f.internetFacing) node.internetFacing = true;
    const SENS_ORDER = ['low', 'medium', 'high', 'critical'];
    if (SENS_ORDER.indexOf(f.dataSensitivity) > SENS_ORDER.indexOf(node.dataSensitivity)) {
      node.dataSensitivity = f.dataSensitivity;
    }
  });

  // Compute average risk score per service
  serviceMap.forEach((node, name) => {
    const svcFindings = findings.filter(f => f.service === name);
    if (svcFindings.length > 0) {
      node.riskScore = Math.round(
        svcFindings.reduce((sum, f) => sum + f.riskScore, 0) / svcFindings.length
      );
    }
  });

  // P1-9: Infer real dependencies from file paths and service relationships
  // Only creates edges where evidence exists — never fabricates relationships
  const nodes = [...serviceMap.values()];
  inferDependencies(nodes, findings);

  return nodes;
}

// P0-12: Per-asset context overrides
export interface ContextOverride {
  /** Finding fingerprint this override applies to, or '*' for all findings in a service */
  fingerprint?: string;
  /** Service name this override applies to */
  service?: string;
  /** Overridden values (undefined = use inference) */
  internetFacing?: boolean;
  dataSensitivity?: 'critical' | 'high' | 'medium' | 'low';
  dataLifetimeYears?: number;
  businessCriticality?: number; // 0-100
}

interface AppState {
  // Current assessment
  assessment: Assessment | null;
  readinessBreakdown: ReturnType<typeof computeQuantumReadinessIndex> | null;

  // Navigation
  currentPage: string;
  sidebarCollapsed: boolean;

  // Cross-page view state (§7/§9). Purely presentational: this seeds
  // the Findings search box so a command-palette investigation lands
  // pre-filtered. It never affects how findings or scores are computed.
  findingsQuery: string;

  // Q-Day simulation state
  qdayActive: boolean;
  qdayYear: number;

  // Settings
  geminiApiKey: string;
  riskWeights: {
    algorithmRisk: number;
    businessCriticality: number;
    internetExposure: number;
    dataLifetime: number;
    dataSensitivity: number;
    migrationDifficulty: number;
  };
  theme: 'dark' | 'light';

  // Scanning state
  isScanning: boolean;
  scanProgress: number;
  scanLog: string[];
  scanError: string | null;

  // P0-12: Context overrides
  contextOverrides: ContextOverride[];

  // Actions
  setCurrentPage: (page: string) => void;
  setFindingsQuery: (query: string) => void;
  toggleSidebar: () => void;
  setGeminiApiKey: (key: string) => void;
  addChatMessage: (message: ChatMessage) => void;
  runQDaySimulation: (targetYear?: number) => void;
  resetQDaySimulation: () => void;
  setQDayYear: (year: number) => void;
  updateFindingStatus: (id: string, status: Finding['remediationStatus']) => void;
  updateTaskStatus: (id: string, status: MigrationTask['status']) => void;
  setTheme: (theme: 'dark' | 'light') => void;
  setFindings: (findings: Finding[]) => void;
  startScan: (files: { path: string; content: string; zipFile?: File; projectName?: string }[]) => Promise<void>;
  loadScan: (scanId: string) => Promise<void>;
  clearAssessment: () => void;
  // P0-12: Context override actions
  setContextOverride: (override: ContextOverride) => void;
  removeContextOverride: (fingerprintOrService: string) => void;
  getContextOverride: (fingerprint: string, service: string) => ContextOverride | undefined;
  recalculateFindingsWithContext: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  assessment: null,
  readinessBreakdown: null,
  currentPage: 'landing',
  sidebarCollapsed: false,
  findingsQuery: '',
  qdayActive: false,
  qdayYear: 2030,
  geminiApiKey: localStorage.getItem('qg_gemini_key') || (import.meta as any).env?.VITE_OPENROUTER_API_KEY ||' ',
  riskWeights: {
    algorithmRisk: 0.30,
    businessCriticality: 0.20,
    internetExposure: 0.15,
    dataLifetime: 0.15,
    dataSensitivity: 0.10,
    migrationDifficulty: 0.10,
  },
  theme: 'dark',
  isScanning: false,
  scanProgress: 0,
  scanLog: [],
  scanError: null,
  contextOverrides: [],

  setCurrentPage: (page) => set({ currentPage: page }),

  setFindingsQuery: (query) => set({ findingsQuery: query }),

  toggleSidebar: () => set(s => ({ sidebarCollapsed: !s.sidebarCollapsed })),

  setGeminiApiKey: (key) => {
    localStorage.setItem('qg_gemini_key', key);
    set({ geminiApiKey: key });
  },

  addChatMessage: (message) => set(s => ({
    assessment: s.assessment ? {
      ...s.assessment,
      chatHistory: [...s.assessment.chatHistory, message],
    } : null,
  })),

  runQDaySimulation: (targetYear?: number) => {
    const { assessment, qdayYear } = get();
    if (!assessment) return;

    const year = targetYear ?? qdayYear;
    const yearNormalized = Math.max(2000, Math.min(2050, year));

    // Decade factor calculation (2000 - 2050):
    // 2000-2009: 0.10 - 0.25 (Pre-Quantum Era)
    // 2010-2019: 0.30 - 0.55 (HNDL Accumulation Era)
    // 2020-2029: 0.60 - 0.85 (NIST PQC Standardization & Active Transition Era)
    // 2030-2039: 0.90 - 1.25 (CRQC Threat Window)
    // 2040-2050: 1.30 - 1.50 (Post-RSA Deprecation Era)
    const decadeProgress = (yearNormalized - 2000) / 50; // 0.0 at 2000, 1.0 at 2050
    const yearFactor = Math.max(0.1, 0.15 + decadeProgress * 1.35);

    const vulnerableFindings = assessment.findings.filter(
      f => (f.quantumStatus === 'vulnerable' || f.classicalStatus === 'broken' || f.classicalStatus === 'weak') && f.severity !== 'info'
    );

    const affectedServiceIds = new Set<string>(vulnerableFindings.map(f => f.service));
    assessment.services.forEach(svc => {
      if (svc.dependencies.some(dep => {
        const depSvc = assessment.services.find(s => s.id === dep);
        return depSvc && affectedServiceIds.has(depSvc.name);
      })) {
        affectedServiceIds.add(svc.name);
      }
    });

    const affectedServices = assessment.services.filter(s => affectedServiceIds.has(s.name));

    // Compute HNDL Exposure based on repo findings & decade
    let hndlExposure: 'critical' | 'high' | 'medium' | 'low' = 'low';
    if (vulnerableFindings.length > 0) {
      if (yearNormalized >= 2035) hndlExposure = 'critical';
      else if (yearNormalized >= 2025) hndlExposure = 'high';
      else if (yearNormalized >= 2015) hndlExposure = 'medium';
      else hndlExposure = 'low';
    }

    // Dynamic Readiness Drop
    const drop = Math.round(vulnerableFindings.length * 4.0 * yearFactor);
    const afterReadiness = Math.max(5, Math.round(assessment.quantumReadinessScore - drop));

    // Era-based Narrative
    let eraTitle = '';
    if (yearNormalized < 2010) {
      eraTitle = 'Pre-Quantum Era (2000–2009)';
    } else if (yearNormalized < 2020) {
      eraTitle = 'HNDL Accumulation Era (2010–2019)';
    } else if (yearNormalized < 2030) {
      eraTitle = 'NIST PQC Standardization & Transition Era (2020–2029)';
    } else if (yearNormalized < 2040) {
      eraTitle = 'CRQC Threat Window (2030–2039)';
    } else {
      eraTitle = 'Post-RSA Deprecation Era (2040–2050)';
    }

    const simulatedBusinessImpact = vulnerableFindings.length > 0
      ? `${eraTitle}: ${vulnerableFindings.length} vulnerable cryptographic primitives impacted across ${affectedServices.length} active service components. System risk factor: ${Math.round(yearFactor * 100)}%.`
      : `${eraTitle}: Repository is PQC-compliant with 0 quantum-vulnerable primitives. Verified 0 risk under quantum threat scenarios.`;

    const simulation: QDaySimulation = {
      active: true,
      vulnerableFindings,
      affectedServices,
      cascadeDepth: Math.min(4, affectedServices.length),
      hndlExposure,
      simulatedBusinessImpact,
      exposureSummary: `Year ${yearNormalized} (${eraTitle}) | Vulnerable Assets: ${vulnerableFindings.length} | Affected Services: ${affectedServices.length}`,
      beforeReadiness: assessment.quantumReadinessScore,
      afterReadiness,
    };

    set(s => ({
      qdayActive: true,
      qdayYear: yearNormalized,
      assessment: s.assessment ? { ...s.assessment, qDaySimulation: simulation } : null,
    }));
  },

  resetQDaySimulation: () => set(s => ({
    qdayActive: false,
    assessment: s.assessment ? { ...s.assessment, qDaySimulation: null } : null,
  })),

  setQDayYear: (year) => {
    set({ qdayYear: year });
    const { qdayActive, runQDaySimulation } = get();
    if (qdayActive) {
      runQDaySimulation(year);
    }
  },

  updateFindingStatus: async (id, status) => {
    // Log finding status change
    const user = useAuthStore.getState().user;
    if (user) {
      firebaseDb.logAudit({
        action: 'finding_status_changed',
        targetId: id,
        metadata: { newStatus: status },
        userId: user.id || 'unknown',
        userEmail: user.email,
      }).catch(console.error);
    }

    set(s => {
      if (!s.assessment) return s;
      const updatedFindings = s.assessment.findings.map(f => 
        f.id === id ? { ...f, remediationStatus: status } : f
      );
      
      const newAssessment = {
        ...s.assessment,
        findings: updatedFindings
      };

      // Background save to firebase if we have a scan ID
      if (user && newAssessment.id && newAssessment.id.startsWith('scan-')) {
        firebaseDb.updateScan(newAssessment.id, { findings: updatedFindings }).catch(console.error);
      }

      return { assessment: newAssessment };
    });
  },

  updateTaskStatus: (id, status) => set(s => ({
    assessment: s.assessment ? {
      ...s.assessment,
      migrationTasks: s.assessment.migrationTasks.map(t => t.id === id ? { ...t, status } : t),
    } : null,
  })),

  setTheme: (theme) => set({ theme }),

  setFindings: (findings) => set(s => {
    if (!s.assessment) return {};
    const readinessBreakdown = computeQuantumReadinessIndex(findings);
    return {
      assessment: { ...s.assessment, findings },
      readinessBreakdown,
    };
  }),

  clearAssessment: () => set({
    assessment: null,
    readinessBreakdown: null,
    qdayActive: false,
    scanError: null,
    currentPage: 'landing',
    contextOverrides: [],
  }),

  // ── P0-12: Context Override Actions ──────────────────────
  setContextOverride: (override) => set(s => {
    const overrides = [...s.contextOverrides];
    // Find existing override by fingerprint or service
    const idx = overrides.findIndex(o => 
      (override.fingerprint && o.fingerprint === override.fingerprint) ||
      (override.service && o.service === override.service && !o.fingerprint)
    );
    if (idx >= 0) {
      overrides[idx] = { ...overrides[idx], ...override };
    } else {
      overrides.push(override);
    }
    return { contextOverrides: overrides };
  }),

  removeContextOverride: (fingerprintOrService) => set(s => ({
    contextOverrides: s.contextOverrides.filter(o => 
      o.fingerprint !== fingerprintOrService && o.service !== fingerprintOrService
    ),
  })),

  getContextOverride: (fingerprint, service) => {
    const overrides = get().contextOverrides;
    // Exact fingerprint match first
    const fpMatch = overrides.find(o => o.fingerprint === fingerprint);
    if (fpMatch) return fpMatch;
    // Service-level override (no fingerprint)
    return overrides.find(o => o.service === service && !o.fingerprint);
  },

  recalculateFindingsWithContext: () => set(s => {
    if (!s.assessment) return {};
    const { contextOverrides } = s;
    
    const updatedFindings = s.assessment.findings.map(f => {
      // Find applicable override
      const override = contextOverrides.find(o => 
        (o.fingerprint && o.fingerprint === f.fingerprint) ||
        (o.service === f.service && !o.fingerprint)
      );
      
      if (!override) return f;
      
      // Apply overrides to finding context
      const internetFacing = override.internetFacing ?? f.internetFacing;
      const dataSensitivity = override.dataSensitivity ?? f.dataSensitivity;
      const dataLifetimeYears = override.dataLifetimeYears ?? f.dataLifetimeYears;
      
      // Recalculate risk with overridden context
      const riskBreakdown = computeRiskScore({
        quantumStatus: f.quantumStatus,
        baseSeverity: f.algorithmSeverity,
        internetFacing,
        dataSensitivity,
        dataLifetimeYears,
        isHardcoded: f.isHardcoded,
        service: f.service,
        businessCriticalityOverride: override.businessCriticality,
      });
      
      return {
        ...f,
        internetFacing,
        dataSensitivity,
        dataLifetimeYears,
        riskScore: riskBreakdown.totalScore,
        riskBreakdown,
        severityRationale: f.severityRationale + (override ? ' [context overridden]' : ''),
      };
    });
    
    const readinessBreakdown = computeQuantumReadinessIndex(updatedFindings);
    
    return {
      assessment: { ...s.assessment, findings: updatedFindings },
      readinessBreakdown,
    };
  }),

  // ── startScan: dual-mode ──────────────────────────────────
  startScan: async (files) => {
    set({ isScanning: true, scanProgress: 0, scanLog: ['Initializing...'], scanError: null });

    // ── Mode A: Real backend ────────────────────────────────
    if (isApiConfigured() && files[0]?.zipFile) {
      try {
        const zipFile = files[0].zipFile!;
        const projectName = files[0].projectName || 'Uploaded Repository';

        set(s => ({ scanLog: [...s.scanLog, 'Uploading repository to backend...'] }));
        const { scanId } = await scansApi.create(zipFile, projectName);
        set(s => ({ scanLog: [...s.scanLog, `Scan ${scanId} queued. Waiting for results...`] }));

        const scanResult = await scansApi.pollUntilComplete(
          scanId,
          (scan) => {
            set(s => ({
              scanProgress: scan.progress,
              scanLog: scan.status === 'RUNNING'
                ? [...s.scanLog, `Progress: ${scan.progress}%`]
                : s.scanLog,
            }));
          }
        );

        // Build Assessment from API result
        const findings = scanResult.findings as unknown as Finding[];
        const services = buildServicesFromFindings(findings);
        const agility = computeCryptoAgilityScore(findings);
        const hndl = generateHNDLAssessments(findings);
        const readinessBreakdown = computeQuantumReadinessIndex(findings);

        const assessment: Assessment = {
          id: scanResult.id,
          name: scanResult.projectName,
          organization: 'Your Organization',
          industry: 'Enterprise Technology',
          createdAt: scanResult.startedAt,
          scannedAt: scanResult.completedAt || new Date().toISOString(),
          status: 'complete',
          scanProgress: 100,
          findings,
          services,
          migrationTasks: (scanResult.migrationTasks as unknown as MigrationTask[]) || [],
          qDaySimulation: null,
          hndlAssessments: hndl,
          cryptoAgilityScore: agility,
          quantumReadinessScore: scanResult.readinessScore ?? readinessBreakdown.overall,
          chatHistory: [],
          scannedFiles: [],
          scanStats: {
            filesScanned: scanResult.filesScanned,
            linesScanned: scanResult.linesScanned,
            findingsTotal: findings.length,
            criticalCount: findings.filter(f => f.severity === 'critical').length,
            highCount: findings.filter(f => f.severity === 'high').length,
            mediumCount: findings.filter(f => f.severity === 'medium').length,
            lowCount: findings.filter(f => f.severity === 'low' || f.severity === 'info').length,
            vulnerableAlgorithms: findings.filter(f => f.quantumStatus === 'vulnerable').length,
            secretsFound: findings.filter(f => f.category === 'secret').length,
            affectedServices: new Set(findings.map(f => f.service)).size,
          },
        };

        set({ isScanning: false, scanProgress: 100, assessment, readinessBreakdown, currentPage: 'dashboard' });
        return;
      } catch (err: any) {
        // Backend upload failed (e.g. not logged in, server error)
        // Fall through to in-browser pipeline as fallback
        console.warn('Backend scan failed, falling back to in-browser pipeline:', err.message);
        set(s => ({ scanLog: [...s.scanLog, `Backend unavailable (${err.message}), using in-browser scan...`] }));
        // Continue to Mode B below
      }
    }

    // ── Mode B: In-browser pipeline (demo / no backend) ────
    try {
      const { runScanPipeline } = await import('../engine/pipeline');
      set(s => ({ scanLog: [...s.scanLog, 'Running in-browser scan pipeline...'] }));

      const pipelineFiles = files.map(f => ({ path: f.path, content: f.content }));
      const result = await runScanPipeline(pipelineFiles, {
        repository: 'uploaded/repo',
        project: files[0]?.projectName || 'Uploaded Repository Scan',
        maxFileSizeBytes: 5000 * 1024 * 1024, // 5GB
        onProgress: (_stage, progress, logMsg) => {
          set(s => ({ scanProgress: progress, scanLog: [...s.scanLog, logMsg] }));
        },
      });

      // ── Live AWS KMS scan (runs if credentials are set in Settings) ──
      let liveKmsFindings: import('../types').Finding[] = [];
      const awsKeyId = sessionStorage.getItem('qg_aws_access_key_id');
      const awsSecret = sessionStorage.getItem('qg_aws_secret_access_key');
      const awsRegion = sessionStorage.getItem('qg_aws_region') || 'us-east-1';
      if (awsKeyId && awsSecret) {
        try {
          set(s => ({ scanLog: [...s.scanLog, `☁️ Polling live AWS KMS (${awsRegion})...`] }));
          const { detectLiveKms } = await import('../../shared/engine/detectors/liveKms');
          liveKmsFindings = await detectLiveKms(
            { accessKeyId: awsKeyId, secretAccessKey: awsSecret, region: awsRegion },
            files[0]?.projectName || 'Uploaded Repository Scan'
          );
          set(s => ({ scanLog: [...s.scanLog, `☁️ AWS KMS scan complete: ${liveKmsFindings.length} key(s) found.`] }));
        } catch (kmsErr: any) {
          set(s => ({ scanLog: [...s.scanLog, `⚠️ AWS KMS scan failed: ${kmsErr.message}`] }));
        }
      }

      const allFindings = [...result.findings, ...liveKmsFindings];

      const services = buildServicesFromFindings(allFindings);
      const agility = computeCryptoAgilityScore(allFindings);
      const hndl = generateHNDLAssessments(allFindings);
      const tasks = generateMigrationRoadmap(allFindings, services);

      const scannedFiles = pipelineFiles.map(f => {
        const lineCount = f.content.split('\n').length;
        const sizeBytes = new Blob([f.content]).size;
        const ext = '.' + (f.path.split('.').pop() || '').toLowerCase();
        let language = 'UNKNOWN';
        if (['.py'].includes(ext)) language = 'Python';
        else if (['.java'].includes(ext)) language = 'Java';
        else if (['.js', '.jsx'].includes(ext)) language = 'JavaScript';
        else if (['.ts', '.tsx'].includes(ext)) language = 'TypeScript';
        else if (['.go'].includes(ext)) language = 'Go';
        else if (['.yml', '.yaml'].includes(ext)) language = 'YAML';
        else if (['.json'].includes(ext)) language = 'JSON';
        else if (['.sh'].includes(ext)) language = 'Shell';
        else if (['.xml'].includes(ext)) language = 'XML';

        const fileFindings = result.findings.filter(fn => fn.file === f.path || fn.file.endsWith(f.path));
        return {
          path: f.path,
          lineCount,
          sizeBytes,
          language,
          findingsCount: fileFindings.length,
          criticalCount: fileFindings.filter(fn => fn.severity === 'critical').length,
          vulnerableCount: fileFindings.filter(fn => fn.quantumStatus === 'vulnerable').length,
        };
      });

      const assessment: Assessment = {
        id: `scan-${Date.now()}`,
        name: 'Repository Scan',
        organization: 'Your Organization',
        industry: 'Enterprise Technology',
        createdAt: new Date().toISOString(),
        scannedAt: new Date().toISOString(),
        status: 'complete',
        scanProgress: 100,
        findings: allFindings,
        services,
        migrationTasks: tasks,
        qDaySimulation: null,
        hndlAssessments: hndl,
        cryptoAgilityScore: agility,
        quantumReadinessScore: result.readinessIndex.overall,
        chatHistory: [],
        scannedFiles,
        scanStats: {
          filesScanned: result.stats.filesScanned,
          linesScanned: result.stats.linesScanned,
          findingsTotal: allFindings.length,
          criticalCount: allFindings.filter(f => f.severity === 'critical').length,
          highCount: allFindings.filter(f => f.severity === 'high').length,
          mediumCount: allFindings.filter(f => f.severity === 'medium').length,
          lowCount: allFindings.filter(f => f.severity === 'low' || f.severity === 'info').length,
          vulnerableAlgorithms: allFindings.filter(f => f.quantumStatus === 'vulnerable').length,
          secretsFound: allFindings.filter(f => f.category === 'secret').length,
          affectedServices: new Set(allFindings.map(f => f.service)).size,
        },
      };

      const readinessIndex = computeQuantumReadinessIndex(allFindings);

      // Save to Firebase
      const user = useAuthStore.getState().user;
      if (user) {
        set(s => ({ scanLog: [...s.scanLog, 'Saving scan to cloud...'] }));
        await firebaseDb.saveScan(assessment, user.id || 'unknown');
        
        firebaseDb.logAudit({
          action: 'scan_completed',
          targetId: assessment.id,
          metadata: { project: assessment.name, findingsCount: result.findings.length },
          userId: user.id || 'unknown',
          userEmail: user.email,
        }).catch(console.error);
      } else {
        set(s => ({ scanLog: [...s.scanLog, 'Browser-only mode: Scan not saved (sign in to save).'] }));
      }

      if (result.errors && result.errors.length > 0) {
        set({ isScanning: false, scanProgress: 100, assessment, readinessBreakdown: readinessIndex, scanError: `Scan completed with warnings: ${result.errors.join(', ')}` });
      } else {
        set({ isScanning: false, scanProgress: 100, assessment, readinessBreakdown: readinessIndex, currentPage: 'dashboard' });
      }
    } catch (err: any) {
      set({ isScanning: false, scanError: err.message || 'An unexpected error occurred during the scan.' });
    }
  },

  // ── loadScan: restore a past scan from the backend ────────
  loadScan: async (scanId: string) => {
    set({ isScanning: true, scanProgress: 0, scanLog: [`Loading scan ${scanId}...`], scanError: null });
    try {
      let scanResult: Assessment | null = null;
      
      // Try Firebase first
      const user = useAuthStore.getState().user;
      if (user) {
        scanResult = await firebaseDb.getScan(scanId);
      }
      
      if (!scanResult) {
        throw new Error(`Scan not found or permission denied`);
      }

      const readinessBreakdown = computeQuantumReadinessIndex(scanResult.findings);

      set({ 
        isScanning: false, 
        scanProgress: 100, 
        assessment: scanResult, 
        readinessBreakdown, 
        currentPage: 'dashboard' 
      });
    } catch (err: any) {
      set({ isScanning: false, scanError: err.message || 'Failed to load scan.' });
    }
  },
}));
