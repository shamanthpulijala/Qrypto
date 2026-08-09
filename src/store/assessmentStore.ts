// ============================================================
// QuantumGuard AI — Zustand Assessment Store
// Real scan-only mode — no hardcoded demo data
// ============================================================

import { create } from 'zustand';
import type { Assessment, Finding, ChatMessage, MigrationTask, QDaySimulation, ServiceNode } from '../types';
import { computeQuantumReadinessIndex } from '../engine/riskEngine';
import { computeCryptoAgilityScore } from '../engine/cryptoAgility';
import { generateHNDLAssessments } from '../engine/hndlAnalyzer';
import { generateMigrationRoadmap } from '../engine/migrationPlanner';
import { injectDemoData } from '../api';

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

  return [...serviceMap.values()];
}

interface AppState {
  // Current assessment
  assessment: Assessment | null;
  readinessBreakdown: ReturnType<typeof computeQuantumReadinessIndex> | null;

  // Navigation
  currentPage: string;
  sidebarCollapsed: boolean;

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

  // Actions
  setCurrentPage: (page: string) => void;
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
  startScan: (files: { path: string; content: string }[]) => Promise<void>;
  clearAssessment: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  assessment: null,
  readinessBreakdown: null,
  currentPage: 'landing',
  sidebarCollapsed: false,
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

  setCurrentPage: (page) => set({ currentPage: page }),

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

  updateFindingStatus: (id, status) => set(s => ({
    assessment: s.assessment ? {
      ...s.assessment,
      findings: s.assessment.findings.map(f => f.id === id ? { ...f, remediationStatus: status } : f),
    } : null,
  })),

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
  }),

  startScan: async (files) => {
    try {
      const { runScanPipeline } = await import('../engine/pipeline');
      set({ isScanning: true, scanProgress: 0, scanLog: ['Initializing scanning pipeline...'], scanError: null });

      const pipelineFiles = files.map(f => ({ path: f.path, content: f.content }));
      const result = await runScanPipeline(pipelineFiles, {
        repository: 'uploaded/repo',
        project: 'Uploaded Repository Scan',
        onProgress: (_stage, progress, logMsg) => {
          set(s => ({
            scanProgress: progress,
            scanLog: [...s.scanLog, logMsg],
          }));
        },
      });

      const services = buildServicesFromFindings(result.findings);
      const agility = computeCryptoAgilityScore(result.findings);
      const hndl = generateHNDLAssessments(result.findings);
      const tasks = generateMigrationRoadmap(result.findings, services);

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
        findings: result.findings,
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
          findingsTotal: result.findings.length,
          criticalCount: result.findings.filter(f => f.severity === 'critical').length,
          highCount: result.findings.filter(f => f.severity === 'high').length,
          mediumCount: result.findings.filter(f => f.severity === 'medium').length,
          lowCount: result.findings.filter(f => f.severity === 'low' || f.severity === 'info').length,
          vulnerableAlgorithms: result.findings.filter(f => f.quantumStatus === 'vulnerable').length,
          secretsFound: result.findings.filter(f => f.category === 'secret').length,
          affectedServices: new Set(result.findings.map(f => f.service)).size,
        },
      };

      injectDemoData(
        { id: assessment.id, name: assessment.name, description: 'Uploaded Repo Scan', repository: 'uploaded/repo', language: 'unknown', owner: 'user', createdAt: assessment.createdAt },
        result.findings, services, tasks
      );

      if (result.errors && result.errors.length > 0) {
        set({ isScanning: false, scanProgress: 100, assessment, readinessBreakdown: result.readinessIndex, scanError: `Scan completed with warnings: ${result.errors.join(', ')}` });
      } else {
        set({ isScanning: false, scanProgress: 100, assessment, readinessBreakdown: result.readinessIndex, currentPage: 'dashboard' });
      }
    } catch (err: any) {
      set({ isScanning: false, scanError: err.message || 'An unexpected error occurred during the scan.' });
    }
  },
}));
