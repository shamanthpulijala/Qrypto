// ============================================================
// QuantumGuard AI — Zustand Assessment Store
// ============================================================

import { create } from 'zustand';
import type { Assessment, Finding, ChatMessage, ServiceNode, MigrationTask, QDaySimulation } from '../types';
import { SAMPLE_FINDINGS, SAMPLE_SERVICES, computeSampleStats } from '../data/sampleRepo';
import { computeQuantumReadinessIndex } from '../engine/riskEngine';
import { computeCryptoAgilityScore } from '../engine/cryptoAgility';
import { generateHNDLAssessments } from '../engine/hndlAnalyzer';
import { generateMigrationRoadmap } from '../engine/migrationPlanner';

const createDemoAssessment = (): Assessment => {
  const findings = SAMPLE_FINDINGS;
  const services = SAMPLE_SERVICES;
  const readiness = computeQuantumReadinessIndex(findings);
  const agilityScore = computeCryptoAgilityScore(findings);
  const hndl = generateHNDLAssessments(findings);
  const tasks = generateMigrationRoadmap(findings, services);

  return {
    id: 'demo-fintech-corp',
    name: 'FinTech Corp Platform Assessment',
    organization: 'FinTech Corp',
    industry: 'Financial Services',
    createdAt: '2026-08-08T04:00:00Z',
    scannedAt: '2026-08-08T04:12:33Z',
    status: 'complete',
    scanProgress: 100,
    findings,
    services,
    migrationTasks: tasks,
    qDaySimulation: null,
    hndlAssessments: hndl,
    cryptoAgilityScore: agilityScore,
    quantumReadinessScore: readiness.overall,
    chatHistory: [],
    scanStats: computeSampleStats(),
  };
};

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

  // Actions
  loadDemoAssessment: () => void;
  setCurrentPage: (page: string) => void;
  toggleSidebar: () => void;
  setGeminiApiKey: (key: string) => void;
  addChatMessage: (message: ChatMessage) => void;
  runQDaySimulation: () => void;
  resetQDaySimulation: () => void;
  setQDayYear: (year: number) => void;
  updateFindingStatus: (id: string, status: Finding['remediationStatus']) => void;
  updateTaskStatus: (id: string, status: MigrationTask['status']) => void;
  setTheme: (theme: 'dark' | 'light') => void;
  setFindings: (findings: Finding[]) => void;
  startScan: (files: { path: string; content: string }[]) => Promise<void>;
}

export const useAppStore = create<AppState>((set, get) => ({
  assessment: null,
  readinessBreakdown: null,
  currentPage: 'landing',
  sidebarCollapsed: false,
  qdayActive: false,
  qdayYear: 2030,
  geminiApiKey: localStorage.getItem('qg_gemini_key') || '',
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

  loadDemoAssessment: () => {
    const assessment = createDemoAssessment();
    const readinessBreakdown = computeQuantumReadinessIndex(assessment.findings);
    set({ assessment, readinessBreakdown, currentPage: 'dashboard' });
  },

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

  runQDaySimulation: () => {
    const { assessment } = get();
    if (!assessment) return;

    const vulnerableFindings = assessment.findings.filter(
      f => f.quantumStatus === 'vulnerable' && f.severity !== 'info'
    );

    const affectedServiceIds = new Set<string>(vulnerableFindings.map(f => f.service));
    // Cascade to dependent services
    assessment.services.forEach(svc => {
      if (svc.dependencies.some(dep => {
        const depSvc = assessment.services.find(s => s.id === dep);
        return depSvc && affectedServiceIds.has(depSvc.name);
      })) {
        affectedServiceIds.add(svc.name);
      }
    });

    const affectedServices = assessment.services.filter(s => affectedServiceIds.has(s.name));

    const simulation: QDaySimulation = {
      active: true,
      vulnerableFindings,
      affectedServices,
      cascadeDepth: 3,
      hndlExposure: 'critical',
      simulatedBusinessImpact: 'Under this scenario, quantum-relevant cryptographic capabilities could expose authentication tokens, payment channel keys, and long-lived financial data protected by RSA/ECC-based infrastructure.',
      exposureSummary: `${vulnerableFindings.length} quantum-vulnerable assets across ${affectedServices.length} services would require immediate remediation.`,
      beforeReadiness: assessment.quantumReadinessScore,
      afterReadiness: Math.max(10, assessment.quantumReadinessScore - 35),
    };

    set(s => ({
      qdayActive: true,
      assessment: s.assessment ? { ...s.assessment, qDaySimulation: simulation } : null,
    }));
  },

  resetQDaySimulation: () => set(s => ({
    qdayActive: false,
    assessment: s.assessment ? { ...s.assessment, qDaySimulation: null } : null,
  })),

  setQDayYear: (year) => set({ qdayYear: year }),

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

  startScan: async (files) => {
    const { scanFiles } = await import('../engine/scanner');
    set({ isScanning: true, scanProgress: 0, scanLog: ['Starting scan...'] });

    const scanFileObjects = files.map(f => ({
      path: f.path,
      content: f.content,
      repository: 'uploaded',
      project: 'Upload',
    }));

    // Simulate progressive scanning
    for (let i = 0; i < files.length; i++) {
      await new Promise(r => setTimeout(r, 50));
      const progress = Math.round(((i + 1) / files.length) * 100);
      set(s => ({
        scanProgress: progress,
        scanLog: [...s.scanLog, `Scanning ${files[i].path}...`],
      }));
    }

    const findings = scanFiles(scanFileObjects);
    const services = SAMPLE_SERVICES; // Use demo services as context
    const readiness = computeQuantumReadinessIndex(findings);
    const agility = computeCryptoAgilityScore(findings);
    const hndl = generateHNDLAssessments(findings);
    const tasks = generateMigrationRoadmap(findings, services);

    const assessment: Assessment = {
      id: `scan-${Date.now()}`,
      name: 'Uploaded Repository Scan',
      organization: 'Your Organization',
      industry: 'Unknown',
      createdAt: new Date().toISOString(),
      scannedAt: new Date().toISOString(),
      status: 'complete',
      scanProgress: 100,
      findings,
      services,
      migrationTasks: tasks,
      qDaySimulation: null,
      hndlAssessments: hndl,
      cryptoAgilityScore: agility,
      quantumReadinessScore: readiness.overall,
      chatHistory: [],
      scanStats: {
        filesScanned: files.length,
        linesScanned: files.reduce((acc, f) => acc + f.content.split('\n').length, 0),
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

    set({ isScanning: false, scanProgress: 100, assessment, readinessBreakdown: readiness });
  },
}));
