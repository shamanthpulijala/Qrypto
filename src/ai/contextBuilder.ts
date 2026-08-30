// ============================================================
// Qrypto AI Advisor — §19 AI Context Builder
//
// Builds structured context object without blindly dumping full DB.
// Extracts key evidence, top assets, inventory summary, risk scores,
// attack graph flows, and migration tasks.
// Filters to service-specific findings when a service is queried.
// ============================================================

import type { Assessment, Finding } from '../types';

export interface StructuredAIContext {
  project: {
    name: string;
    organization: string;
    industry: string;
    readinessScore: number;
    totalFindings: number;
  };
  criticalFindings: Array<{
    id: string;
    algorithm: string;
    category: string;
    service: string;
    file: string;
    line: number;
    severity: string;
    riskScore: number;
    quantumStatus: string;
    classicalStatus: string;
    usage: string;
    codeExcerpt: string;
  }>;
  topAssets: Array<{
    name: string;
    riskScore: number;
    internetFacing: boolean;
  }>;
  inventory: Array<{
    algorithm: string;
    occurrences: number;
    quantumStatus: string;
  }>;
  riskScore: {
    overallReadiness: number;
    criticalCount: number;
    highCount: number;
    vulnerableAlgorithmsCount: number;
    secretsCount: number;
  };
  attackGraph: {
    criticalPath: string[];
    internetFacingServices: string[];
  };
  migrationTasks: Array<{
    id: string;
    title: string;
    priority: string;
    estimatedEffort: string;
  }>;
}

export function buildAIContext(assessment: Assessment, targetService?: string): StructuredAIContext {
  let findings = assessment.findings;

  // §19 Rule: For a question about a specific service, retrieve only relevant findings
  if (targetService) {
    const sLower = targetService.toLowerCase();
    const serviceFindings = findings.filter(f => f.service.toLowerCase().includes(sLower));
    if (serviceFindings.length > 0) {
      findings = serviceFindings;
    }
  }

  // Critical / High findings (sorted by risk)
  const criticalFindings = [...findings]
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 15)
    .map(f => ({
      id: f.id,
      algorithm: f.algorithm,
      category: f.category,
      service: f.service,
      file: f.file,
      line: f.line,
      severity: f.severity,
      riskScore: f.riskScore,
      quantumStatus: f.quantumStatus,
      classicalStatus: f.classicalStatus,
      usage: f.usage,
      codeExcerpt: f.category === 'secret' 
        ? '[REDACTED_SECRET]' 
        : f.evidence?.matchedText?.substring(0, 150) || '[NO_EXCERPT]',
    }));

  // Top services / assets by risk
  const topAssets = assessment.services
    .filter(s => s.id !== 'internet')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 8)
    .map(s => ({
      name: s.name,
      riskScore: s.riskScore,
      internetFacing: s.internetFacing,
    }));

  // Inventory distribution
  const algoCounts: Record<string, { count: number; status: string }> = {};
  assessment.findings.forEach(f => {
    if (!algoCounts[f.algorithm]) {
      algoCounts[f.algorithm] = { count: 0, status: f.quantumStatus };
    }
    algoCounts[f.algorithm].count++;
  });

  const inventory = Object.entries(algoCounts).map(([algorithm, info]) => ({
    algorithm,
    occurrences: info.count,
    quantumStatus: info.status,
  }));

  // Attack graph critical path
  const internetFacingServices = assessment.services
    .filter(s => s.internetFacing && s.id !== 'internet')
    .map(s => s.name);

  const criticalPath = assessment.services
    .filter(s => s.id !== 'internet')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 4)
    .map(s => s.name);

  // Top migration tasks
  const migrationTasks = assessment.migrationTasks
    .slice(0, 6)
    .map(t => ({
      id: t.id,
      title: t.title,
      priority: t.priority,
      estimatedEffort: t.estimatedEffort || `${t.effortValue} ${t.effort}`,
    }));

  return {
    project: {
      name: assessment.name,
      organization: assessment.organization,
      industry: assessment.industry,
      readinessScore: assessment.quantumReadinessScore,
      totalFindings: assessment.findings.length,
    },
    criticalFindings,
    topAssets,
    inventory,
    riskScore: {
      overallReadiness: assessment.quantumReadinessScore,
      criticalCount: assessment.scanStats.criticalCount,
      highCount: assessment.scanStats.highCount,
      vulnerableAlgorithmsCount: assessment.scanStats.vulnerableAlgorithms,
      secretsCount: assessment.scanStats.secretsFound,
    },
    attackGraph: {
      criticalPath,
      internetFacingServices,
    },
    migrationTasks,
  };
}

/** Formats the structured context object into clean string context for LLM prompt */
export function formatAIContextPrompt(context: StructuredAIContext): string {
  return JSON.stringify(context, null, 2);
}
