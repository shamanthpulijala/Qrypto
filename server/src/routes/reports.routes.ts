import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateToken, canAccessResource, type Role } from '../middleware/auth';
import { logAudit } from '../services/audit.service';

const router = Router();
const prisma = new PrismaClient();

// Helper: verify scan ownership
async function getScanOrFail(scanId: string, userId: string, role: Role) {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      findings: { orderBy: { riskScore: 'desc' } },
      migrationTasks: { orderBy: { phase: 'asc' } },
    },
  });
  if (!scan) return null;
  if (!canAccessResource({ userId, role }, scan.userId).allowed) return null;
  return scan;
}

// GET /api/reports/:scanId/json — Full JSON report
router.get('/:scanId/json', authenticateToken, async (req, res) => {
  const scanId = req.params.scanId as string;
  const scan = await getScanOrFail(scanId, req.user!.userId, req.user!.role);
  if (!scan) return res.status(404).json({ error: 'Scan not found or access denied' });
  if (scan.status !== 'COMPLETE') return res.status(400).json({ error: 'Scan not yet complete' });

  await logAudit(req.user!.userId, 'report_generated', scanId, { format: 'json' });

  res.setHeader('Content-Disposition', `attachment; filename="qrypto-report-${scan.projectName.replace(/\s+/g, '-')}-${Date.now()}.json"`);
  res.json({
    generatedAt: new Date().toISOString(),
    generatedBy: 'Qrypto v2.0',
    project: scan.projectName,
    scanId: scan.id,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    quantumReadinessScore: scan.readinessScore,
    scanStats: {
      filesScanned: scan.filesScanned,
      linesScanned: scan.linesScanned,
      totalFindings: scan.findings.length,
      criticalCount: scan.findings.filter(f => f.severity === 'critical').length,
      highCount: scan.findings.filter(f => f.severity === 'high').length,
    },
    findings: scan.findings.map(f => ({
      id: f.id,
      file: f.file,
      line: f.line,
      algorithm: f.algorithm,
      keySize: f.keySize,
      category: f.category,
      usage: f.usage,
      detectedPattern: f.detectedPattern,
      confidence: f.confidence,
      quantumStatus: f.quantumStatus,
      classicalStatus: f.classicalStatus,
      severity: f.severity,
      riskScore: f.riskScore,
      service: f.service,
      language: f.language,
      remediationStatus: f.remediationStatus,
      recommendedAlgo: f.recommendedAlgo,
      migrationStrategy: f.migrationStrategy,
    })),
    migrationTasks: scan.migrationTasks,
  });
});

// GET /api/reports/:scanId/csv — CSV export
router.get('/:scanId/csv', authenticateToken, async (req, res) => {
  const scanId = req.params.scanId as string;
  const scan = await getScanOrFail(scanId, req.user!.userId, req.user!.role);
  if (!scan) return res.status(404).json({ error: 'Scan not found or access denied' });
  if (scan.status !== 'COMPLETE') return res.status(400).json({ error: 'Scan not yet complete' });

  await logAudit(req.user!.userId, 'report_generated', scanId, { format: 'csv' });

  const header = 'ID,File,Line,Algorithm,KeySize,Category,Severity,QuantumStatus,RiskScore,Service,Language,RemediationStatus,RecommendedAlgorithm';
  const rows = scan.findings.map(f =>
    [
      f.id, `"${f.file}"`, f.line, f.algorithm, f.keySize ?? '',
      f.category, f.severity, f.quantumStatus, f.riskScore,
      `"${f.service}"`, f.language, f.remediationStatus, f.recommendedAlgo ?? '',
    ].join(',')
  );

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="qrypto-findings-${Date.now()}.csv"`);
  res.send([header, ...rows].join('\n'));
});

// GET /api/reports/:scanId/cbom — CycloneDX 1.6 CBOM (conformant)
router.get('/:scanId/cbom', authenticateToken, async (req, res) => {
  const scanId = req.params.scanId as string;
  const scan = await getScanOrFail(scanId, req.user!.userId, req.user!.role);
  if (!scan) return res.status(404).json({ error: 'Scan not found or access denied' });
  if (scan.status !== 'COMPLETE') return res.status(400).json({ error: 'Scan not yet complete' });

  await logAudit(req.user!.userId, 'report_generated', scanId, { format: 'cbom' });

  // Use the shared CBOM generator (single source of truth)
  // Import dynamically to avoid issues with CommonJS/ESM interop
  const { generateCBOM, serializeCBOM } = require('../../../shared/engine/cbom');
  const findings = scan.findings.map((f: any) => ({
    id: f.id,
    file: f.file,
    line: f.line,
    repository: '',
    project: scan.projectName,
    service: f.service,
    language: f.language,
    algorithm: f.algorithm,
    keySize: f.keySize,
    category: f.category,
    usage: f.usage,
    detectedPattern: f.detectedPattern,
    confidence: f.confidence,
    quantumStatus: f.quantumStatus,
    classicalStatus: f.classicalStatus,
    severity: f.severity,
    algorithmSeverity: f.severity,
    severityRationale: '',
    internetFacing: false,
    dataSensitivity: 'medium',
    dataLifetimeYears: 5,
    isCryptoAgile: false,
    isHardcoded: false,
    riskScore: f.riskScore,
    riskBreakdown: { algorithmRisk: 0, businessCriticality: 0, internetExposure: 0, dataLifetime: 0, dataSensitivity: 0, migrationDifficulty: 0, totalScore: 0 },
    remediationStatus: f.remediationStatus,
    migrationPriority: 0,
    recommendedAlgorithm: f.recommendedAlgo,
    migrationStrategy: f.migrationStrategy,
    tags: [],
    detectedAt: new Date().toISOString(),
  }));

  const bom = generateCBOM(findings, { projectName: scan.projectName });
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="cbom-${scan.projectName.replace(/\s+/g, '-')}-${Date.now()}.json"`);
  res.send(serializeCBOM(bom));
});

export default router;
