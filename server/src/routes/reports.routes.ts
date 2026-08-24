import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateToken } from '../middleware/auth';
import { logAudit } from '../services/audit.service';

const router = Router();
const prisma = new PrismaClient();

// Helper: verify scan ownership
async function getScanOrFail(scanId: string, userId: string, role: string) {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      findings: { orderBy: { riskScore: 'desc' } },
      migrationTasks: { orderBy: { phase: 'asc' } },
    },
  });
  if (!scan) return null;
  if (scan.userId !== userId && role !== 'ADMIN') return null;
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

// GET /api/reports/:scanId/cbom — CycloneDX CBOM JSON (Phase 2 stub — full impl in Phase 2)
router.get('/:scanId/cbom', authenticateToken, async (req, res) => {
  const scanId = req.params.scanId as string;
  const scan = await getScanOrFail(scanId, req.user!.userId, req.user!.role);
  if (!scan) return res.status(404).json({ error: 'Scan not found or access denied' });
  if (scan.status !== 'COMPLETE') return res.status(400).json({ error: 'Scan not yet complete' });

  await logAudit(req.user!.userId, 'report_generated', scanId, { format: 'cbom' });

  // CycloneDX 1.6 CBOM format
  const cbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: 'Qrypto', version: '2.0.0', vendor: 'Qrypto' }],
      component: { type: 'application', name: scan.projectName },
    },
    components: scan.findings.map((f, i) => ({
      type: 'cryptography',
      'bom-ref': `finding-${f.id}`,
      name: f.algorithm,
      version: f.keySize ? `${f.keySize}-bit` : 'unknown',
      cryptoProperties: {
        assetType: f.category === 'secret' ? 'secret-material' : 'algorithm',
        algorithmProperties: {
          primitive: f.category,
          parameterSetIdentifier: f.keySize?.toString(),
        },
        oid: undefined,
      },
      evidence: {
        occurrences: [{
          location: `${f.file}#L${f.line}`,
          line: f.line,
          offset: 0,
          symbol: f.algorithm,
          additionalContext: f.detectedPattern,
        }],
      },
      properties: [
        { name: 'qrypto:quantumStatus', value: f.quantumStatus },
        { name: 'qrypto:severity', value: f.severity },
        { name: 'qrypto:riskScore', value: String(f.riskScore) },
        { name: 'qrypto:remediationStatus', value: f.remediationStatus },
        { name: 'qrypto:recommendedAlgorithm', value: f.recommendedAlgo ?? '' },
      ],
    })),
  };

  res.setHeader('Content-Disposition', `attachment; filename="cbom-${Date.now()}.json"`);
  res.json(cbom);
});

export default router;
