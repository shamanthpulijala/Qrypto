import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateToken } from '../middleware/auth';
import { logAudit } from '../services/audit.service';

const router = Router();
const prisma = new PrismaClient();

// Helper: safely cast query param to string
const qs = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

// GET /api/findings/scan/:scanId — Paginated, filterable findings list
router.get('/scan/:scanId', authenticateToken, async (req, res) => {
  try {
    const scanId = req.params.scanId as string;
    const severity = qs(req.query.severity);
    const quantumStatus = qs(req.query.quantumStatus);
    const category = qs(req.query.category);
    const remediationStatus = qs(req.query.remediationStatus);
    const page = qs(req.query.page) ?? '1';
    const limit = qs(req.query.limit) ?? '50';

    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.userId !== req.user!.userId && req.user!.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = Math.min(parseInt(limit), 500);

    const where: Record<string, unknown> = { scanId };
    if (severity) where.severity = severity;
    if (quantumStatus) where.quantumStatus = quantumStatus;
    if (category) where.category = category;
    if (remediationStatus) where.remediationStatus = remediationStatus;

    const [findings, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        orderBy: { riskScore: 'desc' },
        skip,
        take,
      }),
      prisma.finding.count({ where }),
    ]);

    res.json({ findings, total, page: parseInt(page), limit: take });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch findings' });
  }
});

// GET /api/findings/:id — Single finding detail
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const finding = await prisma.finding.findUnique({
      where: { id: req.params.id as string },
      include: { statusHistory: { orderBy: { changedAt: 'desc' } } },
    });
    if (!finding) return res.status(404).json({ error: 'Finding not found' });

    const scan = await prisma.scan.findUnique({ where: { id: finding.scanId } });
    if (!scan || (scan.userId !== req.user!.userId && req.user!.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(finding);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch finding' });
  }
});

// PATCH /api/findings/:id/status — Update remediation status
router.patch('/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status, reason } = req.body;
    const VALID_STATUSES = ['open', 'confirmed', 'false-positive', 'accepted-risk', 'under-migration', 'remediated', 'ignored'];

    if (!VALID_STATUSES.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${VALID_STATUSES.join(', ')}` });
    }

    const finding = await prisma.finding.findUnique({ where: { id: req.params.id as string } });
    if (!finding) return res.status(404).json({ error: 'Finding not found' });

    const scan = await prisma.scan.findUnique({ where: { id: finding.scanId } });
    if (!scan || (scan.userId !== req.user!.userId && req.user!.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const oldStatus = finding.remediationStatus;

    const [updated] = await prisma.$transaction([
      prisma.finding.update({
        where: { id: req.params.id as string },
        data: { remediationStatus: status },
      }),
      prisma.findingStatusChange.create({
        data: {
          findingId: req.params.id as string,
          oldStatus,
          newStatus: status,
          changedBy: req.user!.userId,
          reason: reason ?? null,
        },
      }),
    ]);

    await logAudit(req.user!.userId, 'finding_status_changed', req.params.id as string, { oldStatus, newStatus: status, reason });

    res.json({ id: updated.id, remediationStatus: updated.remediationStatus });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update finding status' });
  }
});

export default router;
