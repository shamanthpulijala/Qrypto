import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { authenticateToken } from '../middleware/auth';
import { rateLimit } from '../middleware/rateLimit';
import { upload } from '../services/upload.service';
import { scanQueue } from '../workers/scan.worker';

const router = Router();
const prisma = new PrismaClient();

const EXTRACT_BASE = path.join(__dirname, '../../tmp');

// POST /api/scans — Create a new scan from a zip upload
router.post(
  '/',
  authenticateToken,
  rateLimit(10, 60 * 60 * 1000), // 10 scans/hour per IP
  upload.single('repository'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded. Send a .zip file in the "repository" field.' });
      }

      const projectName = (req.body.projectName as string) || 'Unnamed Project';
      const scanId = uuidv4();
      const extractDir = path.join(EXTRACT_BASE, scanId);

      // Create DB record in QUEUED state
      await prisma.scan.create({
        data: {
          id: scanId,
          userId: req.user!.userId,
          projectName,
          status: 'QUEUED',
          progress: 0,
        },
      });

      // Enqueue the job
      await scanQueue.add('scan', {
        scanId,
        zipPath: req.file.path,
        extractDir,
        projectName,
        userId: req.user!.userId,
      });

      res.status(202).json({
        scanId,
        status: 'queued',
        message: 'Scan queued. Poll GET /api/scans/:id for progress.',
      });
    } catch (error: any) {
      console.error('POST /api/scans error:', error);
      res.status(500).json({ error: 'Failed to create scan' });
    }
  }
);

// GET /api/scans — List scans for current user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where: { userId: req.user!.userId },
        orderBy: { startedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          projectName: true,
          status: true,
          progress: true,
          filesScanned: true,
          linesScanned: true,
          readinessScore: true,
          startedAt: true,
          completedAt: true,
          errorMessage: true,
          _count: { select: { findings: true } },
        },
      }),
      prisma.scan.count({ where: { userId: req.user!.userId } }),
    ]);

    res.json({ scans, total, page, limit });
  } catch (error) {
    res.status(500).json({ error: 'Failed to list scans' });
  }
});

// GET /api/scans/:id — Get scan status + results
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id as string },
      include: {
        findings: {
          orderBy: { riskScore: 'desc' },
        },
        services: true,
        migrationTasks: { orderBy: { phase: 'asc' } },
      },
    });

    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.userId !== req.user!.userId && req.user!.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(scan);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch scan' });
  }
});

export default router;
