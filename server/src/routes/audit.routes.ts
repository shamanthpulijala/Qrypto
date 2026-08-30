import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateToken } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

// GET /api/audit — List audit log entries for the current user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const skip = (page - 1) * limit;

    const [entries, total] = await Promise.all([
      prisma.auditLog.findMany({
        where: { userId: req.user!.userId },
        orderBy: { timestamp: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          action: true,
          targetId: true,
          metadata: true,
          timestamp: true,
        },
      }),
      prisma.auditLog.count({ where: { userId: req.user!.userId } }),
    ]);

    res.json({ entries, total, page, limit });
  } catch (error) {
    console.error('GET /api/audit error:', error);
    res.status(500).json({ error: 'Failed to list audit log' });
  }
});

export default router;
