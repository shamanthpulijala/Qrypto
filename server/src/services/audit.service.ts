import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function logAudit(
  userId: string,
  action: string,
  targetId?: string,
  metadata?: Record<string, any>
) {
  try {
    await prisma.auditLog.create({
      data: {
        userId,
        action,
        targetId: targetId ?? null,
        metadata: metadata ?? {},
      },
    });
  } catch (err) {
    // Audit log failures are non-fatal — log to console but don't crash
    console.error('[audit] Failed to write audit log:', err);
  }
}
