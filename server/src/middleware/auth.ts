import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';

/** Roles, mirrored from the Prisma `Role` enum. */
export const ROLES = ['ADMIN', 'ANALYST', 'DEVELOPER', 'EXECUTIVE'] as const;
export type Role = (typeof ROLES)[number];

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value);
}

export interface AuthUser {
  userId: string;
  role: Role;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Algorithm is pinned. Without this, a token could be presented under a
  // different algorithm than the one we intended to verify with.
  jwt.verify(token, config.jwtSecret, { algorithms: [config.jwtAlgorithm] }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    const payload = decoded as { userId?: unknown; role?: unknown };

    // Validate the claims rather than trusting the shape. A token carrying an
    // unrecognised role must not fall through to a permissive default.
    if (typeof payload.userId !== 'string' || !isRole(payload.role)) {
      return res.status(403).json({ error: 'Malformed token claims' });
    }

    req.user = { userId: payload.userId, role: payload.role };
    next();
  });
};

export const requireRole = (roles: Role[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};

/**
 * Single authorization decision for "may this user act on this resource?".
 *
 * Previously this check was inlined at five call sites as
 *   `resource.userId !== req.user.userId && req.user.role !== 'ADMIN'`
 * which meant the ADMIN override could only be changed by editing five places.
 * Centralising it gives one place to audit and one place to change when a
 * tenant/organisation boundary is introduced.
 *
 * ADMIN retains cross-user read access deliberately — an enterprise tool needs
 * an oversight role. That is only safe because ADMIN can no longer be
 * self-assigned at registration; see auth.routes.ts.
 *
 * Returns whether access is allowed, plus whether it was granted by override,
 * so callers can record privileged access in the audit log.
 */
export interface AccessDecision {
  allowed: boolean;
  viaAdminOverride: boolean;
}

export function canAccessResource(
  user: AuthUser | undefined,
  resourceOwnerId: string,
): AccessDecision {
  if (!user) return { allowed: false, viaAdminOverride: false };
  if (user.userId === resourceOwnerId) return { allowed: true, viaAdminOverride: false };
  if (user.role === 'ADMIN') return { allowed: true, viaAdminOverride: true };
  return { allowed: false, viaAdminOverride: false };
}
