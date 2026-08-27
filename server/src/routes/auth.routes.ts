import { Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { config } from '../config';
import { authenticateToken, requireRole, isRole, type Role } from '../middleware/auth';
import { rateLimit } from '../middleware/rateLimit';

const router = Router();
const prisma = new PrismaClient();

const BCRYPT_ROUNDS = 12;
const MIN_PASSWORD_LENGTH = 12;

/**
 * A real bcrypt hash of a value nobody knows, used to equalise response time
 * when an account does not exist. Without it, login returns measurably faster
 * for unknown emails, which is a user-enumeration oracle.
 */
const DUMMY_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKcEe.7Xhx7uYQxKZK5Zx1qLZTzXQKz8sJ0Iu';

function issueToken(userId: string, role: Role): string {
  return jwt.sign({ userId, role }, config.jwtSecret, {
    algorithm: config.jwtAlgorithm,
    expiresIn: config.jwtExpiresIn,
  } as jwt.SignOptions);
}

function normalizeEmail(email: unknown): string | null {
  if (typeof email !== 'string') return null;
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > 254) return null;
  // Intentionally permissive: real validation is delivery, not a regex.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return null;
  return trimmed;
}

function validatePassword(password: unknown, email: string): string | null {
  if (typeof password !== 'string') return 'Password is required';
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  }
  if (password.length > 200) return 'Password must be at most 200 characters';
  if (password.toLowerCase() === email) return 'Password must not be the email address';
  return null;
}

// ---------------------------------------------------------------------------
// POST /register
//
// SECURITY: `role` is deliberately NOT read from the request body. It used to
// be (`role: role || 'ANALYST'`), which let anyone self-register as ADMIN and,
// combined with the ADMIN override on every ownership check, read every other
// user's scans, findings and reports. Role is now server-determined only.
// ---------------------------------------------------------------------------
router.post(
  '/register',
  rateLimit(5, 60 * 60 * 1000, { scope: 'register' }),
  async (req, res) => {
    try {
      if (!config.allowPublicRegistration) {
        return res.status(403).json({ error: 'Public registration is disabled' });
      }

      const email = normalizeEmail(req.body?.email);
      const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';

      if (!email) return res.status(400).json({ error: 'A valid email is required' });
      if (name.length === 0 || name.length > 120) {
        return res.status(400).json({ error: 'Name is required (max 120 characters)' });
      }

      const passwordError = validatePassword(req.body?.password, email);
      if (passwordError) return res.status(400).json({ error: passwordError });

      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return res.status(409).json({ error: 'An account with that email already exists' });
      }

      // Controlled first-admin bootstrap. Requires server-side env control and
      // only applies while no ADMIN exists, so it cannot be used to escalate
      // once the system is set up.
      let role: Role = 'ANALYST';
      if (config.bootstrapAdminEmail && config.bootstrapAdminEmail === email) {
        const adminCount = await prisma.user.count({ where: { role: 'ADMIN' } });
        if (adminCount === 0) role = 'ADMIN';
      }

      const passwordHash = await bcrypt.hash(req.body.password, BCRYPT_ROUNDS);
      const user = await prisma.user.create({
        data: { email, passwordHash, name, role },
      });

      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'user_registered',
          targetId: user.id,
          metadata: { role, bootstrapped: role === 'ADMIN' },
        },
      });

      const token = issueToken(user.id, role);
      res.status(201).json({
        token,
        user: { id: user.id, email: user.email, name: user.name, role: user.role },
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  },
);

// ---------------------------------------------------------------------------
// POST /login
// Throttled on failures only, so a legitimate user is never locked out by
// their own successful logins.
// ---------------------------------------------------------------------------
router.post(
  '/login',
  rateLimit(10, 15 * 60 * 1000, {
    scope: 'login',
    skipSuccessfulRequests: true,
    message: 'Too many failed login attempts. Try again later.',
  }),
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      // Uniform failure response — never distinguish "no such user" from
      // "wrong password".
      const reject = () => res.status(401).json({ error: 'Invalid credentials' });

      if (!email || password.length === 0) {
        await bcrypt.compare('placeholder', DUMMY_HASH);
        return reject();
      }

      const user = await prisma.user.findUnique({ where: { email } });

      if (!user) {
        // Equalise timing against the found-user path.
        await bcrypt.compare(password, DUMMY_HASH);
        return reject();
      }

      const validPassword = await bcrypt.compare(password, user.passwordHash);
      if (!validPassword) {
        await prisma.auditLog.create({
          data: {
            userId: user.id,
            action: 'user_login_failed',
            targetId: user.id,
            metadata: { reason: 'bad_password' },
          },
        });
        return reject();
      }

      if (!isRole(user.role)) {
        console.error(`User ${user.id} has unrecognised role ${user.role}`);
        return res.status(500).json({ error: 'Internal server error' });
      }

      await prisma.auditLog.create({
        data: { userId: user.id, action: 'user_login', targetId: user.id },
      });

      const token = issueToken(user.id, user.role);
      res.json({
        token,
        user: { id: user.id, email: user.email, name: user.name, role: user.role },
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  },
);

router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user!.userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ id: user.id, email: user.email, name: user.name, role: user.role });
  } catch (error) {
    console.error('Profile lookup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// ADMIN-only user administration.
// These are the first real uses of requireRole, which was previously defined
// but never called anywhere in the codebase.
// ---------------------------------------------------------------------------

router.get('/users', authenticateToken, requireRole(['ADMIN']), async (_req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, email: true, name: true, role: true, createdAt: true },
      orderBy: { createdAt: 'asc' },
    });
    res.json({ users });
  } catch (error) {
    console.error('User list error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.patch('/users/:id/role', authenticateToken, requireRole(['ADMIN']), async (req, res) => {
  try {
    // Express types params as string | string[]; reject the array form rather
    // than casting, so a duplicated path segment can't slip through.
    const rawId = req.params.id;
    if (typeof rawId !== 'string' || rawId.length === 0) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const id: string = rawId;
    const newRole = req.body?.role;

    if (!isRole(newRole)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Prevent an admin removing their own ADMIN rights, which could leave the
    // system with no administrator.
    if (id === req.user!.userId && newRole !== 'ADMIN') {
      return res.status(400).json({ error: 'You cannot change your own admin role' });
    }

    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) return res.status(404).json({ error: 'User not found' });

    // Don't allow removing the last remaining administrator.
    if (target.role === 'ADMIN' && newRole !== 'ADMIN') {
      const adminCount = await prisma.user.count({ where: { role: 'ADMIN' } });
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'Cannot remove the last administrator' });
      }
    }

    const updated = await prisma.user.update({
      where: { id },
      data: { role: newRole },
    });

    await prisma.auditLog.create({
      data: {
        userId: req.user!.userId,
        action: 'user_role_changed',
        targetId: id,
        metadata: { from: target.role, to: newRole },
      },
    });

    res.json({
      user: {
        id: updated.id,
        email: updated.email,
        name: updated.name,
        role: updated.role,
      },
    });
  } catch (error) {
    console.error('Role change error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
