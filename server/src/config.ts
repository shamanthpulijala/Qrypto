import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

/**
 * Known-bad secret that shipped in this repo's git history. Because it is
 * public, any deployment still using it has forgeable tokens. It is rejected
 * outright rather than merely warned about.
 */
const LEAKED_FALLBACK_SECRET = 'fallback-secret-for-dev-only-do-not-use-in-prod';

const MIN_SECRET_LENGTH = 32;

const environment = process.env.NODE_ENV || 'development';
const isProduction = environment === 'production';

/** Collected config problems, so we report all of them at once rather than one per restart. */
const fatal: string[] = [];

function requireInProduction(name: string, value: string | undefined, devDefault: string): string {
  if (value && value.trim() !== '') return value;
  if (isProduction) {
    fatal.push(`${name} is not set. It has no default in production.`);
    return '';
  }
  return devDefault;
}

// ---------------------------------------------------------------------------
// JWT secret
// ---------------------------------------------------------------------------
function resolveJwtSecret(): string {
  const provided = process.env.JWT_SECRET;

  if (provided && provided.trim() !== '') {
    if (provided === LEAKED_FALLBACK_SECRET) {
      fatal.push(
        'JWT_SECRET is set to the fallback value that was committed to this repository. ' +
          'That value is public, so tokens signed with it are forgeable. Generate a new one: ' +
          "node -e \"console.log(require('crypto').randomBytes(48).toString('base64url'))\"",
      );
      return '';
    }
    if (provided.length < MIN_SECRET_LENGTH) {
      const msg = `JWT_SECRET is only ${provided.length} characters; at least ${MIN_SECRET_LENGTH} are required.`;
      if (isProduction) fatal.push(msg);
      else console.warn(`[config] WARNING: ${msg}`);
    }
    return provided;
  }

  if (isProduction) {
    fatal.push(
      'JWT_SECRET is not set. Refusing to start in production with a default signing key.',
    );
    return '';
  }

  // Development only: a per-process random secret. Deliberately NOT a constant,
  // so a dev secret can never accidentally become a shared/committed one. The
  // side effect is that restarting the dev server invalidates existing tokens,
  // which is the correct trade-off.
  const ephemeral = crypto.randomBytes(48).toString('base64url');
  console.warn(
    '[config] JWT_SECRET not set — generated an ephemeral development secret. ' +
      'Tokens will be invalidated on restart. Set JWT_SECRET in .env to persist sessions.',
  );
  return ephemeral;
}

export const config = {
  port: process.env.PORT ? parseInt(process.env.PORT, 10) : 3001,

  databaseUrl: requireInProduction(
    'DATABASE_URL',
    process.env.DATABASE_URL,
    'postgresql://postgres:postgres@localhost:5432/qrypto',
  ),

  redisUrl: requireInProduction('REDIS_URL', process.env.REDIS_URL, 'redis://localhost:6379'),

  jwtSecret: resolveJwtSecret(),

  /** Pinned so a token cannot be presented under a different algorithm. */
  jwtAlgorithm: 'HS256' as const,

  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',

  /**
   * Number of reverse proxies in front of the app. Required for correct client
   * IP resolution — without it every request behind a proxy shares one rate
   * limit bucket. 0 means the app is directly exposed.
   */
  trustProxyHops: process.env.TRUST_PROXY_HOPS
    ? parseInt(process.env.TRUST_PROXY_HOPS, 10)
    : 0,

  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',

  /**
   * Self-service registration. Enabled by default in development for
   * convenience; must be opted into explicitly in production, because an
   * enterprise deployment normally provisions accounts rather than accepting
   * open sign-ups.
   */
  allowPublicRegistration: process.env.ALLOW_PUBLIC_REGISTRATION
    ? process.env.ALLOW_PUBLIC_REGISTRATION === 'true'
    : !isProduction,

  /**
   * Controlled first-admin bootstrap. If this email registers while no ADMIN
   * exists yet, that account is created as ADMIN. Requires server-side env
   * control, and stops working as soon as an admin exists.
   */
  bootstrapAdminEmail: process.env.BOOTSTRAP_ADMIN_EMAIL
    ? process.env.BOOTSTRAP_ADMIN_EMAIL.trim().toLowerCase()
    : null,

  environment,
  isProduction,
};

// ---------------------------------------------------------------------------
// Fail fast. A misconfigured security boundary must not start and serve
// traffic — a warning in a log nobody reads is not a control.
// ---------------------------------------------------------------------------
if (fatal.length > 0) {
  console.error('\n[config] Refusing to start — invalid configuration:\n');
  for (const problem of fatal) console.error(`  • ${problem}`);
  console.error('');
  process.exit(1);
}
