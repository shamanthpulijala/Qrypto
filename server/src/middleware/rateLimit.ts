import { Request, Response, NextFunction } from 'express';

/**
 * In-memory fixed-window rate limiter.
 *
 * Scope and limitations, stated plainly because they matter operationally:
 *  - State is per-process. With more than one instance the effective limit is
 *    (limit x instances). Move to a Redis-backed store before scaling out.
 *  - Fixed window, not sliding, so up to 2x the limit can pass across a window
 *    boundary. Acceptable for abuse control; not a quota mechanism.
 *
 * Correct client IP resolution depends on `app.set('trust proxy', ...)`; see
 * config.trustProxyHops. Without it, every request behind a reverse proxy
 * resolves to the proxy address and shares a single bucket.
 */

interface Bucket {
  count: number;
  resetTime: number;
}

const buckets = new Map<string, Bucket>();

/**
 * Periodic pruning. The previous implementation never removed entries, so the
 * map grew unbounded with unique client IPs — a slow memory leak that an
 * attacker could accelerate. unref() keeps this timer from holding the process
 * open during shutdown or tests.
 */
const PRUNE_INTERVAL_MS = 60_000;
const pruneTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (now > bucket.resetTime) buckets.delete(key);
  }
}, PRUNE_INTERVAL_MS);
pruneTimer.unref();

/** Exposed for tests, so suites don't leak state between cases. */
export function __resetRateLimitState() {
  buckets.clear();
}

export interface RateLimitOptions {
  /** Bucket key. Defaults to client IP. */
  keyGenerator?: (req: Request) => string;
  /** Bucket namespace, so two limiters on one route don't share counters. */
  scope?: string;
  /** Only count requests the handler rejected (used for failed logins). */
  skipSuccessfulRequests?: boolean;
  message?: string;
}

export const rateLimit = (limit: number, windowMs: number, options: RateLimitOptions = {}) => {
  const {
    keyGenerator = (req: Request) => req.ip || 'unknown',
    scope = 'default',
    skipSuccessfulRequests = false,
    message = 'Too many requests, please try again later.',
  } = options;

  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${scope}:${keyGenerator(req)}`;
    const now = Date.now();

    let bucket = buckets.get(key);
    if (!bucket || now > bucket.resetTime) {
      bucket = { count: 0, resetTime: now + windowMs };
    }

    if (bucket.count >= limit) {
      buckets.set(key, bucket);
      const retryAfterSec = Math.max(1, Math.ceil((bucket.resetTime - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.setHeader('RateLimit-Limit', String(limit));
      res.setHeader('RateLimit-Remaining', '0');
      res.setHeader('RateLimit-Reset', String(retryAfterSec));
      return res.status(429).json({ error: message });
    }

    if (skipSuccessfulRequests) {
      // Count only failures. Lets a legitimate user log in repeatedly while
      // still throttling credential guessing.
      res.on('finish', () => {
        if (res.statusCode >= 400) {
          const current = buckets.get(key) ?? { count: 0, resetTime: now + windowMs };
          current.count++;
          buckets.set(key, current);
        }
      });
      bucket.count = bucket.count; // unchanged up front
      buckets.set(key, bucket);
    } else {
      bucket.count++;
      buckets.set(key, bucket);
    }

    res.setHeader('RateLimit-Limit', String(limit));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, limit - bucket.count)));
    next();
  };
};
