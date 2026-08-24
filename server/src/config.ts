import dotenv from 'dotenv';

dotenv.config();

export const config = {
  port: process.env.PORT ? parseInt(process.env.PORT, 10) : 3001,
  databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/qrypto',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  jwtSecret: process.env.JWT_SECRET || 'fallback-secret-for-dev-only-do-not-use-in-prod',
  environment: process.env.NODE_ENV || 'development'
};

if (config.environment === 'production' && config.jwtSecret === 'fallback-secret-for-dev-only-do-not-use-in-prod') {
  console.warn('WARNING: Running in production with fallback JWT secret. Set JWT_SECRET in environment variables.');
}
