import { Request, Response, NextFunction } from 'express';

// Simple in-memory rate limiter for dev.
// In prod, this should use Redis + BullMQ or a redis-based rate limiter library.
const ipRequests = new Map<string, { count: number; resetTime: number }>();

export const rateLimit = (limit: number, windowMs: number) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = req.ip || 'unknown';
    const now = Date.now();

    let record = ipRequests.get(ip);
    
    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + windowMs };
    }

    record.count++;
    ipRequests.set(ip, record);

    if (record.count > limit) {
      return res.status(429).json({ error: 'Too many requests, please try again later.' });
    }

    next();
  };
};
