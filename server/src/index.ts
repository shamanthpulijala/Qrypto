import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'path';
import fs from 'fs';
import { config } from './config';
import authRouter from './routes/auth.routes';
import scanRouter from './routes/scan.routes';
import findingsRouter from './routes/findings.routes';
import reportsRouter from './routes/reports.routes';
import { startScanWorker } from './workers/scan.worker';

// ── Ensure temp upload directories exist ───────────────────────
const UPLOAD_DIR = path.join(__dirname, '../uploads');
const TMP_DIR = path.join(__dirname, '../tmp');
[UPLOAD_DIR, TMP_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ── Express app ───────────────────────────────────────────────
const app = express();

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// ── Routes ────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.0.0', timestamp: new Date().toISOString() });
});

app.use('/api/auth', authRouter);
app.use('/api/scans', scanRouter);
app.use('/api/findings', findingsRouter);
app.use('/api/reports', reportsRouter);

// ── 404 handler ───────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ── Global error handler ──────────────────────────────────────
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[error]', err);
  res.status(err.status || 500).json({
    error: config.environment === 'production' ? 'Internal server error' : err.message,
  });
});

// ── Start server + worker ─────────────────────────────────────
app.listen(config.port, () => {
  console.log(`[server] Qrypto API running at http://localhost:${config.port}`);
  console.log(`[server] Environment: ${config.environment}`);
});

// Start the BullMQ scan worker
startScanWorker();
console.log('[worker] Scan worker started');
