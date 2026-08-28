import { Worker, Job, Queue } from 'bullmq';
import { PrismaClient } from '@prisma/client';
import { config } from '../config';
import { extractZipSecurely } from '../services/upload.service';
import { runScanPipeline } from '../../../shared/engine/pipeline';
import { generateMigrationRoadmap } from '../../../shared/engine/migrationPlanner';
import { computeCryptoAgilityScore } from '../../../shared/engine/cryptoAgility';
import { generateHNDLAssessments } from '../../../shared/engine/hndlAnalyzer';
import fs from 'fs';
import path from 'path';

const prisma = new PrismaClient();

export const connection = {
  url: config.redisUrl,
};

// Export queue so routes can enqueue jobs
export const scanQueue = new Queue('scan-queue', { connection });

export const startScanWorker = () => {
  const worker = new Worker(
    'scan-queue',
    async (job: Job) => {
      const { scanId, zipPath, extractDir, projectName } = job.data;

      try {
        // 1. Mark as RUNNING
        await prisma.scan.update({
          where: { id: scanId },
          data: { status: 'RUNNING', progress: 5 },
        });

        // 2. Ensure extract directory exists, then extract zip securely
        await job.updateProgress(10);
        fs.mkdirSync(extractDir, { recursive: true });
        let filePaths: string[] = [];
        try {
          filePaths = extractZipSecurely(zipPath, extractDir);
        } catch (err: any) {
          throw new Error(`Extraction failed: ${err.message}`);
        }

        // 3. Read files into PipelineFile format
        await job.updateProgress(20);
        const pipelineFiles = [];
        for (const filePath of filePaths) {
          try {
            const stats = fs.statSync(filePath);
            const content = fs.readFileSync(filePath, 'utf-8');
            pipelineFiles.push({
              name: path.basename(filePath),
              path: filePath.replace(extractDir + path.sep, '').replace(/\\/g, '/'),
              content,
              sizeBytes: stats.size,
            });
          } catch {
            // skip unreadable files silently
          }
        }

        // 4. Run the shared pipeline
        let lastProgress = 20;
        const result = await runScanPipeline(pipelineFiles, {
          project: projectName,
          onProgress: async (stage, pct, msg) => {
            // Map pipeline 0–100 to job 20–90
            const mapped = 20 + Math.round((pct / 100) * 70);
            if (mapped > lastProgress) {
              lastProgress = mapped;
              await job.updateProgress(mapped);
            }
          },
        });

        const { findings, stats, readinessIndex } = result;

        // 5. Run additional engines
        await job.updateProgress(90);
        const serviceNodes = Array.from(new Set(findings.map(f => f.service))).map(svcName => {
          const svcFindings = findings.filter(f => f.service === svcName);
          return {
            id: svcName,
            name: svcName,
            type: 'Application' as const,
            internetFacing: svcFindings.some(f => f.internetFacing),
            dataSensitivity: 'High' as const,
            riskScore: Math.max(...svcFindings.map(f => f.riskScore), 0),
            findings: svcFindings,
          };
        });

        const migrationTasks = generateMigrationRoadmap(findings, serviceNodes as any);

        // 6. Persist everything in a transaction
        await prisma.$transaction(async (tx) => {
          await tx.scan.update({
            where: { id: scanId },
            data: {
              status: 'COMPLETE',
              progress: 100,
              completedAt: new Date(),
              filesScanned: stats.filesScanned,
              linesScanned: stats.linesScanned,
              readinessScore: readinessIndex.overall,
            },
          });

          if (findings.length > 0) {
            await tx.finding.createMany({
              data: findings.map(f => ({
                scanId,
                file: f.file,
                line: f.line,
                algorithm: f.algorithm,
                keySize: f.keySize ?? null,
                category: f.category,
                usage: f.usage,
                detectedPattern: f.detectedPattern,
                confidence: f.confidence,
                quantumStatus: f.quantumStatus,
                classicalStatus: f.classicalStatus,
                severity: f.severity,
                riskScore: f.riskScore,
                riskBreakdown: (f.riskBreakdown ?? {}) as any,
                service: f.service,
                language: f.language,
                internetFacing: f.internetFacing,
                dataSensitivity: f.dataSensitivity,
                dataLifetimeYears: f.dataLifetimeYears,
                isCryptoAgile: f.isCryptoAgile,
                isHardcoded: f.isHardcoded,
                remediationStatus: f.remediationStatus ?? 'open',
                recommendedAlgo: f.recommendedAlgorithm ?? null,
                migrationStrategy: f.migrationStrategy ?? null,
                tags: f.tags ?? [],
              })),
            });
          }

          if (migrationTasks.length > 0) {
            await tx.migrationTask.createMany({
              data: migrationTasks.map(t => ({
                scanId,
                phase: t.phase,
                title: t.title,
                description: t.description,
                priority: t.priority,
                effort: t.effort,
                estimatedEffort: t.estimatedEffort,
                affectedServices: t.affectedServices ?? [],
                affectedFindings: t.affectedFindings ?? [],
                reason: t.reason,
                dependencies: t.dependencies ?? [],
                status: t.status ?? 'todo',
                tags: t.tags ?? [],
              })),
            });
          }
        });

        // 7. Cleanup temp files
        try {
          fs.rmSync(extractDir, { recursive: true, force: true });
          if (fs.existsSync(zipPath)) fs.rmSync(zipPath, { force: true });
        } catch { /* cleanup failure is non-fatal */ }

        return { success: true, findingsCount: findings.length, readiness: readinessIndex.overall };
      } catch (error: any) {
        console.error(`[scan-worker] Job ${scanId} failed:`, error);

        await prisma.scan.update({
          where: { id: scanId },
          data: { status: 'ERROR', errorMessage: error.message ?? 'Unknown error' },
        });

        // Cleanup on failure too
        try {
          if (fs.existsSync(extractDir)) fs.rmSync(extractDir, { recursive: true, force: true });
          if (fs.existsSync(zipPath)) fs.rmSync(zipPath, { force: true });
        } catch { /* ignore */ }

        throw error;
      }
    },
    { connection }
  );

  worker.on('completed', job => {
    console.log(`[scan-worker] Job ${job.id} completed`);
  });

  worker.on('failed', (job, err) => {
    console.error(`[scan-worker] Job ${job?.id} failed:`, err.message);
  });

  return worker;
};
