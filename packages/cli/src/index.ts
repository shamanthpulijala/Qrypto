#!/usr/bin/env node

// ============================================================
// Qrypto CLI — Enterprise Cryptographic Discovery & Analysis
//
// Uses the same shared/engine as the web UI and backend.
// No duplication. No fabricated numbers.
//
// Exit codes:
//   0 = successful scan, no policy violation
//   1 = operational failure (file not found, scan error, etc.)
//   2 = policy violation (findings exceed --fail-on threshold)
// ============================================================

import { Command } from 'commander';
import { runScan } from './commands/scan';

const VERSION = '1.0.0';

const program = new Command();

program
  .name('qrypto')
  .description('Enterprise Cryptographic Discovery & Analysis Tool')
  .version(VERSION);

program
  .command('scan <path>')
  .description('Scan a directory or file for cryptographic primitives')
  .option('-f, --format <format>', 'Output format: json, csv, cbom, text', 'text')
  .option('-o, --output <file>', 'Write output to file instead of stdout')
  .option('--json', 'Alias for --format json')
  .option('--csv', 'Alias for --format csv')
  .option('--cbom', 'Alias for --format cbom')
  .option('--fail-on <severity>', 'Exit with code 2 if findings meet or exceed this severity: critical, high, medium, low')
  .option('--no-confidence-filter', 'Show all findings including low-confidence ones')
  .option('--confidence-threshold <number>', 'Minimum confidence threshold (0.0-1.0)', '0.70')
  .option('--repository <name>', 'Repository name for findings metadata')
  .option('--verbose', 'Show detailed scan progress')
  .action(async (path: string, options: any) => {
    try {
      if (options.json) options.format = 'json';
      if (options.csv) options.format = 'csv';
      if (options.cbom) options.format = 'cbom';
      const exitCode = await runScan(path, options);
      process.exit(exitCode);
    } catch (error: any) {
      console.error(`[qrypto] Error: ${error.message}`);
      process.exit(1);
    }
  });

program.parse();
