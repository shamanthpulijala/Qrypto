// ============================================================
// Qrypto — PDF Report Generator
//
// Generates executive and technical PDF reports from scan
// findings using jsPDF. Works entirely in the browser —
// no server-side PDF rendering needed.
//
// Report types:
//   - Executive: high-level readiness, critical risks, compliance
//   - Technical: full findings table with evidence and recommendations
// ============================================================

import type { Finding, MigrationTask, CryptoAgilityScore, HNDLAssessment } from '../types';
import { runMoscaAssessment, type MoscaAssessment } from './mosca';

interface PDFReportData {
  projectName: string;
  organization: string;
  scannedAt: string;
  quantumReadinessScore: number;
  findings: Finding[];
  migrationTasks: MigrationTask[];
  cryptoAgilityScore: CryptoAgilityScore | null;
  hndlAssessments: HNDLAssessment[];
  scanStats: {
    filesScanned: number;
    linesScanned: number;
    findingsTotal: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    vulnerableAlgorithms: number;
    secretsFound: number;
    affectedServices: number;
  };
}

// ─── Color Palette ────────────────────────────────────────────

const COLORS = {
  primary: [0, 40, 85] as [number, number, number],      // dark navy
  accent: [0, 180, 216] as [number, number, number],      // cyan
  critical: [239, 68, 68] as [number, number, number],
  high: [249, 115, 22] as [number, number, number],
  medium: [234, 179, 8] as [number, number, number],
  low: [59, 130, 246] as [number, number, number],
  info: [100, 116, 139] as [number, number, number],
  success: [34, 197, 94] as [number, number, number],
  text: [30, 30, 30] as [number, number, number],
  textLight: [100, 116, 139] as [number, number, number],
  white: [255, 255, 255] as [number, number, number],
  bg: [248, 250, 252] as [number, number, number],
};

function severityColor(severity: string): [number, number, number] {
  switch (severity) {
    case 'critical': return COLORS.critical;
    case 'high': return COLORS.high;
    case 'medium': return COLORS.medium;
    case 'low': return COLORS.low;
    case 'info': return COLORS.info;
    default: return COLORS.textLight;
  }
}

function scoreColor(score: number): [number, number, number] {
  if (score >= 80) return COLORS.success;
  if (score >= 60) return COLORS.medium;
  if (score >= 40) return COLORS.high;
  return COLORS.critical;
}

// ─── NIST Controls ────────────────────────────────────────────

const NIST_CONTROLS = [
  { id: 'PQC-1', title: 'Cryptographic Inventory', desc: 'All crypto assets identified and cataloged.' },
  { id: 'PQC-2', title: 'Quantum-Vulnerable Identification', desc: 'RSA, ECC, ECDH identified and flagged.' },
  { id: 'PQC-3', title: 'Hardcoded Secret Elimination', desc: 'No secrets stored in source code.' },
  { id: 'PQC-4', title: 'Legacy Algorithm Deprecation', desc: 'MD5, SHA-1, DES eliminated.' },
  { id: 'PQC-5', title: 'Post-Quantum Migration Plan', desc: 'Documented migration roadmap.' },
  { id: 'PQC-6', title: 'Crypto-Agility Architecture', desc: 'Algorithms replaceable without major refactoring.' },
  { id: 'PQC-7', title: 'HNDL Risk Assessment', desc: 'Harvest-Now-Decrypt-Later risk evaluated.' },
  { id: 'PQC-8', title: 'TLS Configuration Hardening', desc: 'TLS 1.3 preferred; weak ciphers removed.' },
];

// ─── PDF Generator ────────────────────────────────────────────

export type ReportType = 'executive' | 'technical' | 'developer';

/**
 * Generate a PDF report. Must be called in a browser environment
 * (jsPDF uses the DOM for canvas-based text rendering).
 */
export async function generatePDFReport(
  data: PDFReportData,
  type: ReportType = 'executive',
): Promise<Blob> {
  // Dynamic import to avoid issues in Node test environments
  let jsPDFClass: any;
  try {
    const jspdfModule: any = await import('jspdf');
    jsPDFClass = jspdfModule.jsPDF || jspdfModule.default;
    if (!jsPDFClass) {
      // Fallback: find the constructor among all exports
      jsPDFClass = Object.values(jspdfModule).find((v: any) => typeof v === 'function' && v.prototype?.addPage);
    }
    await import('jspdf-autotable');
  } catch (e) {
    throw new Error(`Failed to load jsPDF library: ${e instanceof Error ? e.message : String(e)}. Ensure jspdf is installed.`);
  }
  if (!jsPDFClass) {
    throw new Error('jsPDF class not found in module. The library may have an unexpected export structure.');
  }

  const doc = new jsPDFClass({ unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  const contentWidth = pageWidth - margin * 2;

  let yPos = margin;

  // ─── Helper: add page if needed ─────────────────────────────
  function ensureSpace(needed: number) {
    if (yPos + needed > pageHeight - margin) {
      doc.addPage();
      yPos = margin;
    }
  }

  // ─── Helper: draw a horizontal rule ─────────────────────────
  function drawRule() {
    doc.setDrawColor(200, 200, 200);
    doc.setLineWidth(0.3);
    doc.line(margin, yPos, pageWidth - margin, yPos);
    yPos += 4;
  }

  // ═══════════════════════════════════════════════════════════
  // TITLE PAGE
  // ═══════════════════════════════════════════════════════════

  // Background header block
  doc.setFillColor(...COLORS.primary);
  doc.rect(0, 0, pageWidth, 70, 'F');

  doc.setTextColor(...COLORS.white);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('QRYPTO', margin, 30);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.text(type === 'executive' ? 'Executive Quantum Readiness Report' : 'Technical Cryptographic Findings Report', margin, 42);

  doc.setFontSize(10);
  doc.text(`${data.organization}  |  ${data.projectName}`, margin, 55);
  doc.text(`Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`, margin, 62);

  yPos = 82;

  // Readiness Score
  doc.setTextColor(...COLORS.text);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Quantum Readiness Score', margin, yPos);
  yPos += 8;

  const scoreColorArr = scoreColor(data.quantumReadinessScore);
  doc.setFontSize(36);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...scoreColorArr);
  doc.text(`${data.quantumReadinessScore}`, margin, yPos);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.text('/ 100', margin + 22, yPos);

  doc.setFontSize(10);
  doc.setTextColor(...COLORS.textLight);
  const grade = data.quantumReadinessScore >= 80 ? 'GOOD' :
                data.quantumReadinessScore >= 60 ? 'AT RISK' : 'CRITICAL';
  doc.text(grade, margin + 45, yPos);
  yPos += 12;

  drawRule();

  // ═══════════════════════════════════════════════════════════
  // SCAN STATISTICS
  // ═══════════════════════════════════════════════════════════

  doc.setTextColor(...COLORS.text);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Scan Summary', margin, yPos);
  yPos += 8;

  const stats = [
    ['Files Scanned', String(data.scanStats.filesScanned)],
    ['Lines Scanned', data.scanStats.linesScanned.toLocaleString()],
    ['Total Findings', String(data.findings.length)],
    ['Critical', String(data.scanStats.criticalCount)],
    ['High', String(data.scanStats.highCount)],
    ['Quantum-Vulnerable', String(data.scanStats.vulnerableAlgorithms)],
    ['Secrets Found', String(data.scanStats.secretsFound)],
    ['Affected Services', String(data.scanStats.affectedServices)],
  ];

  (doc as any).autoTable({
    startY: yPos,
    head: [['Metric', 'Value']],
    body: stats,
    margin: { left: margin, right: margin },
    styles: { fontSize: 9, cellPadding: 3 },
    headStyles: { fillColor: COLORS.primary, textColor: COLORS.white, fontStyle: 'bold' },
    alternateRowStyles: { fillColor: [245, 247, 250] },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 80 },
      1: { halign: 'right' },
    },
  });

  yPos = (doc as any).lastAutoTable.finalY + 10;

  // ═══════════════════════════════════════════════════════════
  // NIST PQC COMPLIANCE
  // ═══════════════════════════════════════════════════════════

  ensureSpace(60);
  doc.setTextColor(...COLORS.text);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('NIST PQC Readiness Checklist', margin, yPos);
  yPos += 8;

  const complianceRows = NIST_CONTROLS.map(ctrl => {
    let status = 'Not Assessed';
    if (ctrl.id === 'PQC-1') status = data.findings.length > 0 ? 'Compliant' : 'Not Assessed';
    if (ctrl.id === 'PQC-2') status = data.findings.some(f => f.quantumStatus === 'vulnerable') ? 'Partial' : 'Compliant';
    if (ctrl.id === 'PQC-3') {
      const openSecrets = data.findings.filter(f => f.category === 'secret' && f.remediationStatus === 'open');
      status = openSecrets.length === 0 ? 'Compliant' : 'Non-Compliant';
    }
    if (ctrl.id === 'PQC-4') {
      const legacy = data.findings.filter(f => f.classicalStatus === 'broken' && f.remediationStatus === 'open');
      status = legacy.length === 0 ? 'Compliant' : 'Non-Compliant';
    }
    if (ctrl.id === 'PQC-5') status = data.migrationTasks.length > 0 ? 'Compliant' : 'Partial';
    if (ctrl.id === 'PQC-6') {
      const score = data.cryptoAgilityScore?.score ?? 0;
      status = score >= 70 ? 'Compliant' : score >= 40 ? 'Partial' : 'Non-Compliant';
    }
    if (ctrl.id === 'PQC-7') status = data.hndlAssessments.length > 0 ? 'Compliant' : 'Partial';
    if (ctrl.id === 'PQC-8') {
      const tlsIssues = data.findings.filter(f => f.category === 'tls' && f.remediationStatus === 'open');
      status = tlsIssues.length === 0 ? 'Compliant' : 'Partial';
    }
    return [ctrl.id, ctrl.title, ctrl.desc, status];
  });

  (doc as any).autoTable({
    startY: yPos,
    head: [['ID', 'Control', 'Description', 'Status']],
    body: complianceRows,
    margin: { left: margin, right: margin },
    styles: { fontSize: 8, cellPadding: 3 },
    headStyles: { fillColor: COLORS.primary, textColor: COLORS.white, fontStyle: 'bold' },
    alternateRowStyles: { fillColor: [245, 247, 250] },
    columnStyles: {
      0: { cellWidth: 18, fontStyle: 'bold' },
      1: { cellWidth: 45 },
      2: { cellWidth: 70 },
      3: { cellWidth: 28, halign: 'center' },
    },
    didParseCell: (hookData: any) => {
      if (hookData.section === 'body' && hookData.column.index === 3) {
        const val = hookData.cell.raw;
        if (val === 'Compliant') hookData.cell.styles.textColor = COLORS.success;
        else if (val === 'Non-Compliant') hookData.cell.styles.textColor = COLORS.critical;
        else if (val === 'Partial') hookData.cell.styles.textColor = COLORS.high;
      }
    },
  });

  yPos = (doc as any).lastAutoTable.finalY + 10;

  // ═══════════════════════════════════════════════════════════
  // CRITICAL FINDINGS TABLE
  // ═══════════════════════════════════════════════════════════

  ensureSpace(40);
  doc.setTextColor(...COLORS.text);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Critical & High-Severity Findings', margin, yPos);
  yPos += 4;

  const criticalFindings = data.findings
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, type === 'executive' ? 15 : data.findings.length);

  if (criticalFindings.length > 0) {
    const findingRows = criticalFindings.map(f => [
      f.id,
      f.algorithm,
      f.service,
      `${f.file}:${f.line}`,
      f.severity.toUpperCase(),
      String(f.riskScore),
      f.quantumStatus,
    ]);

    (doc as any).autoTable({
      startY: yPos,
      head: [['ID', 'Algorithm', 'Service', 'Location', 'Severity', 'Risk', 'Quantum']],
      body: findingRows,
      margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 2.5 },
      headStyles: { fillColor: COLORS.primary, textColor: COLORS.white, fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      columnStyles: {
        0: { cellWidth: 18 },
        4: { halign: 'center' },
        5: { halign: 'center', fontStyle: 'bold' },
      },
      didParseCell: (hookData: any) => {
        if (hookData.section === 'body' && hookData.column.index === 4) {
          const sev = hookData.cell.raw.toLowerCase();
          hookData.cell.styles.textColor = severityColor(sev);
          hookData.cell.styles.fontStyle = 'bold';
        }
      },
    });
    yPos = (doc as any).lastAutoTable.finalY + 10;
  } else {
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.success);
    doc.text('No critical or high-severity findings detected.', margin, yPos);
    yPos += 8;
  }

  // ═══════════════════════════════════════════════════════════
  // MIGRATION ROADMAP
  // ═══════════════════════════════════════════════════════════

  ensureSpace(40);
  doc.setTextColor(...COLORS.text);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Migration Roadmap', margin, yPos);
  yPos += 4;

  if (data.migrationTasks.length > 0) {
    const taskRows = data.migrationTasks.map(t => [
      `Phase ${t.phase}`,
      t.title,
      t.priority.toUpperCase(),
      t.estimatedEffort,
      t.status,
    ]);

    (doc as any).autoTable({
      startY: yPos,
      head: [['Phase', 'Task', 'Priority', 'Effort', 'Status']],
      body: taskRows,
      margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 2.5 },
      headStyles: { fillColor: COLORS.primary, textColor: COLORS.white, fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      columnStyles: {
        0: { cellWidth: 18 },
        1: { cellWidth: 80 },
        2: { halign: 'center', cellWidth: 20 },
        3: { cellWidth: 22 },
        4: { halign: 'center', cellWidth: 22 },
      },
    });
    yPos = (doc as any).lastAutoTable.finalY + 10;
  }

  // ═══════════════════════════════════════════════════════════
  // MOSCA HNDL ASSESSMENT
  // ═══════════════════════════════════════════════════════════

  ensureSpace(40);
  doc.setTextColor(...COLORS.text);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Mosca HNDL Assessment (Harvest-Now-Decrypt-Later)', margin, yPos);
  yPos += 6;

  const mosca = runMoscaAssessment(data.findings, { threatHorizonYear: 2030 });
  doc.setFontSize(8);
  doc.setFont('helvetica', 'italic');
  doc.setTextColor(...COLORS.textLight);
  doc.text(mosca.horizonAssumption, margin, yPos, { maxWidth: contentWidth });
  yPos += 10;

  if (mosca.findings.length > 0) {
    const moscaRows = mosca.findings.slice(0, 15).map(f => [
      f.algorithm,
      f.service,
      `${f.dataLifetimeYears}y`,
      `${f.migrationTimeYears.toFixed(1)}y`,
      `${(f.dataLifetimeYears + f.migrationTimeYears).toFixed(1)}y`,
      `${f.threatHorizonYears}y`,
      f.marginYears > 0 ? `+${f.marginYears.toFixed(1)}y` : `${f.marginYears.toFixed(1)}y`,
      f.riskLevel.toUpperCase(),
    ]);

    (doc as any).autoTable({
      startY: yPos,
      head: [['Algorithm', 'Service', 'Data Life (X)', 'Migration (Y)', 'X+Y', 'Horizon (Z)', 'Margin', 'Risk']],
      body: moscaRows,
      margin: { left: margin, right: margin },
      styles: { fontSize: 7, cellPadding: 2 },
      headStyles: { fillColor: COLORS.primary, textColor: COLORS.white, fontStyle: 'bold', fontSize: 7 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      columnStyles: {
        7: { halign: 'center', fontStyle: 'bold' },
      },
      didParseCell: (hookData: any) => {
        if (hookData.section === 'body' && hookData.column.index === 7) {
          const val = hookData.cell.raw.toLowerCase();
          if (val === 'critical') hookData.cell.styles.textColor = COLORS.critical;
          else if (val === 'high') hookData.cell.styles.textColor = COLORS.high;
          else if (val === 'medium') hookData.cell.styles.textColor = COLORS.medium;
          else if (val === 'safe') hookData.cell.styles.textColor = COLORS.success;
        }
      },
    });
    yPos = (doc as any).lastAutoTable.finalY + 10;
  } else {
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.success);
    doc.text('No quantum-vulnerable findings to assess.', margin, yPos);
    yPos += 8;
  }

  // ═══════════════════════════════════════════════════════════
  // TECHNICAL REPORT: Full findings (continued pages)
  // ═══════════════════════════════════════════════════════════

  if (type === 'technical' || type === 'developer') {
    // Additional detailed findings
    ensureSpace(40);
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('All Findings — Detailed', margin, yPos);
    yPos += 4;

    const allRows = data.findings
      .sort((a, b) => b.riskScore - a.riskScore)
      .map(f => [
        f.id,
        f.algorithm,
        f.category,
        f.service,
        `${f.file}:${f.line}`,
        f.severity.toUpperCase(),
        String(f.riskScore),
        f.confidence ? `${Math.round(f.confidence * 100)}%` : '—',
        f.recommendedAlgorithm ?? '—',
      ]);

    (doc as any).autoTable({
      startY: yPos,
      head: [['ID', 'Algorithm', 'Category', 'Service', 'Location', 'Sev', 'Risk', 'Conf', 'Recommendation']],
      body: allRows,
      margin: { left: margin, right: margin },
      styles: { fontSize: 7, cellPadding: 2 },
      headStyles: { fillColor: COLORS.primary, textColor: COLORS.white, fontStyle: 'bold', fontSize: 7 },
      alternateRowStyles: { fillColor: [245, 247, 250] },
      columnStyles: {
        0: { cellWidth: 16 },
        5: { halign: 'center' },
        6: { halign: 'center', fontStyle: 'bold' },
        7: { halign: 'center' },
      },
      didParseCell: (hookData: any) => {
        if (hookData.section === 'body' && hookData.column.index === 5) {
          const sev = hookData.cell.raw.toLowerCase();
          hookData.cell.styles.textColor = severityColor(sev);
          hookData.cell.styles.fontStyle = 'bold';
        }
      },
    });
    yPos = (doc as any).lastAutoTable.finalY + 10;

    // Evidence details for critical findings
    const criticals = data.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    if (criticals.length > 0) {
      ensureSpace(30);
      doc.setTextColor(...COLORS.text);
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.text('Evidence & Confidence Derivation', margin, yPos);
      yPos += 6;

      for (const f of criticals.slice(0, 10)) {
        ensureSpace(20);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...severityColor(f.severity));
        doc.text(`${f.id} — ${f.algorithm} in ${f.service}`, margin, yPos);
        yPos += 5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(...COLORS.textLight);
        doc.text(`Pattern: ${f.detectedPattern}`, margin + 4, yPos);
        yPos += 4;
        if (f.evidence?.confidenceDerivation) {
          doc.text(`Confidence: ${f.evidence.confidenceDerivation}`, margin + 4, yPos);
          yPos += 4;
        }
        if (f.severityRationale) {
          doc.text(`Severity: ${f.severityRationale}`, margin + 4, yPos);
          yPos += 4;
        }
        yPos += 2;
      }
    }

    // Developer remediation details (developer report only)
    if (type === 'developer') {
      ensureSpace(30);
      doc.setTextColor(...COLORS.text);
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.text('Developer Remediation Guide', margin, yPos);
      yPos += 6;

      for (const f of data.findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 10)) {
        ensureSpace(25);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...severityColor(f.severity));
        doc.text(`${f.id} — ${f.algorithm} (${f.category})`, margin, yPos);
        yPos += 5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(...COLORS.text);
        doc.text(`File: ${f.file}:${f.line}`, margin + 4, yPos);
        yPos += 4;
        doc.text(`Detected: ${f.detectedPattern}`, margin + 4, yPos);
        yPos += 4;
        if (f.recommendedAlgorithm) {
          doc.text(`Replace with: ${f.recommendedAlgorithm}`, margin + 4, yPos);
          yPos += 4;
        }
        if (f.migrationStrategy) {
          doc.text(`Strategy: ${f.migrationStrategy}`, margin + 4, yPos);
          yPos += 4;
        }
        if (f.mode) doc.text(`Mode: ${f.mode}`, margin + 4, yPos), yPos += 4;
        if (f.library) doc.text(`Library: ${f.library}`, margin + 4, yPos), yPos += 4;
        if (f.variant) doc.text(`Variant: ${f.variant}`, margin + 4, yPos), yPos += 4;
        yPos += 3;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════
  // FOOTER (every page)
  // ═══════════════════════════════════════════════════════════

  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.textLight);
    doc.text(
      `Qrypto v2.0  |  Generated ${new Date().toLocaleDateString()}  |  Page ${i} of ${totalPages}`,
      margin,
      pageHeight - 10,
    );
    doc.text(
      'Quantum risk assessments are forward-looking estimates, not predictions.',
      pageWidth - margin - 80,
      pageHeight - 10,
    );
  }

  // Return as Blob for download
  try {
    return doc.output('blob');
  } catch (e) {
    // Fallback: get data URI and convert to blob
    const dataUri = doc.output('datauristring');
    const byteString = atob(dataUri.split(',')[1]);
    const ab = new ArrayBuffer(byteString.length);
    const ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
      ia[i] = byteString.charCodeAt(i);
    }
    return new Blob([ab], { type: 'application/pdf' });
  }
}
