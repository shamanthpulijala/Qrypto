// ============================================================
// QuantumGuard AI — Premium Landing Page §09-§20
// Cinematic scroll-driven editorial experience
// ============================================================

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Shield, Zap, ArrowRight, Upload, FileCode2, AlertCircle, Eye, ChevronRight, Check } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import JSZip from 'jszip';
import { ENTERPRISE_SAMPLE_FILES } from '../../data/enterpriseSampleRepo';
import { PQC_READY_SAMPLE_FILES } from '../../data/pqcReadySampleRepo';
import { QuantumComputer } from './QuantumComputer';
import './Landing.css';

// ─── Crypto labels for §10 ────────────────────────────────────
const CRYPTO_LABELS = [
  { name: 'RSA-2048', status: 'QUANTUM VULNERABLE', cls: 'vulnerable', pos: { top: '12%', left: '5%' },
    tooltip: 'RSA relies on integer factorization, which Shor\'s algorithm can solve in polynomial time on a quantum computer.' },
  { name: 'ECC', status: 'QUANTUM VULNERABLE', cls: 'vulnerable', pos: { top: '25%', right: '3%' },
    tooltip: 'Elliptic Curve Cryptography is broken by quantum computers using Shor\'s algorithm on the discrete logarithm problem.' },
  { name: 'ECDH', status: 'QUANTUM VULNERABLE', cls: 'vulnerable', pos: { bottom: '30%', left: '2%' },
    tooltip: 'ECDH key exchange is vulnerable to quantum attack. Migrate to ML-KEM (FIPS 203) for post-quantum key encapsulation.' },
  { name: 'AES-256', status: 'STRONG', cls: 'strong', pos: { bottom: '15%', right: '8%' },
    tooltip: 'AES-256 remains quantum-safe. Grover\'s algorithm only halves the effective key strength to 128-bit equivalent.' },
  { name: 'ML-KEM', status: 'POST-QUANTUM', cls: 'pqc', pos: { top: '60%', left: '8%' },
    tooltip: 'FIPS 203 (ML-KEM, formerly Kyber). NIST\'s primary post-quantum key encapsulation mechanism based on Module-LWE.' },
  { name: 'TLS 1.2', status: 'MIGRATION REQUIRED', cls: 'migration', pos: { top: '45%', right: '2%' },
    tooltip: 'TLS 1.2 is classically adequate but should be migrated to TLS 1.3 with PQC cipher suites for quantum safety.' },
];

// ─── Discovery nodes §12 ──────────────────────────────────────
const DISCOVERY_NODES = [
  { icon: '🌐', label: 'Internet', algo: 'TLS' },
  { icon: '☁️', label: 'Cloud', algo: 'AES' },
  { icon: '📱', label: 'Applications', algo: 'RSA' },
  { icon: '🔗', label: 'APIs', algo: 'ECDH' },
  { icon: '🔐', label: 'Authentication', algo: 'ECDSA' },
  { icon: '📜', label: 'Certificates', algo: 'SHA-256' },
  { icon: '🗄️', label: 'Databases', algo: 'AES-256' },
  { icon: '📦', label: 'Archives', algo: 'SHA-1' },
];

// ─── Risk model factors §14 ──────────────────────────────────
const RISK_FACTORS = [
  { name: 'Quantum Vulnerability', weight: '30%', fill: 85, color: '#ef4444' },
  { name: 'Business Criticality', weight: '20%', fill: 70, color: '#f97316' },
  { name: 'Internet Exposure', weight: '15%', fill: 60, color: '#eab308' },
  { name: 'Confidentiality Lifetime', weight: '15%', fill: 75, color: '#7c3aed' },
  { name: 'Data Sensitivity', weight: '10%', fill: 65, color: '#00d4ff' },
  { name: 'Migration Difficulty', weight: '10%', fill: 50, color: '#8b5cf6' },
];

// ─── Migration transforms §18 ────────────────────────────────
const MIGRATIONS = [
  { from: 'RSA-2048', to: 'HYBRID ML-KEM', progress: 65 },
  { from: 'ECDSA', to: 'ML-DSA (FIPS 204)', progress: 40 },
  { from: 'TLS 1.0', to: 'TLS 1.3', progress: 80 },
  { from: 'SHA-1', to: 'SHA-3-256', progress: 90 },
  { from: 'HARDCODED KEYS', to: 'MANAGED VAULT', progress: 30 },
];

// ─── HNDL data categories §16 ────────────────────────────────
const HNDL_CATEGORIES = ['Medical Records', 'Financial Records', 'Government Data', 'Source Code', 'Customer Data', 'Intellectual Property'];
const HNDL_RISKS: Record<string, number> = {
  'Medical Records': 98, 'Financial Records': 92, 'Government Data': 97,
  'Source Code': 78, 'Customer Data': 88, 'Intellectual Property': 95,
};

const SUPPORTED_EXT = ['.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go', '.yml', '.yaml', '.json', '.xml', '.sh', '.conf', '.env', '.properties', '.gradle', '.toml', '.tf'];
const MAX_ZIP_SIZE = 50 * 1024 * 1024;
const MAX_FILES = 2000;

interface FileEntry { path: string; content: string; }

// ─── Intersection Observer hook ───────────────────────────────
function useFadeIn() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) { el.classList.add('visible'); obs.disconnect(); } },
      { threshold: 0.15 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);
  return ref;
}

// ─── Main Component ───────────────────────────────────────────
export function Landing() {
  const { startScan, isScanning, scanProgress, scanLog, scanError } = useAppStore();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropRef = useRef<HTMLDivElement>(null);

  const [dragging, setDragging] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [fileSummary, setFileSummary] = useState<{ name: string; count: number } | null>(null);
  const [pendingFiles, setPendingFiles] = useState<FileEntry[] | null>(null);
  const [hoveredLabel, setHoveredLabel] = useState<string | null>(null);
  const [selectedHndl, setSelectedHndl] = useState('Medical Records');

  // Fade-in refs
  const discoveryRef = useFadeIn();
  const riskRef = useFadeIn();
  const hndlRef = useFadeIn();
  const migrationRef = useFadeIn();
  const uploadRef = useFadeIn();
  const accuracyRef = useFadeIn();

  // ── File processing ──
  const processZip = useCallback(async (file: File): Promise<FileEntry[]> => {
    if (file.size > MAX_ZIP_SIZE) throw new Error(`ZIP file too large (max 50 MB). Got ${(file.size / 1024 / 1024).toFixed(1)} MB.`);
    const zip = await JSZip.loadAsync(file);
    const entries: FileEntry[] = [];
    const jobs: Promise<void>[] = [];
    zip.forEach((relativePath, zipEntry) => {
      if (zipEntry.dir) return;
      if (relativePath.includes('..')) return;
      const lower = relativePath.toLowerCase();
      if (!SUPPORTED_EXT.some(ext => lower.endsWith(ext))) return;
      if (entries.length >= MAX_FILES) return;
      jobs.push(zipEntry.async('string').then(content => { entries.push({ path: relativePath, content }); }).catch(() => {}));
    });
    await Promise.all(jobs);
    if (entries.length === 0) throw new Error('No supported source files found in ZIP.');
    return entries;
  }, []);

  const handleFiles = useCallback(async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setUploadError(null); setPendingFiles(null); setFileSummary(null);
    const file = fileList[0];
    try {
      let entries: FileEntry[];
      if (file.name.endsWith('.zip')) { entries = await processZip(file); }
      else {
        const ext = '.' + file.name.split('.').pop()?.toLowerCase();
        if (!SUPPORTED_EXT.includes(ext)) throw new Error(`Unsupported file type: ${ext}`);
        entries = [{ path: file.name, content: await file.text() }];
      }
      setFileSummary({ name: file.name, count: entries.length });
      setPendingFiles(entries);
    } catch (err: any) { setUploadError(err.message || 'Failed to read file.'); }
  }, [processZip]);

  const handleScan = useCallback(() => { if (pendingFiles) startScan(pendingFiles); }, [pendingFiles, startScan]);

  // ── Drag and drop ──
  const onDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); setDragging(true); }, []);
  const onDragLeave = useCallback(() => setDragging(false), []);
  const onDrop = useCallback((e: React.DragEvent) => { e.preventDefault(); setDragging(false); handleFiles(e.dataTransfer.files); }, [handleFiles]);

  // Compute scan steps for cinematic display
  const scanSteps = [
    { label: 'Repository indexed', done: scanProgress >= 10 },
    { label: 'Dependencies analyzed', done: scanProgress >= 25 },
    { label: 'Cryptographic APIs discovered', done: scanProgress >= 45 },
    { label: 'Certificates inspected', done: scanProgress >= 60 },
    { label: 'Configuration analyzed', done: scanProgress >= 75 },
    { label: 'Risk model generated', done: scanProgress >= 90 },
  ];

  return (
    <div className="landing">

      {/* ═══ HERO §09 ═══ */}
      <section className="hero">
        <div className="hero-bg-gradient" />
        <div className="hero-inner">
          <div className="hero-text">
            <div className="hero-badge">
              <Shield size={11} />
              QUANTUMGUARD AI
            </div>
            <h1 className="hero-title">
              SEE WHAT BREAKS<br />
              <span className="hero-title-accent">BEFORE QUANTUM</span> DOES.
            </h1>
            <p className="hero-subtitle">
              Discover, evaluate, and migrate the cryptography protecting your digital
              infrastructure — before quantum computing changes the rules.
            </p>
            <div className="hero-actions">
              <button className="btn-hero-primary" onClick={() => document.getElementById('upload-section')?.scrollIntoView({ behavior: 'smooth' })}>
                START ASSESSMENT <ArrowRight size={16} />
              </button>
              <button className="btn-hero-secondary" onClick={() => {
                setFileSummary({ name: 'qrypto-enterprise-sample.zip', count: ENTERPRISE_SAMPLE_FILES.length });
                setPendingFiles(ENTERPRISE_SAMPLE_FILES);
                setTimeout(() => document.getElementById('upload-section')?.scrollIntoView({ behavior: 'smooth' }), 100);
              }}>
                EXPLORE Q-DAY <Zap size={16} />
              </button>
            </div>
            <div className="hero-stats">
              <div className="hero-stat">
                <span className="hero-stat-value">58+</span>
                <span className="hero-stat-label">Detection Patterns</span>
              </div>
              <div className="hero-stat">
                <span className="hero-stat-value">8</span>
                <span className="hero-stat-label">Languages</span>
              </div>
              <div className="hero-stat">
                <span className="hero-stat-value">FIPS 203–205</span>
                <span className="hero-stat-label">NIST PQC Standards</span>
              </div>
            </div>
          </div>

          {/* 3D Quantum Computer §08 */}
          <div className="hero-3d-container">
            <QuantumComputer />
            {/* Floating crypto labels §10 */}
            <div className="crypto-labels">
              {CRYPTO_LABELS.map(l => (
                <div
                  key={l.name}
                  className="crypto-label"
                  style={l.pos as React.CSSProperties}
                  onMouseEnter={() => setHoveredLabel(l.name)}
                  onMouseLeave={() => setHoveredLabel(null)}
                >
                  <span className="cl-name">{l.name}</span>
                  <span className={`cl-status ${l.cls}`}>{l.status}</span>
                  {hoveredLabel === l.name && (
                    <div className="crypto-label-tooltip">{l.tooltip}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ═══ DISCOVERY §12 ═══ */}
      <div ref={discoveryRef} className="landing-section fade-in-section">
        <div className="section-badge danger">THE CHALLENGE</div>
        <h2 className="section-title">
          YOU CAN'T PROTECT<br />WHAT YOU CAN'T SEE.
        </h2>
        <p className="section-desc">
          Cryptographic dependencies are embedded across every layer of your infrastructure.
          QuantumGuard maps them all — automatically.
        </p>
        <div className="discovery-grid">
          {DISCOVERY_NODES.map(n => (
            <div key={n.label} className="discovery-node">
              <span className="discovery-node-icon">{n.icon}</span>
              <span className="discovery-node-label">{n.label}</span>
              <span className="discovery-node-algo">{n.algo}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ RISK MODEL §14 ═══ */}
      <div ref={riskRef} className="landing-section fade-in-section">
        <div className="section-badge">QUANTUMGUARD RISK MODEL</div>
        <h2 className="section-title">
          NOT EVERY<br />CRYPTOGRAPHIC RISK<br />IS THE SAME.
        </h2>
        <p className="section-desc">
          Our deterministic, multi-factor risk model evaluates each cryptographic asset
          based on quantum vulnerability, business context, and migration complexity.
        </p>
        <div className="risk-formula">
          {RISK_FACTORS.map(f => (
            <div key={f.name} className="risk-factor">
              <span className="risk-factor-weight">{f.weight}</span>
              <span className="risk-factor-name">{f.name}</span>
              <div className="risk-factor-bar">
                <div className="risk-factor-bar-fill" style={{ width: `${f.fill}%`, background: f.color }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ HNDL §16 ═══ */}
      <div ref={hndlRef} className="landing-section fade-in-section">
        <div className="section-badge danger">HARVEST NOW, DECRYPT LATER</div>
        <h2 className="section-title">
          Your data is being<br />collected today.
        </h2>
        <p className="section-desc">
          Adversaries are intercepting encrypted data now, storing it until quantum computers
          can decrypt it. How long does your data need to remain confidential?
        </p>
        <div className="hndl-categories">
          {HNDL_CATEGORIES.map(c => (
            <button
              key={c}
              className={`hndl-category-btn ${selectedHndl === c ? 'active' : ''}`}
              onClick={() => setSelectedHndl(c)}
            >
              {c}
            </button>
          ))}
        </div>
        <div className="hndl-result">
          <div>
            <div className="hndl-risk-label">LONG-TERM CONFIDENTIALITY RISK</div>
            <div className="hndl-risk-value">{HNDL_RISKS[selectedHndl]}%</div>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {selectedHndl} with 20+ year confidentiality requirements face extreme HNDL risk.
            Data intercepted today can be decrypted when CRQCs arrive.
          </p>
        </div>
      </div>

      {/* ═══ MIGRATION §18 ═══ */}
      <div ref={migrationRef} className="landing-section fade-in-section">
        <div className="section-badge cyan">MIGRATION PATHWAYS</div>
        <h2 className="section-title">
          From classical<br />to quantum-safe.
        </h2>
        <p className="section-desc">
          QuantumGuard generates step-by-step migration paths aligned with NIST FIPS 203, 204, and 205.
        </p>
        <div className="migration-transforms">
          {MIGRATIONS.map(m => (
            <div key={m.from} className="migration-row">
              <span className="migration-from">{m.from}</span>
              <span className="migration-arrow">→</span>
              <span className="migration-to">{m.to}</span>
              <div className="migration-bar">
                <div className="migration-bar-fill" style={{ width: `${m.progress}%` }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ UPLOAD SECTION ═══ */}
      <div id="upload-section" ref={uploadRef} className="upload-section fade-in-section">
        <div className="upload-section-inner">
          {isScanning ? (
            /* Cinematic scanning experience §47 */
            <div className="scan-cinematic">
              <div className="scan-title">INITIALIZING QUANTUM ASSESSMENT</div>
              <div className="scan-steps">
                {scanSteps.map((s, i) => (
                  <div
                    key={s.label}
                    className={`scan-step ${s.done ? 'complete' : ''}`}
                    style={{ animationDelay: `${i * 0.3}s` }}
                  >
                    {s.done ? (
                      <Check size={14} className="scan-step-icon" />
                    ) : (
                      <div className="scan-step-icon pending" style={{ width: 14, height: 14, borderRadius: '50%', border: '2px solid var(--text-tertiary)' }} />
                    )}
                    {s.label}
                  </div>
                ))}
              </div>
              <div className="scan-bar-track">
                <div className="scan-bar-fill" style={{ width: `${scanProgress}%` }} />
              </div>
            </div>
          ) : (
            <>
              <div className="section-badge">START YOUR ASSESSMENT</div>
              <h2 className="section-title" style={{ textAlign: 'center' }}>
                Scan your repository.
              </h2>
              <p className="section-desc" style={{ textAlign: 'center', margin: '0 auto 0' }}>
                Upload a ZIP archive or individual source file. Everything is processed entirely in your browser.
              </p>
              <div className="upload-card">
                <div className="upload-card-header">
                  <FileCode2 size={20} className="upload-header-icon" />
                  <div>
                    <h3>Scan Your Repository</h3>
                    <p>Upload a ZIP archive or individual source file</p>
                  </div>
                </div>

                <div
                  ref={dropRef}
                  className={`drop-zone ${dragging ? 'dragging' : ''} ${fileSummary ? 'has-file' : ''}`}
                  onDragOver={onDragOver}
                  onDragLeave={onDragLeave}
                  onDrop={onDrop}
                  onClick={() => !fileSummary && fileInputRef.current?.click()}
                >
                  <input
                    ref={fileInputRef} type="file"
                    accept=".zip,.py,.java,.js,.ts,.jsx,.tsx,.go,.yml,.yaml,.json,.xml,.sh,.conf,.env,.toml,.tf"
                    style={{ display: 'none' }}
                    onChange={e => handleFiles(e.target.files)}
                  />
                  {fileSummary ? (
                    <div className="drop-zone-ready">
                      <div className="dz-file-icon">📦</div>
                      <div className="dz-file-info">
                        <span className="dz-file-name">{fileSummary.name}</span>
                        <span className="dz-file-count">{fileSummary.count} file{fileSummary.count !== 1 ? 's' : ''} ready to scan</span>
                      </div>
                      <button className="dz-change-btn" onClick={e => { e.stopPropagation(); setPendingFiles(null); setFileSummary(null); fileInputRef.current?.click(); }}>
                        Change
                      </button>
                    </div>
                  ) : (
                    <>
                      <Upload size={32} className="dz-icon" />
                      <p className="dz-primary">Drop your ZIP or source file here</p>
                      <p className="dz-secondary">or <span className="dz-link">browse files</span></p>
                      <p className="dz-hint">.zip, .py, .java, .js, .ts, .go, .yml, .json · Max 50 MB</p>
                    </>
                  )}
                </div>

                {uploadError && <div className="upload-error"><AlertCircle size={14} />{uploadError}</div>}
                {scanError && !isScanning && <div className="upload-error"><AlertCircle size={14} />{scanError}</div>}

                <button className="upload-scan-btn" onClick={handleScan} disabled={!pendingFiles || isScanning}>
                  {pendingFiles ? <><Zap size={16} /> Run Quantum Scan <ArrowRight size={16} /></> : <>Select Files to Begin</>}
                </button>

                {!pendingFiles && (
                  <div className="sample-btns">
                    <button
                      className="load-sample-btn"
                      onClick={() => { setFileSummary({ name: 'PQC-Ready Sample (85+ Score)', count: PQC_READY_SAMPLE_FILES.length }); setPendingFiles(PQC_READY_SAMPLE_FILES); }}
                      style={{ color: '#22c55e', borderColor: 'rgba(34, 197, 94, 0.3)', background: 'rgba(34, 197, 94, 0.06)' }}
                    >
                      🛡️ Load PQC-Ready Sample (85+ Score)
                    </button>
                    <button
                      className="load-sample-btn"
                      onClick={() => { setFileSummary({ name: 'Vulnerable Enterprise Sample', count: ENTERPRISE_SAMPLE_FILES.length }); setPendingFiles(ENTERPRISE_SAMPLE_FILES); }}
                      style={{ color: '#00d4ff', borderColor: 'rgba(0, 212, 255, 0.3)', background: 'rgba(0, 212, 255, 0.04)' }}
                    >
                      ⚡ Load Vulnerable Enterprise Sample
                    </button>
                  </div>
                )}

                <p className="upload-disclaimer">Files are processed entirely in your browser — no code is sent to a server.</p>
              </div>
            </>
          )}
        </div>
      </div>

      {/* ═══ ACCURACY NOTICE ═══ */}
      <div ref={accuracyRef} className="landing-section fade-in-section">
        <div className="accuracy-card">
          <div className="accuracy-icon"><Eye size={28} /></div>
          <div>
            <h3>Built on technical accuracy</h3>
            <p>
              QuantumGuard distinguishes classical security problems (MD5, SHA-1, weak TLS) from
              quantum migration concerns (RSA, ECC, ECDH). It does not claim quantum computers can
              currently break RSA, or that PQC algorithms are mathematically guaranteed to be secure.
              Every recommendation is grounded in NIST-standardized PQC algorithms (ML-KEM FIPS 203,
              ML-DSA FIPS 204, SLH-DSA FIPS 205). Your source code never leaves your browser.
            </p>
          </div>
        </div>
      </div>

      {/* ═══ FOOTER ═══ */}
      <footer className="landing-footer">
        <div className="landing-footer-logo">
          <Shield size={16} /> QuantumGuard AI
        </div>
        <span className="landing-footer-text">Post-Quantum Cryptography Readiness Platform</span>
      </footer>
    </div>
  );
}
