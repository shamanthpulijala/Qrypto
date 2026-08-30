// ============================================================
// Qrypto AI Advisor — Premium Landing Page §09-§20
// Cinematic scroll-driven editorial experience
// ============================================================

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Zap, ArrowRight, Upload, FileCode2, AlertCircle, Eye, Check, LogOut } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';
import JSZip from 'jszip';

import { SCANNER_REGISTRY } from '../../../shared/engine/scannerRegistry';
import './Landing.css';

// ─── Algorithm classification shown pre-scan §10 / §38.1 ──────
// Reference facts, presented as cards rather than as decoration
// floating around a 3D scene. §35 wording: quantum-vulnerable,
// never "already broken".
const CRYPTO_LABELS = [
  {
    name: 'RSA-2048', status: 'QUANTUM VULNERABLE', cls: 'vulnerable',
    tooltip: 'RSA relies on integer factorization, which Shor\'s algorithm can solve in polynomial time on a quantum computer.'
  },
  {
    name: 'ECC', status: 'QUANTUM VULNERABLE', cls: 'vulnerable',
    tooltip: 'Elliptic Curve Cryptography is quantum-vulnerable: Shor\'s algorithm solves the discrete logarithm problem it depends on.'
  },
  {
    name: 'ECDH', status: 'QUANTUM VULNERABLE', cls: 'vulnerable',
    tooltip: 'ECDH key exchange is vulnerable to quantum attack. Migrate to ML-KEM (FIPS 203) for post-quantum key encapsulation.'
  },
  {
    name: 'AES-256', status: 'STRONG', cls: 'strong',
    tooltip: 'AES-256 remains quantum-safe. Grover\'s algorithm only halves the effective key strength to a 128-bit equivalent.'
  },
  {
    name: 'ML-KEM', status: 'POST-QUANTUM', cls: 'pqc',
    tooltip: 'FIPS 203 (ML-KEM, formerly Kyber). NIST\'s primary post-quantum key encapsulation mechanism, based on Module-LWE.'
  },
  {
    name: 'TLS 1.2', status: 'MIGRATION REQUIRED', cls: 'migration',
    tooltip: 'TLS 1.2 is classically adequate but should move to TLS 1.3 with PQC key exchange for quantum safety.'
  },
];

// Removed old DISCOVERY_NODES in favor of actual scanner capability registry

// ─── Risk model factors §14 ──────────────────────────────────
// These show the model's weight distribution — the fill bar represents
// the relative weight of each factor, not a measured value.
const RISK_FACTORS = [
  { name: 'Quantum Vulnerability', weight: '30%', fill: 30, color: '#F5484B' },
  { name: 'Business Criticality', weight: '20%', fill: 20, color: '#FF8A3D' },
  { name: 'Internet Exposure', weight: '15%', fill: 15, color: '#F5B84D' },
  { name: 'Confidentiality Lifetime', weight: '15%', fill: 15, color: 'var(--accent-primary)' },
  { name: 'Data Sensitivity', weight: '10%', fill: 10, color: '#4DD0E1' },
  { name: 'Migration Difficulty', weight: '10%', fill: 10, color: 'var(--accent-classical)' },
];

// ─── Migration transforms §18 ────────────────────────────────
// These show recommended algorithm transitions, not measured progress.
const MIGRATIONS = [
  { from: 'RSA-2048', to: 'ML-KEM (FIPS 203) / Hybrid', nist: 'FIPS 203' },
  { from: 'ECDSA / RSA Sig', to: 'ML-DSA (FIPS 204)', nist: 'FIPS 204' },
  { from: 'TLS 1.0 / 1.1', to: 'TLS 1.3', nist: 'RFC 8446' },
  { from: 'SHA-1', to: 'SHA-256 / SHA-3', nist: 'FIPS 180-4 / FIPS 202' },
  { from: 'Hardcoded Keys', to: 'Managed Secrets Vault', nist: '—' },
];

// ─── HNDL data categories §16 ────────────────────────────────
const HNDL_CATEGORIES = ['Medical Records', 'Financial Records', 'Government Data', 'Source Code', 'Customer Data', 'Intellectual Property'];
// HNDL risk is derived from data lifetime requirements.
// These are illustrative ranges based on typical confidentiality periods,
// not measured values from a specific scan.
const HNDL_LIFETIME_YEARS: Record<string, number> = {
  'Medical Records': 25, 'Financial Records': 15, 'Government Data': 25,
  'Source Code': 10, 'Customer Data': 10, 'Intellectual Property': 20,
};

const SUPPORTED_EXT = ['.zip', '.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go', '.yml', '.yaml', '.json', '.xml', '.sh', '.conf', '.env', '.properties', '.gradle', '.toml', '.tf', '.pem', '.key', '.crt', '.p12', '.pfx', '.jks', '.dll', '.so', '.dylib', '.exe', '.bin', '.dockerfile'];
const MAX_UPLOAD_SIZE = 500 * 1024 * 1024;
const MAX_FILES = 2000;

function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 MB';
  const mb = bytes / (1024 * 1024);
  return mb >= 1 ? `${mb.toFixed(1)} MB` : `${(bytes / 1024).toFixed(1)} KB`;
}

async function readFileText(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const decoder = new TextDecoder('utf-8', { fatal: false });
  return decoder.decode(bytes).replace(/\u0000/g, '');
}

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
  const navigate = useNavigate();
  const { startScan, isScanning, scanProgress, scanLog, scanError, setCurrentPage } = useAppStore();
  const { openLoginModal, user, logout } = useAuthStore();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dirInputRef = useRef<HTMLInputElement>(null);
  const dropRef = useRef<HTMLDivElement>(null);

  const [dragging, setDragging] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [fileSummary, setFileSummary] = useState<{ name: string; count: number } | null>(null);
  const [pendingFiles, setPendingFiles] = useState<FileEntry[] | null>(null);
  const [selectedHndl, setSelectedHndl] = useState('Medical Records');

  // Fade-in refs
  const discoveryRef = useFadeIn();
  const riskRef = useFadeIn();
  const hndlRef = useFadeIn();
  const migrationRef = useFadeIn();
  const uploadRef = useFadeIn();
  const accuracyRef = useFadeIn();

  // ── File processing ──
  interface FileEntry {
    path: string;
    content: string;
    zipFile?: File;
    projectName?: string;
  }

  const processZip = useCallback(async (file: File): Promise<FileEntry[]> => {
    if (file.size > MAX_UPLOAD_SIZE) throw new Error(`ZIP file too large (max 500 MB). Got ${formatFileSize(file.size)}.`);
    const zip = await JSZip.loadAsync(file);
    const entries: FileEntry[] = [];
    const jobs: Promise<void>[] = [];
    zip.forEach((relativePath, zipEntry) => {
      if (zipEntry.dir) return;
      if (relativePath.includes('..')) return;
      const lower = relativePath.toLowerCase();
      const isContainerConfig = lower.includes('dockerfile') || lower.includes('compose');
      const isSupported = SUPPORTED_EXT.some(ext => lower.endsWith(ext)) || isContainerConfig || !lower.includes('.') || lower.endsWith('.zip');
      if (!isSupported) return;
      if (entries.length >= MAX_FILES) return;
      jobs.push(zipEntry.async('string').then(content => { entries.push({ path: relativePath, content }); }).catch(() => { }));
    });
    await Promise.all(jobs);
    if (entries.length === 0) throw new Error('No uploadable files were found in the ZIP.');
    if (entries.length > 0) {
      entries[0].zipFile = file;
      entries[0].projectName = file.name.replace(/\.zip$/i, '');
    }
    return entries;
  }, []);

  const handleFiles = useCallback(async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setUploadError(null); setPendingFiles(null); setFileSummary(null);

    try {
      const files = Array.from(fileList);
      const allEntries: FileEntry[] = [];
      let summaryName = files.length === 1 ? files[0].name : `${files.length} selected files`;

      for (const file of files) {
        if (file.size > MAX_UPLOAD_SIZE) {
          throw new Error(`${file.name} exceeds the 500 MB upload limit.`);
        }

        let entries: FileEntry[];
        if (file.name.toLowerCase().endsWith('.zip')) {
          entries = await processZip(file);
        } else {
          const fileName = file.name.toLowerCase();
          const ext = '.' + fileName.split('.').pop()?.toLowerCase();
          const isApplicable = SUPPORTED_EXT.includes(ext) || fileName.includes('dockerfile') || fileName.includes('compose') || !ext || !fileName.includes('.');
          if (!isApplicable) {
            continue;
          }
          entries = [{ path: file.name, content: await readFileText(file) }];
        }
        allEntries.push(...entries);
      }

      if (allEntries.length === 0) {
        throw new Error('No uploadable files were found in the selected files.');
      }

      setFileSummary({ name: summaryName, count: allEntries.length });
      setPendingFiles(allEntries);
    } catch (err: any) {
      setUploadError(err.message || 'Failed to read file.');
    }
  }, [processZip]);

  const handleScan = useCallback(() => { if (pendingFiles) startScan(pendingFiles); }, [pendingFiles, startScan]);

  const handleUploadClick = useCallback((type: 'file' | 'dir' | 'zip') => {
    if (!user) {
      openLoginModal('login');
      return;
    }
    if (type === 'file' || type === 'zip') fileInputRef.current?.click();
    else if (type === 'dir') dirInputRef.current?.click();
  }, [user, openLoginModal]);

  // ── Drag and drop ──
  const onDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); setDragging(true); }, []);
  const onDragLeave = useCallback(() => setDragging(false), []);
  const onDrop = useCallback((e: React.DragEvent) => { 
    e.preventDefault(); 
    setDragging(false); 
    if (!useAuthStore.getState().user) {
      openLoginModal('login');
      return;
    }
    handleFiles(e.dataTransfer.files); 
  }, [handleFiles, openLoginModal]);

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
              Qrypto AI Advisor
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
                setCurrentPage('qday');
                navigate('/qday');
              }}>
                EXPLORE Q-DAY <Zap size={16} />
              </button>
              {user && (
                <button className="btn-hero-secondary" style={{ gap: '10px', background: 'rgba(255, 255, 255, 0.05)', borderColor: 'rgba(255, 255, 255, 0.1)', color: '#f1f5f9' }} onClick={logout}>
                  <span style={{ width: 24, height: 24, borderRadius: '50%', background: user.avatarColor, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', fontWeight: 800, color: '#fff', flexShrink: 0, boxShadow: '0 2px 4px rgba(0,0,0,0.2)' }}>{user.initials}</span>
                  <span style={{ fontWeight: 600 }}>{user.name.split(' ')[0]}</span>
                  <LogOut size={14} style={{ opacity: 0.6, marginLeft: '4px' }} />
                </button>
              )}
            </div>              <div className="hero-stats">
              <div className="hero-stat">
                <span className="hero-stat-value">71</span>
                <span className="hero-stat-label">Detection Patterns</span>
              </div>
              <div className="hero-stat">
                <span className="hero-stat-value">8</span>
                <span className="hero-stat-label">File Types</span>
              </div>
              <div className="hero-stat">
                <span className="hero-stat-value">FIPS 203–205</span>
                <span className="hero-stat-label">NIST PQC Standards</span>
              </div>
            </div>
          </div>

          {/* §38.1 — Real algorithm classification panel.
              This replaced a decorative orbiting-particles WebGL scene.
              Every card states a verifiable property of the algorithm and
              the reason for its classification. It is reference material,
              not scan output, and says so (§3). */}
          <div className="hero-algo-panel">
            <div className="hero-algo-head">
              <span className="section-label">Algorithm classification</span>
              <span className="provenance provenance-none" title="Reference classification from NIST guidance — not results from your repository">
                Reference · not scan data
              </span>
            </div>
            <div className="hero-algo-grid">
              {CRYPTO_LABELS.map(l => (
                <div key={l.name} className={`hero-algo-card ${l.cls}`}>
                  <div className="hac-top">
                    <span className="hac-name mono">{l.name}</span>
                    <span className={`hac-status ${l.cls}`}>{l.status}</span>
                  </div>
                  <p className="hac-why">{l.tooltip}</p>
                </div>
              ))}
            </div>
            <p className="hero-algo-foot">
              Upload a repository to replace this reference set with your own
              cryptographic inventory.
            </p>
          </div>
        </div>
      </section>

      {/* ═══ AVAILABLE SCANNERS ═══ */}
      <div ref={discoveryRef} className="landing-section fade-in-section">
        <div className="section-badge danger">AVAILABLE SCANNERS</div>
        <h2 className="section-title">
          KNOW EXACTLY<br />WHAT WE CAN SEE.
        </h2>
        <p className="section-desc">
          Qrypto maps your cryptographic dependencies across multiple dimensions. Here is what is currently supported.
        </p>
        <div className="scanners-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px', marginTop: '40px' }}>
          {SCANNER_REGISTRY.map(scanner => (
            <div key={scanner.id} className="scanner-card" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '12px', padding: '24px', display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ margin: 0, fontSize: '1.2rem', color: 'var(--text-primary)' }}>{scanner.name}</h3>
                <span className={`scanner-status ${scanner.status.toLowerCase()}`} style={{ fontSize: '0.7rem', padding: '4px 8px', borderRadius: '4px', background: scanner.status === 'READY' ? 'rgba(76, 175, 109, 0.1)' : 'rgba(245, 184, 77, 0.1)', color: scanner.status === 'READY' ? '#4CAF6D' : '#F5B84D' }}>
                  {scanner.status}
                </span>
              </div>
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>{scanner.description}</p>
              
              <div style={{ marginTop: 'auto' }}>
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '4px' }}>Inputs</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{scanner.supportedInputs.join(', ')}</div>
                </div>
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '4px' }}>Detects</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{scanner.detects}</div>
                </div>
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '4px' }}>Does Not Detect</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{scanner.doesNotDetect}</div>
                </div>
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '4px' }}>Limitations</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{scanner.limitations}</div>
                </div>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '4px' }}>Method</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{scanner.method}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ RISK MODEL §14 ═══ */}
      <div ref={riskRef} className="landing-section fade-in-section">
        <div className="section-badge">Qrypto RISK MODEL</div>
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
            <div className="hndl-risk-label">CONFIDENTIALITY LIFETIME</div>
            <div className="hndl-risk-value">{HNDL_LIFETIME_YEARS[selectedHndl]}+ years</div>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {selectedHndl} typically requires {HNDL_LIFETIME_YEARS[selectedHndl]}+ years of confidentiality.
            If protected by quantum-vulnerable algorithms (RSA, ECC), data intercepted today
            may be decryptable when cryptographically relevant quantum computers arrive.
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
          Qrypto generates step-by-step migration paths aligned with NIST FIPS 203, 204, and 205.
        </p>
        <div className="migration-transforms">
          {MIGRATIONS.map(m => (
            <div key={m.from} className="migration-row">
              <span className="migration-from">{m.from}</span>
              <span className="migration-arrow">→</span>
              <span className="migration-to">{m.to}</span>
              <span className="migration-nist" style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)' }}>{m.nist}</span>
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

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', margin: '24px 0' }}>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '1px' }}>Profile: COMBINED ENTERPRISE SCAN</div>
                  
                  {fileSummary ? (
                    <div className="drop-zone-ready" style={{ border: '1px solid var(--border)', borderRadius: '8px', padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div className="dz-file-icon" style={{ fontSize: '1.5rem' }}>📦</div>
                        <div className="dz-file-info" style={{ display: 'flex', flexDirection: 'column' }}>
                          <span className="dz-file-name" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{fileSummary.name}</span>
                          <span className="dz-file-count" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{fileSummary.count} file{fileSummary.count !== 1 ? 's' : ''} ready to scan</span>
                        </div>
                      </div>
                      <button className="dz-change-btn" style={{ background: 'rgba(255,255,255,0.05)', border: 'none', padding: '6px 12px', borderRadius: '6px', color: 'var(--text-secondary)', cursor: 'pointer' }} onClick={() => { setPendingFiles(null); setFileSummary(null); }}>
                        Clear
                      </button>
                    </div>
                  ) : (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px' }}>
                      <button className="cta-select-btn" onClick={() => handleUploadClick('file')} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', padding: '16px', borderRadius: '8px', cursor: 'pointer', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
                        <FileCode2 size={24} color="#6366f1" />
                        <span>📄 FILE</span>
                      </button>
                      <button className="cta-select-btn" onClick={() => handleUploadClick('dir')} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', padding: '16px', borderRadius: '8px', cursor: 'pointer', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
                        <Upload size={24} color="#4CAF6D" />
                        <span>📁 FOLDER</span>
                      </button>
                      <button className="cta-select-btn" onClick={() => handleUploadClick('zip')} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', padding: '16px', borderRadius: '8px', cursor: 'pointer', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
                        <Upload size={24} color="#F5B84D" />
                        <span>📦 ZIP</span>
                      </button>
                      <button className="cta-select-btn" onClick={() => alert('Repository integration requires backend authentication. Local mode active.')} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', padding: '16px', borderRadius: '8px', cursor: 'pointer', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
                        <Shield size={24} color="#F5484B" />
                        <span>🌐 REPOSITORY</span>
                      </button>
                    </div>
                  )}

                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept=".zip,.tar,.gz,.tgz,.bz2,.xz,.7z,.rar,.py,.java,.js,.ts,.jsx,.tsx,.go,.rs,.c,.cpp,.h,.hpp,.cs,.rb,.php,.swift,.kt,.scala,.clj,.yml,.yaml,.json,.xml,.sh,.conf,.cfg,.ini,.env,.properties,.gradle,.toml,.tf,.pem,.key,.crt,.cer,.p12,.pfx,.jks,.dll,.so,.dylib,.exe,.bin,.obj,.o,.a,.class,.jar,.war,.ear,.txt,.md,.rst,.log,.csv,.sql,.dockerfile,.dockerignore,.zip,.*"
                    style={{ display: 'none' }}
                    onChange={e => handleFiles(e.target.files)}
                  />
                  <input
                    ref={dirInputRef}
                    type="file"
                    /* @ts-expect-error React types don't officially support directory attributes on inputs, but browsers do */
                    webkitdirectory=""
                    directory=""
                    multiple
                    style={{ display: 'none' }}
                    onChange={e => handleFiles(e.target.files)}
                  />
                </div>

                {uploadError && <div className="upload-error"><AlertCircle size={14} />{uploadError}</div>}
                {scanError && !isScanning && <div className="upload-error"><AlertCircle size={14} />{scanError}</div>}

                <button className="upload-scan-btn" onClick={handleScan} disabled={!pendingFiles || isScanning}>
                  {pendingFiles ? <><Zap size={16} /> Run Quantum Scan <ArrowRight size={16} /></> : <>Select Files to Begin</>}
                </button>


                <p className="upload-disclaimer">In browser-only mode, file contents are processed locally. When a backend is configured, scan metadata (file paths, line numbers, detected patterns) may be transmitted for persistence and reporting.</p>
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
              Qrypto distinguishes classical security problems (MD5, SHA-1, weak TLS) from
              quantum migration concerns (RSA, ECC, ECDH). It does not claim quantum computers can
              currently break RSA, or that PQC algorithms are mathematically guaranteed to be secure.
              Every recommendation is grounded in NIST-standardized PQC algorithms (ML-KEM FIPS 203,
              ML-DSA FIPS 204, SLH-DSA FIPS 205). In browser-only mode, all processing is local.
            </p>
          </div>
        </div>
      </div>

      {/* ═══ FOOTER ═══ */}
      <footer className="landing-footer">
        <div className="landing-footer-logo">
          <Shield size={16} /> Qrypto AI Advisor
        </div>
        <span className="landing-footer-text">Post-Quantum Cryptography Readiness Platform</span>
      </footer>
    </div>
  );
}
