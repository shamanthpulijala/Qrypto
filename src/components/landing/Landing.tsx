// ============================================================
// Qrypto AI Advisor — Premium Landing Page §09-§20
// Cinematic scroll-driven editorial experience
// ============================================================

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Zap, ArrowRight, FileCode2, AlertCircle, Eye, Check, LogOut, ChevronDown, ChevronUp, FolderOpen, FileArchive } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import { useAuthStore } from '../../store/authStore';

import { SCANNER_REGISTRY } from '../../../shared/engine/scannerRegistry';
import type { ScannerCapability } from '../../../shared/engine/scannerRegistry';
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

// ─── Risk model factors §14 / §38.3 ──────────────────────────
// These show the model's weight distribution — the fill bar represents
// the relative weight of each factor, not a measured value.
//
// Colour encodes CATEGORY, not position in a rotation (§38.3):
//   · threat  — how much this factor raises exposure → severity scale
//   · context — data & architecture properties       → one muted tone
// A reader can therefore tell what kind of factor they are looking at
// without reading the label.
const RISK_FACTOR_GROUPS = [
  {
    id: 'threat',
    label: 'Threat-correlated factors',
    note: 'Scaled on the severity ramp — higher means more exposure.',
    factors: [
      { name: 'Quantum Vulnerability', pct: 30, color: 'var(--severity-critical)' },
      { name: 'Business Criticality', pct: 20, color: 'var(--severity-high)' },
      { name: 'Internet Exposure', pct: 15, color: 'var(--severity-medium)' },
    ],
  },
  {
    id: 'context',
    label: 'Data & architecture factors',
    note: 'Properties of the asset itself — one tone, because they are one kind of input.',
    factors: [
      { name: 'Confidentiality Lifetime', pct: 15, color: 'var(--accent-classical)' },
      { name: 'Data Sensitivity', pct: 10, color: 'var(--accent-classical)' },
      { name: 'Migration Difficulty', pct: 10, color: 'var(--accent-classical)' },
    ],
  },
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


const MAX_UPLOAD_SIZE = 500 * 1024 * 1024; // 500 MB per file

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

// ─── §38.2 Scanner capability card ────────────────────────────
// Every card carries the SAME subsections in the SAME order, so the
// grid reads as a comparison table rather than six differently-shaped
// blurbs. The two long fields (LIMITATIONS, METHOD) sit behind one
// consistent disclosure, which is what keeps card heights equal —
// previously some cards ran twice as long as others.
//
// Status is legible before you read the chip: PARTIAL scanners dim
// their content, so scanning the grid tells you what is production-
// ready without parsing text (§38.2).
function ScannerCard({ scanner }: { scanner: ScannerCapability }) {
  const [showConstraints, setShowConstraints] = useState(false);
  const ready = scanner.status === 'READY';

  return (
    <article className={`scanner-card ${ready ? 'is-ready' : 'is-partial'}`}>
      <header className="sc-head">
        <h3 className="sc-name">{scanner.name}</h3>
        <span className={`sc-status ${scanner.status.toLowerCase()}`}>{scanner.status}</span>
      </header>

      <p className="sc-desc">{scanner.description}</p>

      <dl className="sc-spec">
        <div className="sc-spec-row">
          <dt className="section-label">Inputs</dt>
          <dd className="sc-spec-val mono">{scanner.supportedInputs.join(' · ')}</dd>
        </div>
        <div className="sc-spec-row">
          <dt className="section-label">Detects</dt>
          <dd className="sc-spec-val">{scanner.detects}</dd>
        </div>
        <div className="sc-spec-row">
          <dt className="section-label">Does not detect</dt>
          <dd className="sc-spec-val">{scanner.doesNotDetect}</dd>
        </div>
      </dl>

      <div className="sc-foot">
        <button
          type="button"
          className="sc-disclose"
          aria-expanded={showConstraints}
          onClick={() => setShowConstraints(v => !v)}
        >
          {showConstraints ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          {showConstraints ? 'Hide constraints' : 'Constraints & method'}
        </button>

        {showConstraints && (
          <dl className="sc-spec sc-spec-extra">
            <div className="sc-spec-row">
              <dt className="section-label">Limitations</dt>
              <dd className="sc-spec-val">{scanner.limitations}</dd>
            </div>
            <div className="sc-spec-row">
              <dt className="section-label">Method</dt>
              <dd className="sc-spec-val mono">{scanner.method}</dd>
            </div>
          </dl>
        )}
      </div>
    </article>
  );
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
  const [pendingFiles, setPendingFiles] = useState<File[] | null>(null);
  const [selectedHndl, setSelectedHndl] = useState('Medical Records');

  // Fade-in refs
  const discoveryRef = useFadeIn();
  const riskRef = useFadeIn();
  const hndlRef = useFadeIn();
  const migrationRef = useFadeIn();
  const uploadRef = useFadeIn();
  const accuracyRef = useFadeIn();

  // ── File processing ────────────────────────────────────────
  // We deliberately do NOT read file contents on the main thread.
  // All extraction and scanning runs in scanner.worker.ts.
  // Here we only validate, count, and summarise.

  const SUPPORTED_EXTS_SET = new Set([
    '.zip', '.py', '.java', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs',
    '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php', '.swift', '.kt',
    '.scala', '.clj', '.yml', '.yaml', '.json', '.xml', '.sh', '.conf',
    '.cfg', '.ini', '.env', '.properties', '.gradle', '.toml', '.tf',
    '.pem', '.key', '.crt', '.p12', '.pfx', '.jks', '.dll', '.so',
    '.dylib', '.exe', '.bin', '.dockerfile',
  ]);

  const handleFiles = useCallback(async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setUploadError(null); setPendingFiles(null); setFileSummary(null);

    try {
      const MAX_FILES = 2000;
      const accepted: File[] = [];

      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        if (!file) continue;
        
        const path = file.webkitRelativePath || file.name;
        if (path.includes('node_modules/') || path.includes('.git/') || path.includes('.next/')) continue;
        
        accepted.push(file);
        if (accepted.length >= MAX_FILES) break;
      }

      if (accepted.length === 0) {
        throw new Error('No uploadable files were found in the selected folder/archive (or they were excluded).');
      }

      const summaryName =
        fileList.length === 1
          ? fileList[0].name
          : `${fileList.length} files processed (capped to ${MAX_FILES})`;

      setFileSummary({ name: summaryName, count: accepted.length });
      setPendingFiles(accepted);
    } catch (err: any) {
      setUploadError(err.message || 'Failed to read file.');
    }
  }, []);

  const handleScan = useCallback(() => {
    if (pendingFiles) startScan(pendingFiles);
  }, [pendingFiles, startScan]);

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
                <button className="btn-hero-secondary hero-user" onClick={logout}>
                  <span className="hero-user-avatar" style={{ background: user.avatarColor }}>{user.initials}</span>
                  <span className="hero-user-name">{user.name.split(' ')[0]}</span>
                  <LogOut size={14} className="hero-user-out" />
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
        <div className="scanners-grid">
          {SCANNER_REGISTRY.map(scanner => (
            <ScannerCard key={scanner.id} scanner={scanner} />
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
          {RISK_FACTOR_GROUPS.map(g => (
            <div key={g.id} className={`risk-group risk-group-${g.id}`}>
              <div className="risk-group-head">
                <span className="section-label">{g.label}</span>
                <span className="risk-group-note">{g.note}</span>
              </div>
              {g.factors.map(f => (
                <div key={f.name} className="risk-factor">
                  <span className="risk-factor-weight mono">{f.pct}%</span>
                  <span className="risk-factor-name">{f.name}</span>
                  <div className="risk-factor-bar">
                    <div className="risk-factor-bar-fill" style={{ width: `${f.pct}%`, background: f.color }} />
                  </div>
                </div>
              ))}
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
          <div className="hndl-result-figure">
            <div className="hndl-risk-label section-label">Confidentiality lifetime</div>
            {/* §38.4 — one line: figure at --text-xl, unit as a smaller
                suffix beside it, not a second display-sized line. */}
            <div className="hndl-risk-value">
              <span className="hndl-risk-num mono">{HNDL_LIFETIME_YEARS[selectedHndl]}+</span>
              <span className="hndl-risk-unit">years</span>
            </div>
          </div>
          <p className="hndl-result-text">
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
              <span className="migration-nist mono">{m.nist}</span>
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
              {/* Drag-and-drop was already implemented in this component but
                  no element consumed the handlers, so dropping a ZIP did
                  nothing. Wiring them to the card restores the behaviour
                  without touching handleFiles itself. */}
              <div
                ref={dropRef}
                className={`upload-card ${dragging ? 'dragging' : ''}`}
                onDragOver={onDragOver}
                onDragLeave={onDragLeave}
                onDrop={onDrop}
              >
                <div className="upload-card-header">
                  <FileCode2 size={20} className="upload-header-icon" />
                  <div>
                    <h3>Scan Your Codebase</h3>
                    <p>Drop a ZIP archive here, or choose a source below</p>
                  </div>
                </div>

                <div className="upload-body">
                  <div className="upload-profile section-label">Profile: Combined enterprise scan</div>

                  {fileSummary ? (
                    <div className="drop-zone-ready">
                      <FileArchive size={20} className="dz-file-icon" aria-hidden />
                      <div className="dz-file-info">
                        <span className="dz-file-name">{fileSummary.name}</span>
                        <span className="dz-file-count">{fileSummary.count} file{fileSummary.count !== 1 ? 's' : ''} ready to scan</span>
                      </div>
                      <button className="dz-change-btn" onClick={() => { setPendingFiles(null); setFileSummary(null); }}>
                        Clear
                      </button>
                    </div>
                  ) : (
                    /* §38.5 — one icon colour, one stroke width, one size.
                       Four unrelated hues here was the clearest "a machine
                       picked these" tell on the page. Colour arrives only on
                       hover, and it is the single accent, not four. */
                    <div className="upload-sources">
                      <button className="upload-source" onClick={() => handleUploadClick('file')}>
                        <FileCode2 size={20} aria-hidden />
                        <span className="us-label">File</span>
                        <span className="us-hint">Single source file</span>
                      </button>
                      <button className="upload-source" onClick={() => handleUploadClick('dir')}>
                        <FolderOpen size={20} aria-hidden />
                        <span className="us-label">Folder</span>
                        <span className="us-hint">Whole project tree</span>
                      </button>
                      <button className="upload-source" onClick={() => handleUploadClick('zip')}>
                        <FileArchive size={20} aria-hidden />
                        <span className="us-label">ZIP</span>
                        <span className="us-hint">Archive up to 500 MB</span>
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
