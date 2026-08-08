import React, { useEffect, useRef } from 'react';
import { Shield, Zap, ArrowRight, ChevronDown, Search, BarChart3, Network, Bot, Lock, Eye, AlertTriangle } from 'lucide-react';
import { useAppStore } from '../../store/assessmentStore';
import './Landing.css';

const FEATURES = [
  { icon: Search, title: 'Cryptographic Discovery', desc: 'Scan source code, configs, and infrastructure for cryptographic assets across Python, Java, JavaScript, and more.', color: '#00d4ff' },
  { icon: BarChart3, title: 'Quantum Risk Intelligence', desc: 'Transparent, deterministic risk scoring with component-level breakdown — no black-box scores.', color: '#8b5cf6' },
  { icon: Zap, title: 'Q-Day Simulation', desc: 'Simulate your organization\'s exposure if quantum-relevant capabilities threatened current public-key cryptography.', color: '#ef4444' },
  { icon: Network, title: 'Attack Path Analysis', desc: 'Interactive dependency graph showing how quantum vulnerability propagates through your architecture.', color: '#f97316' },
  { icon: Bot, title: 'AI Security Consultant', desc: 'Grounded AI advisor that cites actual findings and provides actionable migration guidance.', color: '#22c55e' },
  { icon: Lock, title: 'Crypto Agility Score', desc: 'Evaluate how easily your organization can replace cryptographic algorithms as standards evolve.', color: '#14b8a6' },
];

const WORKFLOW_STEPS = [
  { num: '01', title: 'Discover', desc: 'Upload code or analyze a sample repository to detect all cryptographic usage' },
  { num: '02', title: 'Inventory', desc: 'Build a Cryptographic Bill of Materials (CBOM) with full context for every finding' },
  { num: '03', title: 'Evaluate', desc: 'Score each finding with a transparent, multi-factor quantum risk formula' },
  { num: '04', title: 'Simulate', desc: 'Run Q-Day scenarios to understand your exposure under various assumptions' },
  { num: '05', title: 'Plan', desc: 'Generate a prioritized, phased migration roadmap with effort estimates' },
  { num: '06', title: 'Remediate', desc: 'Get AI-generated code migration examples and track your progress to quantum readiness' },
];

export function Landing() {
  const { loadDemoAssessment, setCurrentPage, isScanning } = useAppStore();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    const particles: Array<{ x: number; y: number; vx: number; vy: number; size: number; opacity: number }> = [];
    for (let i = 0; i < 60; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        size: Math.random() * 2 + 0.5,
        opacity: Math.random() * 0.4 + 0.1,
      });
    }

    let animId: number;
    function draw() {
      if (!ctx || !canvas) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = canvas!.width;
        if (p.x > canvas!.width) p.x = 0;
        if (p.y < 0) p.y = canvas!.height;
        if (p.y > canvas!.height) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 212, 255, ${p.opacity})`;
        ctx.fill();
      });

      // Draw connections
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 100) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(0, 212, 255, ${0.1 * (1 - dist / 100)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }

      animId = requestAnimationFrame(draw);
    }

    draw();

    const handleResize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    window.addEventListener('resize', handleResize);
    return () => { cancelAnimationFrame(animId); window.removeEventListener('resize', handleResize); };
  }, []);

  return (
    <div className="landing">
      {/* Hero */}
      <section className="hero">
        <canvas ref={canvasRef} className="hero-canvas" />
        <div className="hero-content">
          <div className="hero-badge">
            <Shield size={12} />
            QUANTUM READINESS PLATFORM
          </div>
          <h1 className="hero-title">
            Know what breaks
            <span className="hero-accent"> before </span>
            quantum does.
          </h1>
          <p className="hero-subtitle">
            Discover cryptography. Measure quantum exposure. Simulate Q-Day.
            Build your migration roadmap. Become quantum ready.
          </p>
          <div className="hero-actions">
            <button
              className="btn btn-primary btn-lg"
              onClick={loadDemoAssessment}
              disabled={isScanning}
            >
              {isScanning ? 'Loading...' : <>Start Quantum Assessment <ArrowRight size={18} /></>}
            </button>
            <button
              className="btn btn-ghost btn-lg"
              onClick={() => {
                document.getElementById('how-it-works')?.scrollIntoView({ behavior: 'smooth' });
              }}
            >
              Explore Demo <ChevronDown size={18} />
            </button>
          </div>

          {/* Stats */}
          <div className="hero-stats">
            <div className="hero-stat">
              <span className="hero-stat-value">15</span>
              <span className="hero-stat-label">Feature Modules</span>
            </div>
            <div className="hero-stat">
              <span className="hero-stat-value">58+</span>
              <span className="hero-stat-label">Detection Patterns</span>
            </div>
            <div className="hero-stat">
              <span className="hero-stat-value">FIPS 203–205</span>
              <span className="hero-stat-label">NIST PQC Standards</span>
            </div>
          </div>
        </div>

        {/* Dashboard Preview */}
        <div className="hero-preview">
          <div className="preview-card">
            <div className="preview-header">
              <div className="preview-dot red" />
              <div className="preview-dot yellow" />
              <div className="preview-dot green" />
              <span className="preview-title">QuantumGuard AI — Dashboard</span>
            </div>
            <div className="preview-body">
              <div className="preview-gauge">
                <div className="gauge-circle">
                  <svg viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="40" fill="none" stroke="#1e2d4a" strokeWidth="8"/>
                    <circle cx="50" cy="50" r="40" fill="none" stroke="#00d4ff" strokeWidth="8"
                      strokeDasharray="164" strokeDashoffset="42" strokeLinecap="round"
                      transform="rotate(-90 50 50)" />
                  </svg>
                  <div className="gauge-label">
                    <span className="gauge-value">74</span>
                    <span className="gauge-sub">/ 100</span>
                  </div>
                </div>
                <p className="gauge-title">Quantum Readiness</p>
              </div>
              <div className="preview-grid">
                <div className="preview-stat critical">
                  <span className="pstat-value">12</span>
                  <span className="pstat-label">Critical</span>
                </div>
                <div className="preview-stat high">
                  <span className="pstat-value">23</span>
                  <span className="pstat-label">High Risk</span>
                </div>
                <div className="preview-stat warn">
                  <span className="pstat-value">37</span>
                  <span className="pstat-label">Quantum Vuln</span>
                </div>
                <div className="preview-stat ok">
                  <span className="pstat-value">41%</span>
                  <span className="pstat-label">PQC Progress</span>
                </div>
              </div>
              <button className="preview-btn">⚡ SIMULATE Q-DAY</button>
            </div>
          </div>
        </div>
      </section>

      {/* Problem Section */}
      <section className="problem-section">
        <div className="section-content">
          <div className="section-badge danger">THE CHALLENGE</div>
          <h2>Your cryptography is everywhere.<br />Do you know where?</h2>
          <p className="section-desc">
            Organizations have cryptographic assets scattered across source code, certificates, APIs,
            dependencies, and infrastructure. Most don't know which algorithms are quantum-vulnerable,
            which systems are highest priority, or what a migration path should look like.
          </p>
          <div className="problem-grid">
            {[
              { q: 'Where is cryptography being used?', icon: '🔍' },
              { q: 'Which algorithms are quantum-vulnerable?', icon: '⚠️' },
              { q: 'Which assets are most business-critical?', icon: '💼' },
              { q: 'What is our HNDL exposure?', icon: '📦' },
              { q: 'What should we migrate first?', icon: '🎯' },
              { q: 'How difficult is migration?', icon: '🛠️' },
              { q: 'Are we crypto-agile?', icon: '🔄' },
              { q: 'What is our quantum readiness?', icon: '📊' },
            ].map(item => (
              <div key={item.q} className="problem-item">
                <span className="problem-icon">{item.icon}</span>
                <span>{item.q}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="workflow-section">
        <div className="section-content">
          <div className="section-badge">HOW IT WORKS</div>
          <h2>From discovery to quantum readiness</h2>
          <p className="section-desc">A complete end-to-end workflow — not just a scanner.</p>
          <div className="workflow-grid">
            {WORKFLOW_STEPS.map((step, i) => (
              <div key={step.num} className="workflow-step">
                <div className="step-num">{step.num}</div>
                <h4>{step.title}</h4>
                <p>{step.desc}</p>
                {i < WORKFLOW_STEPS.length - 1 && <div className="step-arrow">→</div>}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="features-section">
        <div className="section-content">
          <div className="section-badge">CAPABILITIES</div>
          <h2>Everything you need for quantum migration</h2>
          <div className="features-grid">
            {FEATURES.map(f => {
              const Icon = f.icon;
              return (
                <div key={f.title} className="feature-card" style={{ '--accent-color': f.color } as React.CSSProperties}>
                  <div className="feature-icon" style={{ color: f.color, background: `${f.color}18`, border: `1px solid ${f.color}33` }}>
                    <Icon size={22} />
                  </div>
                  <h4>{f.title}</h4>
                  <p>{f.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Accuracy Notice */}
      <section className="accuracy-section">
        <div className="section-content">
          <div className="accuracy-card">
            <div className="accuracy-icon"><Eye size={28} /></div>
            <div>
              <h3>Built on technical accuracy</h3>
              <p>
                QuantumGuard AI distinguishes classical security problems (MD5, SHA-1, weak TLS) from
                quantum migration concerns (RSA, ECC, ECDH). It does not claim quantum computers can
                currently break RSA, or that PQC algorithms are mathematically guaranteed to be secure.
                Every recommendation is grounded in NIST-standardized PQC algorithms (ML-KEM FIPS 203,
                ML-DSA FIPS 204, SLH-DSA FIPS 205) and accurate security context.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="cta-section">
        <div className="section-content">
          <h2>Ready to assess your quantum exposure?</h2>
          <p className="section-desc">Start with the FinTech Corp demo — no setup required.</p>
          <div className="cta-actions">
            <button className="btn btn-primary btn-lg" onClick={loadDemoAssessment}>
              Start Quantum Assessment <ArrowRight size={18} />
            </button>
          </div>
          <p className="cta-note">
            Demo uses synthetic FinTech Corp data. Upload your own ZIP for real scanning.
          </p>
        </div>
      </section>
    </div>
  );
}
