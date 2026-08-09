import React, { useState, useRef, useEffect } from 'react';
import { Shield, Mail, Lock, Eye, EyeOff, X, LogIn, AlertCircle } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';
import './LoginModal.css';

export function LoginModal() {
  const { showLoginModal, closeLoginModal, login, loginError } = useAuthStore();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (showLoginModal) {
      setEmail('');
      setPassword('');
      setLoading(false);
      setTimeout(() => emailRef.current?.focus(), 100);
    }
  }, [showLoginModal]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setLoading(true);
    // Tiny delay for UX feel
    await new Promise(r => setTimeout(r, 400));
    login(email, password);
    setLoading(false);
  };

  const fillDemo = (demoEmail: string, demoPassword: string) => {
    setEmail(demoEmail);
    setPassword(demoPassword);
  };

  if (!showLoginModal) return null;

  return (
    <div className="login-overlay" onClick={closeLoginModal}>
      <div className="login-modal" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="login-header">
          <div className="login-logo">
            <Shield size={22} />
            <span>Qrypto</span>
          </div>
          <button className="login-close" onClick={closeLoginModal}><X size={16} /></button>
        </div>

        <div className="login-body">
          <h2>Welcome back</h2>
          <p className="login-subtitle">Sign in to your security workspace</p>

          <form onSubmit={handleSubmit} className="login-form">
            <div className="login-field">
              <label>Email</label>
              <div className="login-input-wrap">
                <Mail size={15} className="login-input-icon" />
                <input
                  ref={emailRef}
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                />
              </div>
            </div>

            <div className="login-field">
              <label>Password</label>
              <div className="login-input-wrap">
                <Lock size={15} className="login-input-icon" />
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                />
                <button type="button" className="login-pw-toggle" onClick={() => setShowPw(v => !v)}>
                  {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {loginError && (
              <div className="login-error">
                <AlertCircle size={13} /> {loginError}
              </div>
            )}

            <button type="submit" className="login-submit" disabled={loading || !email || !password}>
              {loading ? (
                <span className="login-spinner" />
              ) : (
                <><LogIn size={15} /> Sign In</>
              )}
            </button>
          </form>

          {/* Demo credentials */}
          <div className="login-demo">
            <span className="login-demo-title">Demo accounts</span>
            <div className="login-demo-accounts">
              {[
                { label: 'Security Lead', email: 'admin@quantumguard.ai', pw: 'quantum2024' },
                { label: 'Analyst', email: 'security@example.com', pw: 'password123' },
                { label: 'CISO', email: 'ciso@example.com', pw: 'password123' },
              ].map(a => (
                <button
                  key={a.email}
                  className="login-demo-btn"
                  onClick={() => fillDemo(a.email, a.pw)}
                  type="button"
                >
                  <span className="demo-role">{a.label}</span>
                  <span className="demo-email">{a.email}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
