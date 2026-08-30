import React, { useState, useRef, useEffect } from 'react';
import { Shield, Mail, Lock, Eye, EyeOff, X, LogIn, UserPlus, AlertCircle, User } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';
import './LoginModal.css';

export function LoginModal() {
  const {
    showLoginModal, closeLoginModal,
    login, register,
    loginError, registerError,
    authMode, setAuthMode,
    isLoading,
  } = useAuthStore();

  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showLoginPw, setShowLoginPw] = useState(false);

  // Register fields
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regConfirm, setRegConfirm] = useState('');
  const [showRegPw, setShowRegPw] = useState(false);
  const [showRegConfirm, setShowRegConfirm] = useState(false);
  const [clientError, setClientError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);

  const firstInputRef = useRef<HTMLInputElement>(null);

  // Reset state when modal opens
  useEffect(() => {
    if (showLoginModal) {
      setLoginEmail(''); setLoginPassword(''); setShowLoginPw(false);
      setRegName(''); setRegEmail(''); setRegPassword(''); setRegConfirm('');
      setShowRegPw(false); setShowRegConfirm(false); setClientError(null); setShake(false);
      setTimeout(() => firstInputRef.current?.focus(), 150);
    }
  }, [showLoginModal]);

  // Reset fields when switching tabs
  useEffect(() => {
    setClientError(null);
    setTimeout(() => firstInputRef.current?.focus(), 100);
  }, [authMode]);

  // Shake on error
  const currentError = authMode === 'login' ? loginError : (registerError || clientError);
  useEffect(() => {
    if (currentError) {
      setShake(true);
      const t = setTimeout(() => setShake(false), 500);
      return () => clearTimeout(t);
    }
  }, [currentError]);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginEmail || !loginPassword) return;
    await login(loginEmail, loginPassword);
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setClientError(null);
    if (!regName.trim()) { setClientError('Please enter your full name.'); return; }
    if (!regEmail) { setClientError('Please enter your email address.'); return; }
    if (regPassword.length < 6) { setClientError('Password must be at least 6 characters.'); return; }
    if (regPassword !== regConfirm) { setClientError('Passwords do not match.'); return; }
    await register(regName.trim(), regEmail, regPassword);
  };

  if (!showLoginModal) return null;

  return (
    <div className="login-overlay" onClick={closeLoginModal}>
      <div className={`login-modal ${shake ? 'error-shake' : ''}`} onClick={e => e.stopPropagation()}>

        {/* Close */}
        <button className="login-close" onClick={closeLoginModal} aria-label="Close">
          <X size={18} />
        </button>

        {/* Logo */}
        <div className="login-header">
          <div className="login-logo">
            <Shield size={24} className="logo-icon" />
            <span>Qrypto</span>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="auth-tabs">
          <button
            className={`auth-tab ${authMode === 'login' ? 'active' : ''}`}
            onClick={() => setAuthMode('login')}
          >
            <LogIn size={15} /> Sign In
          </button>
          <button
            className={`auth-tab ${authMode === 'register' ? 'active' : ''}`}
            onClick={() => setAuthMode('register')}
          >
            <UserPlus size={15} /> Create Account
          </button>
          <div className={`auth-tab-indicator ${authMode === 'register' ? 'right' : ''}`} />
        </div>

        <div className="login-body">

          {/* ── LOGIN FORM ── */}
          {authMode === 'login' && (
            <div className="auth-panel">
              <h2>Welcome back</h2>
              <p className="login-subtitle">Sign in to your security workspace</p>

              <form onSubmit={handleLoginSubmit} className="login-form">
                <div className="login-input-wrap">
                  <input
                    ref={firstInputRef}
                    type="email"
                    value={loginEmail}
                    onChange={e => setLoginEmail(e.target.value)}
                    placeholder=" "
                    autoComplete="email"
                    required
                  />
                  <Mail size={18} className="login-input-icon" />
                  <label>Email Address</label>
                </div>

                <div className="login-input-wrap">
                  <input
                    type={showLoginPw ? 'text' : 'password'}
                    value={loginPassword}
                    onChange={e => setLoginPassword(e.target.value)}
                    placeholder=" "
                    autoComplete="current-password"
                    required
                  />
                  <Lock size={18} className="login-input-icon" />
                  <label>Password</label>
                  <button type="button" className="login-pw-toggle" onClick={() => setShowLoginPw(v => !v)} tabIndex={-1}>
                    {showLoginPw ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                {loginError && (
                  <div className="login-error"><AlertCircle size={16} /><span>{loginError}</span></div>
                )}

                <button type="submit" className="login-submit" disabled={isLoading || !loginEmail || !loginPassword}>
                  {isLoading ? <span className="login-spinner" /> : <><LogIn size={18} /> Sign In</>}
                </button>
              </form>

              <p className="auth-switch-hint">
                Don't have an account?{' '}
                <button className="auth-switch-link" onClick={() => setAuthMode('register')}>Create one</button>
              </p>
            </div>
          )}

          {/* ── REGISTER FORM ── */}
          {authMode === 'register' && (
            <div className="auth-panel">
              <h2>Create account</h2>
              <p className="login-subtitle">Start your quantum security assessment</p>

              <form onSubmit={handleRegisterSubmit} className="login-form">
                <div className="login-input-wrap">
                  <input
                    ref={firstInputRef}
                    type="text"
                    value={regName}
                    onChange={e => setRegName(e.target.value)}
                    placeholder=" "
                    autoComplete="name"
                    required
                  />
                  <User size={18} className="login-input-icon" />
                  <label>Full Name</label>
                </div>

                <div className="login-input-wrap">
                  <input
                    type="email"
                    value={regEmail}
                    onChange={e => setRegEmail(e.target.value)}
                    placeholder=" "
                    autoComplete="email"
                    required
                  />
                  <Mail size={18} className="login-input-icon" />
                  <label>Email Address</label>
                </div>

                <div className="login-input-wrap">
                  <input
                    type={showRegPw ? 'text' : 'password'}
                    value={regPassword}
                    onChange={e => setRegPassword(e.target.value)}
                    placeholder=" "
                    autoComplete="new-password"
                    required
                    minLength={6}
                  />
                  <Lock size={18} className="login-input-icon" />
                  <label>Password</label>
                  <button type="button" className="login-pw-toggle" onClick={() => setShowRegPw(v => !v)} tabIndex={-1}>
                    {showRegPw ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                <div className="login-input-wrap">
                  <input
                    type={showRegConfirm ? 'text' : 'password'}
                    value={regConfirm}
                    onChange={e => setRegConfirm(e.target.value)}
                    placeholder=" "
                    autoComplete="new-password"
                    required
                  />
                  <Lock size={18} className="login-input-icon" />
                  <label>Confirm Password</label>
                  <button type="button" className="login-pw-toggle" onClick={() => setShowRegConfirm(v => !v)} tabIndex={-1}>
                    {showRegConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                {(registerError || clientError) && (
                  <div className="login-error">
                    <AlertCircle size={16} /><span>{registerError || clientError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  className="login-submit"
                  disabled={isLoading || !regName || !regEmail || !regPassword || !regConfirm}
                >
                  {isLoading ? <span className="login-spinner" /> : <><UserPlus size={18} /> Create Account</>}
                </button>
              </form>

              <p className="auth-switch-hint">
                Already have an account?{' '}
                <button className="auth-switch-link" onClick={() => setAuthMode('login')}>Sign in</button>
              </p>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
