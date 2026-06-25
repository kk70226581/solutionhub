// src/pages/Login.jsx
import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import '../styles/Login.css';
import {
  getGoogleClientId,
  loadGoogleIdentityScript,
  saveAuthSession,
} from '../utils/googleAuth';

// ✅ Base API root from Vite env (e.g. VITE_API_BASE=https://solutionhub66.onrender.com)
const API = import.meta.env.VITE_API_BASE || 'https://solutionhub66.onrender.com';

const Login = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotMsg, setForgotMsg] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [resetMsg, setResetMsg] = useState('');
  const [googleError, setGoogleError] = useState('');

  const hasWindow = typeof window !== 'undefined';

  const token = hasWindow ? localStorage.getItem('token') : null;
  const role = hasWindow ? localStorage.getItem('role') : null;
  const normalizedRole = (role || '').toLowerCase();
  const storedName =
    (hasWindow && localStorage.getItem('name')) ||
    (hasWindow && localStorage.getItem('username')) ||
    (hasWindow && localStorage.getItem('email')
      ? localStorage.getItem('email').split('@')[0]
      : null);

  // Redirect if already logged in
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const mode = String(params.get('mode') || '').toLowerCase();
    if (mode === 'reset') return;
    if (token && role) {
      const dashUrl =
        normalizedRole === 'expert' ? '/expert-dashboard' : '/client-dashboard';
      navigate(dashUrl, { replace: true });
    }
  }, [location.search, token, role, normalizedRole, navigate]);

  const handleLogout = () => {
    if (!hasWindow) return;
    if (window.confirm('Logout from this device?')) {
      localStorage.clear();
      navigate('/login', { replace: true });
    }
  };

  const dashUrl =
    normalizedRole === 'expert' ? '/expert-dashboard' : '/client-dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (isSubmitting) return;

    const formData = new FormData(e.currentTarget);
    const email = String(formData.get('email') || '').trim().toLowerCase();
    const password = String(formData.get('password') || '');

    setIsSubmitting(true);
    const originalText = 'Sign in';

    try {
      const res = await fetch(`${API}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (data.success) {
        const incomingRole = String(data.role || 'client').toLowerCase();
        if (hasWindow) {
          localStorage.setItem('token', data.token);
          localStorage.setItem('username', data.name);
          localStorage.setItem('email', data.email);
          localStorage.setItem('role', incomingRole);
        }

        const target =
          incomingRole === 'expert' ? '/expert-dashboard' : '/client-dashboard';
        navigate(target);
      } else {
        alert(data.error || 'Invalid email or password');
        setIsSubmitting(false);
        const btn = document.getElementById('loginBtn');
        if (btn) btn.innerText = originalText;
      }
    } catch {
      alert('Connection error. Please try again later.');
      setIsSubmitting(false);
      const btn = document.getElementById('loginBtn');
      if (btn) btn.innerText = originalText;
    }
  };

  const handleGoogleCredential = async (response) => {
    const idToken = response?.credential;
    if (!idToken) {
      setGoogleError('Google did not return a sign-in token.');
      return;
    }

    setIsSubmitting(true);
    setGoogleError('');

    try {
      const res = await fetch(`${API}/api/google-auth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken, role: 'client' }),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok || !data.success) {
        setGoogleError(data.error || 'Google sign-in failed.');
        setIsSubmitting(false);
        return;
      }

      saveAuthSession(data);
      const incomingRole = String(data.role || 'client').toLowerCase();
      navigate(incomingRole === 'expert' ? '/expert-dashboard' : '/client-dashboard');
    } catch {
      setGoogleError('Connection error. Please try again later.');
      setIsSubmitting(false);
    }
  };

  const handleGoogleLogin = async () => {
    if (isSubmitting) return;
    setGoogleError('');

    try {
      const [google, googleClientId] = await Promise.all([
        loadGoogleIdentityScript(),
        getGoogleClientId(API),
      ]);
      google.accounts.id.initialize({
        client_id: googleClientId,
        callback: handleGoogleCredential,
        ux_mode: 'popup',
      });
      google.accounts.id.prompt((notification) => {
        if (
          notification.isNotDisplayed?.() ||
          notification.isSkippedMoment?.()
        ) {
          setGoogleError('Google account chooser was closed or blocked.');
        }
      });
    } catch (err) {
      setGoogleError(err.message || 'Google sign-in is not available right now.');
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const mode = String(params.get('mode') || '').toLowerCase();
    const tokenFromUrl = String(params.get('token') || '');
    if (mode === 'reset') {
      setAuthMode('reset');
      if (tokenFromUrl) setResetToken(tokenFromUrl);
    }
  }, [location.search]);

  const validateStrongPassword = (pwd) => {
    if (pwd.length < 8) return 'Password must be at least 8 characters.';
    if (!/[A-Z]/.test(pwd)) return 'Include at least one uppercase letter.';
    if (!/[a-z]/.test(pwd)) return 'Include at least one lowercase letter.';
    if (!/[0-9]/.test(pwd)) return 'Include at least one number.';
    if (!/[!@#$%^&*()_\-+=[\]{};:'",.<>/?\\|`~]/.test(pwd)) {
      return 'Include at least one special character.';
    }
    return '';
  };

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    if (isSubmitting) return;
    setForgotMsg('');
    const email = forgotEmail.trim().toLowerCase();
    if (!email) {
      setForgotMsg('Enter your registered email.');
      return;
    }
    setIsSubmitting(true);
    try {
      const res = await fetch(`${API}/api/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setForgotMsg(data.error || 'Could not process forgot password.');
      } else if (data.resetLink) {
        setForgotMsg(`Reset link generated (dev mode): ${data.resetLink}`);
      } else {
        setForgotMsg(data.message || 'If this email exists, reset link has been sent.');
      }
    } catch {
      setForgotMsg('Network error. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    if (isSubmitting) return;
    setResetMsg('');
    const tokenValue = resetToken.trim();
    if (!tokenValue) {
      setResetMsg('Reset token is required.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setResetMsg('Passwords do not match.');
      return;
    }
    const pwdErr = validateStrongPassword(newPassword);
    if (pwdErr) {
      setResetMsg(pwdErr);
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetch(`${API}/api/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: tokenValue, password: newPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.success) {
        setResetMsg(data.error || 'Could not reset password.');
        setIsSubmitting(false);
        return;
      }
      setResetMsg('Password reset successful. You can now sign in.');
      setAuthMode('login');
      setResetToken('');
      setNewPassword('');
      setConfirmPassword('');
    } catch {
      setResetMsg('Network error. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="login-page">
      <div className="ambient-glow" aria-hidden="true"></div>

      {/* HEADER */}
      <header>
        <div className="container header-inner">
          <div className="logo" onClick={() => navigate('/')}>
            <div className="txt">
              Solve<span className="nut">nut</span>
            </div>
          </div>

          <nav className="desktop" aria-label="Primary navigation">
            <a href="/#categories">Categories</a>
            <a href="/#how">How It Works</a>
            <a href="/#features">Features</a>
            <Link to="/experts">Find Experts</Link>
          </nav>

          <div className="actions">
            {token && role ? (
              <>
                <div className="nav-user-pill">
                  <i className="fa-regular fa-circle-user"></i>
                  <span>{storedName || 'User'}</span>
                </div>
                <Link
                  className="btn btn-ghost"
                  to={dashUrl}
                  style={{ fontSize: '13px', padding: '6px 12px' }}
                >
                  Dashboard
                </Link>
                <button className="nav-logout" onClick={handleLogout}>
                  Logout
                </button>
              </>
            ) : (
              <Link className="btn btn-ghost" to="/signup-client">
                Sign up
              </Link>
            )}
          </div>

          <button
            className="mobile-toggle"
            aria-expanded={isMenuOpen}
            aria-controls="mobileDrawer"
            onClick={() => setIsMenuOpen(true)}
          >
            <i className="fa-solid fa-bars"></i>
          </button>
        </div>
      </header>

      {/* MOBILE DRAWER */}
      <div
        id="mobileDrawer"
        className={`mobile-drawer ${isMenuOpen ? 'open' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-hidden={!isMenuOpen}
        style={{ display: isMenuOpen ? 'flex' : 'none' }}
      >
        <button
          style={{
            alignSelf: 'flex-end',
            background: 'transparent',
            border: 0,
            color: 'var(--text)',
            fontSize: '24px',
            padding: '6px',
            cursor: 'pointer',
          }}
          onClick={() => setIsMenuOpen(false)}
        >
          <i className="fa-solid fa-xmark"></i>
        </button>
        <a href="/#categories" onClick={() => setIsMenuOpen(false)}>
          Categories
        </a>
        <a href="/#how" onClick={() => setIsMenuOpen(false)}>
          How It Works
        </a>
        <a href="/#features" onClick={() => setIsMenuOpen(false)}>
          Features
        </a>
        <Link to="/experts" onClick={() => setIsMenuOpen(false)}>
          Find Experts
        </Link>
      </div>

      {/* MAIN */}
      <main>
        <div className="container auth-layout">
          <section className="auth-intro">
            <h1>
              Login to <span>Solvenut</span>
            </h1>
            <p>
              Continue your conversations, manage sessions, and track expert
              advice all from one simple dashboard.
            </p>
            <div className="auth-points">
              <span>
                <i className="fa-solid fa-circle-check"></i> One login for both
                client and expert accounts
              </span>
              <span>
                <i className="fa-solid fa-circle-check"></i> Access your saved
                chats, calls, and payment history
              </span>
              <span>
                <i className="fa-solid fa-circle-check"></i> Switch between
                devices without losing your session
              </span>
            </div>
          </section>

          <section className="login-card">
            <div className="login-badge">
              <i className="fa-solid fa-lock"></i>
              Secure login · Encrypted
            </div>
            <h2>Welcome back</h2>
            <p>
              Use your client or expert account to access your Solvenut dashboard.
            </p>

            {authMode === 'login' && (
            <form id="loginForm" autoComplete="on" onSubmit={handleSubmit}>
              <div className="input-group">
                <label htmlFor="email">Email address</label>
                <div className="input-wrapper">
                  <i className="fas fa-envelope"></i>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    placeholder="you@example.com"
                    required
                    autoComplete="email"
                  />
                </div>
              </div>

              <div className="input-group">
                <label htmlFor="password">Password</label>
                <div className="input-wrapper">
                  <i className="fas fa-lock"></i>
                  <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="••••••••"
                    required
                    autoComplete="current-password"
                  />
                </div>
              </div>

              <div className="login-meta">
                <span>Use the same account for app and web</span>
                <button
                  type="button"
                  className="login-text-link"
                  onClick={() => {
                    setAuthMode('forgot');
                    setForgotMsg('');
                    setResetMsg('');
                  }}
                >
                  Forgot password?
                </button>
              </div>

              <button
                type="submit"
                className="btn-login"
                id="loginBtn"
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Signing you in…' : 'Sign in'}
              </button>
              <div className="auth-divider"><span>or</span></div>
                <button
                  type="button"
                  className="google-auth-btn"
                  onClick={handleGoogleLogin}
                  disabled={isSubmitting}
                >
                  <span className="google-mark" aria-hidden="true">G</span>
                  Continue with Google
                </button>
              {googleError ? <div className="auth-hint auth-error">{googleError}</div> : null}
            </form>
            )}

            {authMode === 'forgot' && (
              <form autoComplete="on" onSubmit={handleForgotPassword}>
                <div className="input-group">
                  <label htmlFor="forgotEmail">Registered email</label>
                  <div className="input-wrapper">
                    <i className="fas fa-envelope"></i>
                    <input
                      type="email"
                      id="forgotEmail"
                      value={forgotEmail}
                      onChange={(e) => setForgotEmail(e.target.value)}
                      placeholder="you@example.com"
                      required
                      autoComplete="email"
                    />
                  </div>
                </div>
                {forgotMsg ? <div className="auth-hint">{forgotMsg}</div> : null}
                <div className="login-meta">
                  <button type="button" className="login-text-link" onClick={() => setAuthMode('login')}>Back to login</button>
                </div>
                <button type="submit" className="btn-login" disabled={isSubmitting}>
                  {isSubmitting ? 'Processing…' : 'Send reset link'}
                </button>
              </form>
            )}

            {authMode === 'reset' && (
              <form autoComplete="on" onSubmit={handleResetPassword}>
                <div className="input-group">
                  <label htmlFor="resetToken">Reset token</label>
                  <div className="input-wrapper">
                    <i className="fas fa-key"></i>
                    <input
                      type="text"
                      id="resetToken"
                      value={resetToken}
                      onChange={(e) => setResetToken(e.target.value)}
                      placeholder="Paste token from reset link"
                      required
                    />
                  </div>
                </div>
                <div className="input-group">
                  <label htmlFor="newPassword">New password</label>
                  <div className="input-wrapper">
                    <i className="fas fa-lock"></i>
                    <input
                      type="password"
                      id="newPassword"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="New strong password"
                      required
                      autoComplete="new-password"
                    />
                  </div>
                </div>
                <div className="input-group">
                  <label htmlFor="confirmPassword">Confirm password</label>
                  <div className="input-wrapper">
                    <i className="fas fa-lock"></i>
                    <input
                      type="password"
                      id="confirmPassword"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Re-enter password"
                      required
                      autoComplete="new-password"
                    />
                  </div>
                </div>
                <div className="auth-hint">
                  Password must be 8+ chars with uppercase, lowercase, number, and special character.
                </div>
                {resetMsg ? <div className="auth-hint">{resetMsg}</div> : null}
                <div className="login-meta">
                  <button type="button" className="login-text-link" onClick={() => setAuthMode('login')}>Back to login</button>
                </div>
                <button type="submit" className="btn-login" disabled={isSubmitting}>
                  {isSubmitting ? 'Resetting…' : 'Reset password'}
                </button>
              </form>
            )}

            {!token && (
              <div className="auth-footer-links">
                Don’t have an account yet?
                <br />
                <Link to="/signup-client">Create client account</Link>
                &nbsp;·&nbsp;
                <Link to="/signup-expert">Apply as expert</Link>
                <br />
                <Link to="/admin-login">Admin login</Link>
              </div>
            )}
          </section>
        </div>
      </main>

      {/* FOOTER */}
      <footer>
        <div className="container footer-row">
          <div>
            © 2026 Solvenut. Human‑first expert advice, when you need it most.
          </div>
          <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
            <a href="#" style={{ color: 'var(--muted)' }}>
              Privacy
            </a>
            <a href="#" style={{ color: 'var(--muted)' }}>
              Terms
            </a>
            <a href="#" style={{ color: 'var(--muted)' }}>
              Refunds
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Login;
