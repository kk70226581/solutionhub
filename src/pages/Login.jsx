// src/pages/Login.jsx
import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import '../styles/Login.css';

// ✅ Base API root from Vite env (e.g. VITE_API_BASE=https://solutionhub66.onrender.com)
const API = import.meta.env.VITE_API_BASE;

const Login = () => {
  const navigate = useNavigate();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const hasWindow = typeof window !== 'undefined';

  const token = hasWindow ? localStorage.getItem('token') : null;
  const role = hasWindow ? localStorage.getItem('role') : null;
  const storedName =
    (hasWindow && localStorage.getItem('name')) ||
    (hasWindow && localStorage.getItem('username')) ||
    (hasWindow && localStorage.getItem('email')
      ? localStorage.getItem('email').split('@')[0]
      : null);

  // Redirect if already logged in
  useEffect(() => {
    if (token && role) {
      const dashUrl = role === 'expert' ? '/expert-dashboard' : '/client-dashboard';
      navigate(dashUrl, { replace: true });
    }
  }, [token, role, navigate]);

  const handleLogout = () => {
    if (!hasWindow) return;
    if (window.confirm('Logout from this device?')) {
      localStorage.clear();
      navigate('/login', { replace: true });
    }
  };

  const dashUrl = role === 'expert' ? '/expert-dashboard' : '/client-dashboard';

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
        if (hasWindow) {
          localStorage.setItem('token', data.token);
          localStorage.setItem('username', data.name);
          localStorage.setItem('email', data.email);
          localStorage.setItem('role', data.role || 'client');
        }

        const target =
          data.role === 'expert' ? '/expert-dashboard' : '/client-dashboard';
        navigate(target);
      } else {
        alert(data.error || 'Invalid email or password');
        setIsSubmitting(false);
        const btn = document.getElementById('loginBtn');
        if (btn) btn.innerText = originalText;
      }
    } catch (err) {
      alert('Connection error. Please try again later.');
      setIsSubmitting(false);
      const btn = document.getElementById('loginBtn');
      if (btn) btn.innerText = originalText;
    }
  };

  return (
    <div className="login-page">
      <div className="ambient-glow" aria-hidden="true"></div>

      {/* HEADER */}
      <header>
        <div className="container header-inner">
          <div className="logo" onClick={() => navigate('/')}>
            <div className="mark">🥜</div>
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
              Enter your registered email and password to access your Solvenut
              dashboard.
            </p>

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
              </div>

              <button
                type="submit"
                className="btn-login"
                id="loginBtn"
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Signing you in…' : 'Sign in'}
              </button>
            </form>

            {!token && (
              <div className="auth-footer-links">
                Don’t have an account yet?
                <br />
                <Link to="/signup-client">Create client account</Link>
                &nbsp;·&nbsp;
                <Link to="/signup-expert">Apply as expert</Link>
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
