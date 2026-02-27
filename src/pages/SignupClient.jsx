// src/pages/SignupClient.jsx
import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import '../styles/SignupClient.css';

// ✅ Base API root from Vite env (e.g. VITE_API_BASE=https://solutionhub66.onrender.com)
const API = import.meta.env.VITE_API_BASE;

const SignupClient = () => {
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

  const dashUrl = role === 'expert' ? '/expert-dashboard' : '/client-dashboard';

  // Redirect if already logged in
  useEffect(() => {
    if (token && role) {
      navigate(dashUrl, { replace: true });
    }
  }, [token, role, dashUrl, navigate]);

  const handleLogout = () => {
    if (!hasWindow) return;
    if (window.confirm('Logout from this device?')) {
      localStorage.clear();
      navigate('/login', { replace: true });
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (isSubmitting) return;

    const formData = new FormData(e.currentTarget);
    const name = String(formData.get('name') || '').trim();
    const email = String(formData.get('email') || '').trim().toLowerCase();
    const password = String(formData.get('password') || '');

    setIsSubmitting(true);

    try {
      const res = await fetch(`${API}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      });

      const data = await res.json();

      if (!data.success) {
        alert(data.error || 'Signup failed. Please try again.');
        setIsSubmitting(false);
        return;
      }

      const btn = document.getElementById('signupBtn');
      if (btn) {
        btn.innerHTML =
          '<i class="fa-solid fa-circle-check"></i> Account created!';
      }
      setTimeout(() => {
        navigate('/login');
      }, 1000);
    } catch (err) {
      alert('Connection error. Please try again.');
      setIsSubmitting(false);
    }
  };

  return (
    <div className="signup-page">
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

          <nav className="desktop">
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
              <Link className="btn btn-ghost" to="/login">
                Log in
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
        <div className="container">
          <div className="auth-card">
            <section className="auth-info">
              <h1>
                Create your <span>client account</span>
              </h1>
              <p>
                Ask verified human experts about health, money, studies,
                relationships, and more—anytime you feel stuck.
              </p>
              <div className="info-points">
                <span>
                  <i className="fa-solid fa-circle-check"></i> One account to
                  talk to any expert on Solvenut
                </span>
                <span>
                  <i className="fa-solid fa-circle-check"></i> Pay only for the
                  minutes you actually use
                </span>
                <span>
                  <i className="fa-solid fa-circle-check"></i> Your chats and
                  call notes are securely stored
                </span>
              </div>
            </section>

            <section className="auth-form-side">
              <div className="form-header">
                <h2>Sign up as client</h2>
                <p>
                  It takes less than a minute. You can delete your account
                  anytime.
                </p>
              </div>

              <form id="signupForm" autoComplete="on" onSubmit={handleSubmit}>
                <div className="input-group">
                  <label htmlFor="name">Full name</label>
                  <div className="input-wrapper">
                    <i className="fa-solid fa-user"></i>
                    <input
                      type="text"
                      id="name"
                      name="name"
                      placeholder="Your full name"
                      required
                      autoComplete="name"
                    />
                  </div>
                </div>

                <div className="input-group">
                  <label htmlFor="email">Email address</label>
                  <div className="input-wrapper">
                    <i className="fa-solid fa-envelope"></i>
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
                    <i className="fa-solid fa-lock"></i>
                    <input
                      type="password"
                      id="password"
                      name="password"
                      placeholder="Create a strong password"
                      required
                      autoComplete="new-password"
                    />
                  </div>
                </div>

                <div className="input-group">
                  <label htmlFor="interest">
                    Main category you care about
                  </label>
                  <div className="input-wrapper">
                    <i className="fa-solid fa-layer-group"></i>
                    <select id="interest" name="interest" defaultValue="">
                      <option value="" disabled>
                        Select a category (optional)
                      </option>
                      <option value="health">Health & wellness</option>
                      <option value="studies">Studies & exams</option>
                      <option value="money">Money & finance</option>
                      <option value="tech">Tech & coding</option>
                      <option value="relationships">Life & relationships</option>
                    </select>
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn-signup"
                  id="signupBtn"
                  disabled={isSubmitting}
                >
                  {isSubmitting
                    ? 'Creating your account…'
                    : 'Create my Solvenut account'}
                </button>
              </form>

              <div className="terms-note">
                By signing up, you agree to Solvenut’s <a href="#">Terms</a>{' '}
                and <a href="#">Privacy Policy</a>.
              </div>
              <div className="have-account">
                Already have an account? <Link to="/login">Log in</Link>
              </div>
            </section>
          </div>
        </div>
      </main>

      {/* FOOTER */}
      <footer>
        <div className="container footer-row">
          <div>
            © 2026 Solvenut. Making expert knowledge accessible and affordable.
          </div>
          <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
            <a href="#" style={{ color: 'var(--muted)' }}>
              Privacy
            </a>
            <a href="#" style={{ color: 'var(--muted)' }}>
              Terms
            </a>
            <a href="#" style={{ color: 'var(--muted)' }}>
              Support
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default SignupClient;
