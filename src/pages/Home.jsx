import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/Home.css';

const API = import.meta.env.VITE_API_BASE || 'http://localhost:3000';

const Home = () => {
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [expertCount, setExpertCount] = useState(null);
  const innerRef = useRef(null);

  const token =
    typeof window !== 'undefined' ? localStorage.getItem('token') : null;
  const email =
    typeof window !== 'undefined' ? localStorage.getItem('email') : null;
  const isLoggedIn = Boolean(token && email);

  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = mobileOpen ? 'hidden' : prev || '';
    return () => {
      document.body.style.overflow = prev || '';
    };
  }, [mobileOpen]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape' && mobileOpen) setMobileOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mobileOpen]);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const res = await fetch(`${API}/api/experts?status=approved`);
        if (!res.ok) return;
        const data = await res.json();
        if (mounted && Array.isArray(data)) setExpertCount(data.length);
      } catch {
        if (mounted) setExpertCount(null);
      }
    };
    load();
    return () => {
      mounted = false;
    };
  }, []);

  const go = (path) => {
    navigate(path);
    setMobileOpen(false);
  };

  const scrollToSection = (id) => {
    const section = document.getElementById(id);
    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setMobileOpen(false);
  };

  const onOverlayClick = (e) => {
    if (!innerRef.current || !innerRef.current.contains(e.target)) {
      setMobileOpen(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('email');
    localStorage.removeItem('name');
    localStorage.removeItem('username');
    navigate('/login');
  };

  return (
    <div className="home-page">
      <div className="home-ambient" />

      <header className="home-header" role="banner">
        <div className="home-shell home-header-inner">
          <button
            className="home-logo"
            onClick={() => go('/')}
            aria-label="Go to Solvenut home"
          >
            <div className="home-logo-mark" aria-hidden>
              🥜
            </div>
            <div className="home-logo-text">
              Solve<span className="home-logo-nut">nut</span>
            </div>
          </button>

          <nav className="home-nav-desktop" aria-label="Main navigation">
            <div className="home-nav-links">
              <button
                className="home-nav-link"
                onClick={() => scrollToSection('why-solvenut')}
              >
                Why Solvenut
              </button>
              <button
                className="home-nav-link"
                onClick={() => scrollToSection('solutions')}
              >
                Solutions
              </button>
              <button
                className="home-nav-link"
                onClick={() => scrollToSection('process')}
              >
                Process
              </button>
              <button
                className="home-nav-link"
                onClick={() => scrollToSection('faq')}
              >
                FAQ
              </button>
            </div>

            <div className="home-nav-actions">
              {isLoggedIn ? (
                <>
                  <button
                    className="home-btn home-btn-ghost"
                    onClick={() => go('/client-dashboard')}
                  >
                    Dashboard
                  </button>
                  <button
                    className="home-btn home-btn-primary"
                    onClick={handleLogout}
                  >
                    Logout
                  </button>
                </>
              ) : (
                <>
                  <button
                    className="home-btn home-btn-ghost"
                    onClick={() => go('/login')}
                  >
                    Log in
                  </button>
                  <button
                    className="home-btn home-btn-primary"
                    onClick={() => go('/signup-client')}
                  >
                    Get started
                  </button>
                </>
              )}
            </div>
          </nav>

          <button
            className="home-mobile-toggle"
            onClick={() => setMobileOpen((v) => !v)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileOpen}
            aria-controls="home-mobile-menu"
          >
            <span />
            <span />
            <span />
          </button>
        </div>
      </header>

      <div
        id="home-mobile-menu"
        className={`home-mobile-drawer ${mobileOpen ? 'open' : ''}`}
        aria-hidden={!mobileOpen}
        onMouseDown={onOverlayClick}
      >
        <div
          className="home-mobile-inner"
          ref={innerRef}
          onMouseDown={(e) => e.stopPropagation()}
        >
          <button
            className="home-mobile-close"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
          >
            ✕
          </button>

          <button
            className="home-mobile-link"
            onClick={() => scrollToSection('why-solvenut')}
          >
            Why Solvenut
          </button>
          <button
            className="home-mobile-link"
            onClick={() => scrollToSection('solutions')}
          >
            Solutions
          </button>
          <button
            className="home-mobile-link"
            onClick={() => scrollToSection('process')}
          >
            Process
          </button>
          <button
            className="home-mobile-link"
            onClick={() => scrollToSection('faq')}
          >
            FAQ
          </button>
          <button className="home-mobile-link" onClick={() => go('/experts')}>
            Browse experts
          </button>

          <div className="home-mobile-actions">
            {isLoggedIn ? (
              <>
                <button
                  className="home-btn home-btn-ghost full"
                  onClick={() => go('/client-dashboard')}
                >
                  Dashboard
                </button>
                <button
                  className="home-btn home-btn-primary full"
                  onClick={handleLogout}
                >
                  Logout
                </button>
              </>
            ) : (
              <>
                <button
                  className="home-btn home-btn-ghost full"
                  onClick={() => go('/login')}
                >
                  Log in
                </button>
                <button
                  className="home-btn home-btn-primary full"
                  onClick={() => go('/signup-client')}
                >
                  Get started
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      <main className="home-main">
        <div className="home-shell">
          <section className="home-hero">
            <div className="home-hero-grid">
              <div className="home-hero-copy">
                <p className="home-hero-kicker">Professional Decision Platform</p>
                <h1 className="home-hero-title">
                  Make high-stakes decisions with
                  <span className="home-hero-highlight"> clarity, speed, and confidence</span>
                </h1>
                <p className="home-hero-sub">
                  Solvenut connects you with vetted experts and a structured
                  decision process, so you move from uncertainty to action with
                  clear next steps.
                </p>

                <div className="home-hero-pill-row">
                  <span className="home-hero-pill">Career strategy</span>
                  <span className="home-hero-pill">Money planning</span>
                  <span className="home-hero-pill">Business decisions</span>
                  <span className="home-hero-pill">Growth roadmap</span>
                </div>

                <div className="home-hero-cta-row">
                  <button
                    className="home-btn home-btn-primary"
                    onClick={() =>
                      isLoggedIn ? go('/client-dashboard') : go('/signup-client')
                    }
                  >
                    {isLoggedIn ? 'Go to dashboard' : 'Start as client'}
                  </button>
                  <button
                    className="home-btn home-btn-outline"
                    onClick={() => go('/experts')}
                  >
                    Browse experts
                  </button>
                </div>

                <div className="home-trust-strip">
                  <div className="home-trust-item">
                    <strong>{expertCount == null ? 'Growing' : `${expertCount}+`}</strong>
                    <span>approved experts</span>
                  </div>
                  <div className="home-trust-item">
                    <strong>1-to-1</strong>
                    <span>private guidance</span>
                  </div>
                  <div className="home-trust-item">
                    <strong>Actionable</strong>
                    <span>decision plans</span>
                  </div>
                </div>
              </div>

              <aside className="home-hero-card" aria-labelledby="hero-card-heading">
                <div className="home-hero-card-header">
                  <h2 id="hero-card-heading">What you gain with Solvenut</h2>
                  <p>A premium experience built for serious outcomes.</p>
                </div>
                <div className="home-hero-stats">
                  <div className="home-hero-stat">
                    <div className="home-hero-stat-label">Clarity</div>
                    <p>Understand your best options and the trade-offs behind each.</p>
                  </div>
                  <div className="home-hero-stat">
                    <div className="home-hero-stat-label">Direction</div>
                    <ul>
                      <li>Prioritized next steps</li>
                      <li>Focused short-term plan</li>
                      <li>Measurable milestones</li>
                    </ul>
                  </div>
                  <div className="home-hero-stat">
                    <div className="home-hero-stat-label">Momentum</div>
                    <p>Move from overthinking to execution with confident decisions.</p>
                  </div>
                </div>
              </aside>
            </div>
          </section>

          <section className="home-section" id="why-solvenut">
            <div className="home-section-head">
              <p className="home-section-kicker">Why Solvenut</p>
              <h2 className="home-section-title">
                Built for users who want outcomes, not generic advice
              </h2>
              <p className="home-section-sub">
                Every part of the platform is designed to help you make better
                decisions faster while staying grounded in your real context.
              </p>
            </div>
            <div className="home-proof-grid">
              <article className="home-proof-card">
                <div className="home-proof-value">Expert-first</div>
                <div className="home-proof-label">
                  Talk to experienced professionals, not random opinions.
                </div>
              </article>
              <article className="home-proof-card">
                <div className="home-proof-value">Structured flow</div>
                <div className="home-proof-label">
                  From problem framing to final action plan in one clear process.
                </div>
              </article>
              <article className="home-proof-card">
                <div className="home-proof-value">Private by design</div>
                <div className="home-proof-label">
                  Your discussions and decisions stay in dedicated private spaces.
                </div>
              </article>
              <article className="home-proof-card">
                <div className="home-proof-value">Decision quality</div>
                <div className="home-proof-label">
                  Focus on practical trade-offs, not abstract motivation.
                </div>
              </article>
            </div>
          </section>

          <section className="home-section" id="solutions">
            <div className="home-section-head">
              <p className="home-section-kicker">Solutions</p>
              <h2 className="home-section-title">Where users get the most value</h2>
              <p className="home-section-sub">
                Solvenut supports decisions across personal and professional life.
              </p>
            </div>
            <div className="home-domains-grid">
              <div className="home-domain-card">
                <h3>Career and job moves</h3>
                <p>
                  Promotions, role shifts, team changes, and major transition
                  choices with less risk.
                </p>
                <ul>
                  <li>Stay vs switch planning</li>
                  <li>Role growth strategy</li>
                  <li>Compensation decisions</li>
                </ul>
              </div>
              <div className="home-domain-card">
                <h3>Money and financial direction</h3>
                <p>
                  Practical support for income planning, spending priorities, and
                  long-term money decisions.
                </p>
                <ul>
                  <li>Income roadmap</li>
                  <li>Risk-based choices</li>
                  <li>Priority allocation</li>
                </ul>
              </div>
              <div className="home-domain-card">
                <h3>Business and side ventures</h3>
                <p>
                  Decide what to launch, pause, or scale using clearer validation
                  logic and milestones.
                </p>
                <ul>
                  <li>Idea prioritization</li>
                  <li>Execution sequencing</li>
                  <li>Growth checkpoints</li>
                </ul>
              </div>
              <div className="home-domain-card">
                <h3>Leadership and personal growth</h3>
                <p>
                  Build direction for leadership, communication, and long-term
                  personal development.
                </p>
                <ul>
                  <li>Leadership clarity</li>
                  <li>Confidence in decisions</li>
                  <li>Long-term planning</li>
                </ul>
              </div>
            </div>
          </section>

          <section className="home-section" id="process">
            <div className="home-section-head">
              <p className="home-section-kicker">Process</p>
              <h2 className="home-section-title">A simple 3-step journey</h2>
              <p className="home-section-sub">
                Designed to save time and produce clear action outcomes.
              </p>
            </div>
            <div className="home-steps-grid">
              <div className="home-step-card">
                <span className="home-step-tag">Step 1</span>
                <h3>Define your decision</h3>
                <p>Set the context, objective, and constraints clearly.</p>
                <ul>
                  <li>What matters most</li>
                  <li>Current limitations</li>
                  <li>Decision timeline</li>
                </ul>
              </div>
              <div className="home-step-card">
                <span className="home-step-tag">Step 2</span>
                <h3>Work with the right expert</h3>
                <p>Get focused guidance aligned to your exact situation.</p>
                <ul>
                  <li>Domain-matched expert</li>
                  <li>Practical option analysis</li>
                  <li>Clear recommendations</li>
                </ul>
              </div>
              <div className="home-step-card">
                <span className="home-step-tag">Step 3</span>
                <h3>Execute with confidence</h3>
                <p>Follow a practical plan with milestones and follow-ups.</p>
                <ul>
                  <li>Action roadmap</li>
                  <li>Priority order</li>
                  <li>Progress visibility</li>
                </ul>
              </div>
            </div>
          </section>

          <section className="home-section home-section-alt">
            <div className="home-section-head">
              <p className="home-section-kicker">For every user type</p>
              <h2 className="home-section-title">Choose the path that fits you</h2>
            </div>
            <div className="home-path-grid">
              <article className="home-path-card">
                <h3>For clients</h3>
                <p>
                  Get decision support for important life and career moments with
                  expert guidance and clear plans.
                </p>
                <button
                  className="home-btn home-btn-outline"
                  onClick={() =>
                    isLoggedIn ? go('/client-dashboard') : go('/signup-client')
                  }
                >
                  {isLoggedIn ? 'Open client dashboard' : 'Create client account'}
                </button>
              </article>
              <article className="home-path-card">
                <h3>For experts</h3>
                <p>
                  Build trust with serious clients, run high-value sessions, and
                  grow your professional impact.
                </p>
                <button
                  className="home-btn home-btn-outline"
                  onClick={() =>
                    isLoggedIn ? go('/expert-dashboard') : go('/signup-expert')
                  }
                >
                  {isLoggedIn ? 'Open expert dashboard' : 'Join as expert'}
                </button>
              </article>
            </div>
          </section>

          <section className="home-section" id="faq">
            <div className="home-section-head">
              <p className="home-section-kicker">FAQ</p>
              <h2 className="home-section-title">Common questions before getting started</h2>
            </div>
            <div className="home-faq-grid">
              <details className="home-faq-item">
                <summary>How do I know which expert to choose?</summary>
                <p>
                  Browse profiles by domain, experience, and fit. Start with the
                  expert who best matches your exact decision context.
                </p>
              </details>
              <details className="home-faq-item">
                <summary>Can I continue with the same expert over time?</summary>
                <p>
                  Yes, many users continue with the same expert for deeper
                  follow-through and long-term planning.
                </p>
              </details>
              <details className="home-faq-item">
                <summary>Is Solvenut only for career topics?</summary>
                <p>
                  No. It also supports financial decisions, growth planning, and
                  business-side choices.
                </p>
              </details>
              <details className="home-faq-item">
                <summary>What makes Solvenut different from normal advice platforms?</summary>
                <p>
                  Solvenut combines vetted experts, a structured process, and
                  actionable outputs instead of generic motivational content.
                </p>
              </details>
            </div>
          </section>

          <section className="home-section home-cta-section">
            <div className="home-cta-inner">
              <div className="home-cta-copy">
                <p className="home-section-kicker">Ready to move forward</p>
                <h2 className="home-section-title">
                  Turn uncertainty into a clear plan today.
                </h2>
                <p className="home-section-sub">
                  Join Solvenut and make your next important decision with
                  confidence.
                </p>
              </div>
              <div className="home-cta-actions">
                <button
                  className="home-btn home-btn-primary"
                  onClick={() =>
                    isLoggedIn ? go('/client-dashboard') : go('/signup-client')
                  }
                >
                  {isLoggedIn ? 'Go to dashboard' : 'Start now'}
                </button>
                <button
                  className="home-btn home-btn-outline"
                  onClick={() => go('/experts')}
                >
                  See expert network
                </button>
              </div>
            </div>
          </section>
        </div>
      </main>

      <footer className="home-footer" aria-label="Site footer">
        <div className="home-shell home-footer-row">
          <div className="home-footer-left">
            <div className="home-footer-brand">
              <span className="home-footer-logo">🥜</span>
              <span className="home-footer-name">Solvenut</span>
            </div>
            <p className="home-footer-text">
              Solvenut helps people and professionals make better decisions
              through expert guidance, structured thinking, and clear execution
              plans.
            </p>
            <div className="home-footer-badges">
              <span className="home-footer-badge">Outcome-focused</span>
              <span className="home-footer-badge">Professional experts</span>
              <span className="home-footer-badge">High-trust platform</span>
            </div>
            <div className="home-footer-contact">
              <div className="home-footer-contact-item">
                <span className="home-footer-contact-label">Support</span>
                <a href="mailto:hello@solvenut.com">hello@solvenut.com</a>
              </div>
              <div className="home-footer-contact-item">
                <span className="home-footer-contact-label">Response time</span>
                <span>Usually within 24 hours</span>
              </div>
            </div>
            <span className="home-footer-meta">
              © 2026 Solvenut. All rights reserved.
            </span>
          </div>

          <div className="home-footer-right">
            <div className="home-footer-col">
              <h4>Platform</h4>
              <button onClick={() => go('/experts')}>Browse experts</button>
              <button onClick={() => go('/signup-client')}>For clients</button>
              <button onClick={() => go('/signup-expert')}>For experts</button>
            </div>
            <div className="home-footer-col">
              <h4>Product</h4>
              <button onClick={() => scrollToSection('why-solvenut')}>
                Why Solvenut
              </button>
              <button onClick={() => scrollToSection('solutions')}>Solutions</button>
              <button onClick={() => scrollToSection('process')}>Process</button>
            </div>
            <div className="home-footer-col">
              <h4>Dashboards</h4>
              <button onClick={() => go('/client-dashboard')}>
                Client dashboard
              </button>
              <button onClick={() => go('/expert-dashboard')}>
                Expert dashboard
              </button>
              <button onClick={() => go('/admin-login')}>Admin panel</button>
            </div>
            <div className="home-footer-col">
              <h4>Account</h4>
              {isLoggedIn ? (
                <>
                  <button onClick={() => go('/client-dashboard')}>Dashboard</button>
                  <button onClick={handleLogout}>Logout</button>
                </>
              ) : (
                <>
                  <button onClick={() => go('/login')}>Log in</button>
                  <button onClick={() => go('/signup-client')}>Get started</button>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="home-shell home-footer-bottom">
          <div className="home-footer-links">
            <button onClick={() => scrollToSection('why-solvenut')}>
              Why Solvenut
            </button>
            <button onClick={() => scrollToSection('solutions')}>Solutions</button>
            <button onClick={() => scrollToSection('faq')}>FAQ</button>
          </div>
          <div className="home-footer-social">
            <a href="https://x.com" target="_blank" rel="noreferrer">
              X
            </a>
            <a href="https://www.linkedin.com" target="_blank" rel="noreferrer">
              LinkedIn
            </a>
            <a href="mailto:hello@solvenut.com">Email</a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Home;
