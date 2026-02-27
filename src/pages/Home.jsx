// src/pages/Home.jsx
import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/Home.css';

const Home = () => {
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const innerRef = useRef(null);

  // simple auth detection
  const hasWindow = typeof window !== 'undefined';
  const token = hasWindow ? localStorage.getItem('token') : null;
  const email = hasWindow ? localStorage.getItem('email') : null;
  const isLoggedIn = !!token && !!email;

  // lock body scroll when mobile menu is open
  useEffect(() => {
    const original = document.body.style.overflow;
    if (mobileOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = original || '';
    }
    return () => {
      document.body.style.overflow = original || '';
    };
  }, [mobileOpen]);

  // close on Escape
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape' && mobileOpen) setMobileOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mobileOpen]);

  // navigate helper – uses your actual React routes
  const go = (path) => {
    navigate(path);
    setMobileOpen(false);
  };

  const toggleMobile = () => setMobileOpen((v) => !v);

  // close when clicking overlay (but not when clicking inside the drawer)
  const onOverlayClick = (e) => {
    if (!innerRef.current) return setMobileOpen(false);
    if (!innerRef.current.contains(e.target)) {
      setMobileOpen(false);
    }
  };

  // logout handler
  const handleLogout = () => {
    if (!hasWindow) return;
    localStorage.removeItem('token');
    localStorage.removeItem('email');
    localStorage.removeItem('name');
    navigate('/login');
  };

  return (
    <div className="home-page">
      {/* background */}
      <div className="home-ambient" />

      {/* HEADER */}
      <header className="home-header" role="banner">
        <div className="home-shell home-header-inner">
          {/* Logo */}
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

          {/* Desktop nav */}
          <nav className="home-nav-desktop" aria-label="Main navigation">
            <div className="home-nav-links">
              <button className="home-nav-link" onClick={() => go('/experts')}>
                Find experts
              </button>
              <button
                className="home-nav-link"
                onClick={() => go('/client-dashboard')}
              >
                For clients
              </button>
              <button
                className="home-nav-link"
                onClick={() => go('/expert-dashboard')}
              >
                For experts
              </button>
              <button
                className="home-nav-link"
                onClick={() => go('/admin-login')}
              >
                Admin
              </button>
            </div>

            {/* Auth-aware desktop actions */}
            <div className="home-nav-actions">
              {isLoggedIn ? (
                <>
                  <button
                    className="home-btn home-btn-ghost"
                    onClick={() => go('/client-dashboard')}
                  >
                    Go to dashboard
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

          {/* Mobile hamburger */}
          <button
            className="home-mobile-toggle"
            onClick={toggleMobile}
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

      {/* Mobile drawer menu */}
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

          <button className="home-mobile-link" onClick={() => go('/experts')}>
            Find experts
          </button>
          <button
            className="home-mobile-link"
            onClick={() => go('/client-dashboard')}
          >
            For clients
          </button>
          <button
            className="home-mobile-link"
            onClick={() => go('/expert-dashboard')}
          >
            For experts
          </button>
          <button
            className="home-mobile-link"
            onClick={() => go('/admin-login')}
          >
            Admin
          </button>

          <div className="home-mobile-actions">
            {isLoggedIn ? (
              <>
                <button
                  className="home-btn home-btn-ghost full"
                  onClick={() => go('/client-dashboard')}
                >
                  Go to dashboard
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

      {/* MAIN */}
      <main className="home-main">
        <div className="home-shell">
          {/* HERO */}
          <section className="home-hero">
            <div className="home-hero-grid">
              <div className="home-hero-copy">
                <p className="home-hero-kicker">
                  Structured thinking • Clear actions
                </p>
                <h1 className="home-hero-title">
                  From confused to{' '}
                  <span className="home-hero-highlight">decisive</span> on your
                  next move.
                </h1>
                <p className="home-hero-sub">
                  Solvenut pairs focused AI structure with vetted human experts,
                  so you can move from vague “what ifs” to a concrete 30–90 day
                  plan for your career, money, and side-projects.
                </p>

                <div className="home-hero-pill-row">
                  <span className="home-hero-pill">Career forks</span>
                  <span className="home-hero-pill">Money dilemmas</span>
                  <span className="home-hero-pill">Side-projects</span>
                  <span className="home-hero-pill">Life planning</span>
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
                    onClick={() => go('/signup-expert')}
                  >
                    Apply as expert
                  </button>
                </div>

                <p className="home-hero-meta">
                  No subscriptions • Pay per engagement • Private 1-to-1 rooms
                </p>

                <div className="home-hero-trust">
                  <div className="home-hero-avatars" aria-hidden="true">
                    <span className="home-hero-avatar home-hero-avatar-1" />
                    <span className="home-hero-avatar home-hero-avatar-2" />
                    <span className="home-hero-avatar home-hero-avatar-3" />
                  </div>
                  <div className="home-hero-trust-copy">
                    <span className="home-hero-trust-metric">
                      9.2/10 clarity score
                    </span>
                    <span className="home-hero-trust-sub">
                      from recent client sessions
                    </span>
                  </div>
                </div>
              </div>

              <aside
                className="home-hero-card"
                aria-labelledby="hero-card-heading"
              >
                <div className="home-hero-card-header">
                  <h2 id="hero-card-heading">Why people use Solvenut</h2>
                  <p>Real decisions, not just quick answers.</p>
                </div>
                <div className="home-hero-stats">
                  <div className="home-hero-stat">
                    <div className="home-hero-stat-label">Typical question</div>
                    <p>
                      “Should I switch jobs now or double down where I am for
                      12–18 months?”
                    </p>
                  </div>
                  <div className="home-hero-stat">
                    <div className="home-hero-stat-label">
                      What you leave with
                    </div>
                    <ul>
                      <li>3–5 criteria that actually fit your life</li>
                      <li>1–3 realistic options with trade-offs</li>
                      <li>A 30–90 day decision and action plan</li>
                    </ul>
                  </div>
                  <div className="home-hero-stat">
                    <div className="home-hero-stat-label">Who you talk to</div>
                    <p>
                      Practitioners who&apos;ve made similar decisions, not
                      generic influencers or random internet threads.
                    </p>
                  </div>
                </div>
              </aside>
            </div>
          </section>

          {/* HOW IT WORKS */}
          <section className="home-section">
            <div className="home-section-head">
              <p className="home-section-kicker">How it works</p>
              <h2 className="home-section-title">
                Turn messy thoughts into a concrete decision path.
              </h2>
              <p className="home-section-sub">
                We combine structured prompts, async prep, and focused live
                calls so you don&apos;t waste time “venting” and can get to a
                decision you can actually act on.
              </p>
            </div>
            <div className="home-steps-grid">
              <div className="home-step-card">
                <span className="home-step-tag">Step 1</span>
                <h3>Clarify the real question</h3>
                <p>
                  A short intake helps you unpack the real decision — not just
                  the surface-level “should I quit?” but what is actually at
                  stake for you.
                </p>
                <ul>
                  <li>10–12 structured prompts</li>
                  <li>Clarify constraints and non-negotiables</li>
                  <li>See hidden assumptions surfaced</li>
                </ul>
              </div>
              <div className="home-step-card">
                <span className="home-step-tag">Step 2</span>
                <h3>Match with a relevant expert</h3>
                <p>
                  Get paired with someone who has lived a similar fork — same
                  domain, similar level, and compatible risk appetite.
                </p>
                <ul>
                  <li>Vetted practitioners with real track records</li>
                  <li>Clear bios and case examples</li>
                  <li>Transparent hourly pricing</li>
                </ul>
              </div>
              <div className="home-step-card">
                <span className="home-step-tag">Step 3</span>
                <h3>Co-design your 30–90 day plan</h3>
                <p>
                  Use Solvenut&apos;s structured workspace to map options,
                  trade-offs, and next steps you can actually calendar.
                </p>
                <ul>
                  <li>Decision scorecards and trade-off maps</li>
                  <li>Concrete experiments and checkpoints</li>
                  <li>Downloadable summary you can revisit</li>
                </ul>
              </div>
            </div>
          </section>

          {/* DOMAINS / USE CASES */}
          <section className="home-section">
            <div className="home-section-head">
              <p className="home-section-kicker">Where Solvenut helps</p>
              <h2 className="home-section-title">
                Different domains, same structured clarity.
              </h2>
              <p className="home-section-sub">
                Whether it&apos;s work, money, or side bets, the patterns of
                good decision-making look surprisingly similar.
              </p>
            </div>
            <div className="home-domains-grid">
              <div className="home-domain-card">
                <h3>Career & work</h3>
                <p>
                  Promotions, role changes, switching tracks, or taking a
                  sabbatical without blowing up your long-term trajectory.
                </p>
                <ul>
                  <li>Stay vs. switch decisions</li>
                  <li>IC vs. manager paths</li>
                  <li>Relocation and remote trade-offs</li>
                </ul>
              </div>
              <div className="home-domain-card">
                <h3>Money & risk</h3>
                <p>
                  Make moves on savings, equity, and income that fit your risk
                  tolerance and actual lifestyle goals.
                </p>
                <ul>
                  <li>Runway and buffer planning</li>
                  <li>Side income vs. full focus</li>
                  <li>Big purchases and timing</li>
                </ul>
              </div>
              <div className="home-domain-card">
                <h3>Side-projects & bets</h3>
                <p>
                  Decide how seriously to take that idea — hobby, side income,
                  or something you gradually lean into.
                </p>
                <ul>
                  <li>Idea validation sprints</li>
                  <li>Scope and constraints</li>
                  <li>Clear “kill, pause, or double down” triggers</li>
                </ul>
              </div>
              <div className="home-domain-card">
                <h3>Life planning</h3>
                <p>
                  Zoom out to see how your work, money, and time stack into a
                  life that feels coherent instead of reactive.
                </p>
                <ul>
                  <li>Values and constraints mapping</li>
                  <li>Multi-year direction checks</li>
                  <li>Partner and family conversations</li>
                </ul>
              </div>
            </div>
          </section>

          {/* SOCIAL PROOF / TESTIMONIALS */}
          <section className="home-section home-section-alt">
            <div className="home-section-head">
              <p className="home-section-kicker">What clients say</p>
              <h2 className="home-section-title">
                “It felt like finally having a clean mental whiteboard.”
              </h2>
              <p className="home-section-sub">
                Anonymous composites from early users making real career and
                money decisions.
              </p>
            </div>
            <div className="home-testimonials-grid">
              <article className="home-testimonial-card">
                <p className="home-testimonial-quote">
                  “I went in with a vague ‘should I leave?’ and left with three
                  very specific scenarios, plus exact conversations I needed to
                  have with my manager.”
                </p>
                <div className="home-testimonial-meta">
                  <span className="home-testimonial-name">
                    Product lead, fintech
                  </span>
                  <span className="home-testimonial-tag">
                    Career fork • 2 sessions
                  </span>
                </div>
              </article>
              <article className="home-testimonial-card">
                <p className="home-testimonial-quote">
                  “We turned my messy Notion docs into one page of trade-offs
                  that my partner and I could actually agree on.”
                </p>
                <div className="home-testimonial-meta">
                  <span className="home-testimonial-name">
                    Senior engineer, big tech
                  </span>
                  <span className="home-testimonial-tag">
                    Move vs. stay • 1 session
                  </span>
                </div>
              </article>
              <article className="home-testimonial-card">
                <p className="home-testimonial-quote">
                  “Instead of yet another inspirational podcast, I finally had a
                  concrete 90-day plan for my side project.”
                </p>
                <div className="home-testimonial-meta">
                  <span className="home-testimonial-name">
                    Designer, SaaS startup
                  </span>
                  <span className="home-testimonial-tag">
                    Side project • 3 sessions
                  </span>
                </div>
              </article>
            </div>
          </section>

          {/* FAQ */}
          <section className="home-section">
            <div className="home-section-head">
              <p className="home-section-kicker">Questions, answered</p>
              <h2 className="home-section-title">
                A few things people usually ask before booking.
              </h2>
            </div>
            <div className="home-faq-grid">
              <details className="home-faq-item">
                <summary>Is Solvenut a therapy or coaching replacement?</summary>
                <p>
                  No. Solvenut is a structured decision space with experienced
                  practitioners. It&apos;s not a substitute for therapy,
                  medical, legal, or emergency support.
                </p>
              </details>
              <details className="home-faq-item">
                <summary>How are experts vetted?</summary>
                <p>
                  We review actual work history, decisions they&apos;ve made,
                  and ask for concrete examples of outcomes — not just titles or
                  follower counts.
                </p>
              </details>
              <details className="home-faq-item">
                <summary>What does a typical session look like?</summary>
                <p>
                  You come in with a structured pre-brief, spend 45–60 minutes
                  exploring options and trade-offs, and leave with a written
                  summary and next steps.
                </p>
              </details>
              <details className="home-faq-item">
                <summary>Can I bring my partner or co-founder?</summary>
                <p>
                  Yes. Many decisions are shared. As long as everyone&apos;s
                  aligned on the goal of the session, shared rooms work well.
                </p>
              </details>
            </div>
          </section>

          {/* FINAL CTA */}
          <section className="home-section home-cta-section">
            <div className="home-cta-inner">
              <div className="home-cta-copy">
                <p className="home-section-kicker">Ready when you are</p>
                <h2 className="home-section-title">
                  One focused session can unblock your next 3–6 months.
                </h2>
                <p className="home-section-sub">
                  Start with a single, no-commitment engagement. If it helps,
                  you can always book follow-ups with the same expert.
                </p>
              </div>
              <div className="home-cta-actions">
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
            </div>
          </section>
        </div>
      </main>

      {/* FOOTER */}
      <footer className="home-footer" aria-label="Site footer">
        <div className="home-shell home-footer-row">
          <div className="home-footer-left">
            <div className="home-footer-brand">
              <span className="home-footer-logo">🥜</span>
              <span className="home-footer-name">Solvenut</span>
            </div>
            <p className="home-footer-text">
              Human experts + structured tools for real-world decisions. Not a
              replacement for medical, legal, or emergency advice.
            </p>
            <div className="home-footer-badges">
              <span className="home-footer-badge">No subscriptions</span>
              <span className="home-footer-badge">Human + AI blended</span>
              <span className="home-footer-badge">Private by default</span>
            </div>
            <span className="home-footer-meta">
              © 2026 Solvenut. All rights reserved.
            </span>
          </div>

          <div className="home-footer-right">
            <div className="home-footer-col">
              <h4>Product</h4>
              <button onClick={() => go('/experts')}>Experts</button>
              <button onClick={() => go('/client-dashboard')}>
                Client dashboard
              </button>
              <button onClick={() => go('/pricing')}>Pricing</button>
            </div>
            <div className="home-footer-col">
              <h4>Company</h4>
              <button onClick={() => go('/about')}>About</button>
              <button onClick={() => go('/blog')}>Blog</button>
              <button onClick={() => go('/careers')}>Careers</button>
            </div>
            <div className="home-footer-col">
              <h4>Resources</h4>
              <button onClick={() => go('/use-cases')}>Use cases</button>
              <button onClick={() => go('/security')}>Security</button>
              <button onClick={() => go('/support')}>Support</button>
            </div>
            <div className="home-footer-col">
              <h4>Account</h4>
              {isLoggedIn ? (
                <>
                  <button onClick={() => go('/client-dashboard')}>
                    Dashboard
                  </button>
                  <button onClick={handleLogout}>Logout</button>
                </>
              ) : (
                <>
                  <button onClick={() => go('/login')}>Log in</button>
                  <button onClick={() => go('/signup-client')}>
                    Get started
                  </button>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="home-shell home-footer-bottom">
          <div className="home-footer-links">
            <button onClick={() => go('/terms')}>Terms</button>
            <button onClick={() => go('/privacy')}>Privacy</button>
            <button onClick={() => go('/cookies')}>Cookies</button>
          </div>
          <div className="home-footer-social">
            <a
              href="https://x.com"
              target="_blank"
              rel="noreferrer"
              aria-label="Solvenut on X"
            >
              X
            </a>
            <a
              href="https://www.linkedin.com"
              target="_blank"
              rel="noreferrer"
              aria-label="Solvenut on LinkedIn"
            >
              LinkedIn
            </a>
            <a
              href="mailto:hello@solvenut.com"
              aria-label="Email Solvenut"
            >
              Email
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Home;
