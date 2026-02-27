// src/pages/ClientDashboard.jsx
import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Mail,
  Phone,
  MapPin,
  Briefcase,
  CalendarDays,
} from 'lucide-react';
import '../styles/ClientDashboard.css';

// ✅ Ready for any future API calls
// const API = import.meta.env.VITE_API_BASE;

const ClientDashboard = () => {
  const navigate = useNavigate();

  // auth detection
  const token =
    typeof window !== 'undefined' ? localStorage.getItem('token') : null;
  const email =
    typeof window !== 'undefined' ? localStorage.getItem('email') : null;
  const name =
    typeof window !== 'undefined' ? localStorage.getItem('username') : null;

  const isLoggedIn = !!token && !!email;

  const [userData] = useState({
    username: name || 'Client',
    email: email || 'you@example.com',
    phone: '+91-98765-43210',
    location: 'Lucknow, Uttar Pradesh',
    role: 'Client',
    focusArea: 'Career & Side Projects',
    reqCount:
      typeof window !== 'undefined'
        ? parseInt(localStorage.getItem('reqCount') || '0', 10) || 0
        : 0,
  });

  const memberSince = useMemo(() => '2025', []);
  const usernameInitial =
    userData.username?.trim()?.charAt(0)?.toUpperCase() || 'C';

  const totalSessions = userData.reqCount;
  const activeFocusAreas = 1;

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('email');
    localStorage.removeItem('name');
    localStorage.removeItem('username');
    navigate('/login');
  };

  const go = (path) => navigate(path);

  return (
    <div className="client-page">
      <div className="client-ambient" />

      {/* HEADER (mirrors Home) */}
      <header className="client-header" role="banner">
        <div className="client-shell client-header-inner">
          {/* Logo */}
          <button
            className="client-logo"
            onClick={() => go('/')}
            aria-label="Go to Solvenut home"
          >
            <div className="client-logo-mark" aria-hidden>
              🥜
            </div>
            <div className="client-logo-text">
              Solve<span className="client-logo-nut">nut</span>
            </div>
          </button>

          {/* Simple nav for dashboard */}
          <nav className="client-nav-desktop" aria-label="Dashboard navigation">
            <button
              className="client-nav-link active"
              onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
            >
              Overview
            </button>
            <button
              className="client-nav-link"
              onClick={() =>
                document
                  .getElementById('client-how-section')
                  ?.scrollIntoView({ behavior: 'smooth' })
              }
            >
              How to use
            </button>
            <button
              className="client-nav-link"
              onClick={() =>
                document
                  .getElementById('client-profile-section')
                  ?.scrollIntoView({ behavior: 'smooth' })
              }
            >
              Profile
            </button>
          </nav>

          {/* Header actions */}
          <div className="client-nav-actions">
            <button
              className="client-btn client-btn-ghost"
              onClick={() => go('/experts')}
            >
              Browse experts
            </button>
            {isLoggedIn ? (
              <button
                className="client-btn client-btn-primary"
                onClick={handleLogout}
              >
                Logout
              </button>
            ) : (
              <button
                className="client-btn client-btn-primary"
                onClick={() => go('/login')}
              >
                Log in
              </button>
            )}
          </div>
        </div>
      </header>

      {/* MAIN */}
      <main className="client-main">
        <div className="client-shell">
          {/* HERO */}
          <section className="client-hero">
            <div className="client-hero-grid">
              <div className="client-hero-copy">
                <p className="client-hero-kicker">Client dashboard</p>
                <h1 className="client-hero-title">
                  A calm, structured space for your real decisions.
                </h1>
                <p className="client-hero-sub">
                  This dashboard is where you track your context, keep your
                  focus areas in one place, and jump into high‑leverage
                  sessions with experts who’ve walked similar paths.
                </p>

                <div className="client-hero-pill-row">
                  <span className="client-hero-pill">Career forks</span>
                  <span className="client-hero-pill">Money decisions</span>
                  <span className="client-hero-pill">Side‑project bets</span>
                  <span className="client-hero-pill">Life planning</span>
                </div>

                <div className="client-hero-cta-row">
                  <button
                    className="client-btn client-btn-primary"
                    onClick={() => go('/experts')}
                  >
                    Start a session
                  </button>
                  <button
                    className="client-btn client-btn-outline"
                    onClick={() => go('/support')}
                  >
                    Talk to support
                  </button>
                </div>

                <p className="client-hero-meta">
                  No subscriptions • Pay per engagement • Private 1‑to‑1 rooms
                </p>
              </div>

              {/* Hero card */}
              <aside
                className="client-hero-card"
                aria-labelledby="client-hero-card-heading"
              >
                <div className="client-hero-card-header">
                  <div className="client-hero-avatar">
                    <span>{usernameInitial}</span>
                  </div>
                  <div className="client-hero-card-titleblock">
                    <h2 id="client-hero-card-heading">{userData.username}</h2>
                    <p>Solvenut client • Member since {memberSince}</p>
                  </div>
                </div>

                <div className="client-hero-stats">
                  <div className="client-hero-stat">
                    <div className="client-hero-stat-label">Total sessions</div>
                    <div className="client-hero-stat-value">
                      {totalSessions}
                    </div>
                  </div>
                  <div className="client-hero-stat">
                    <div className="client-hero-stat-label">
                      Active focus areas
                    </div>
                    <div className="client-hero-stat-value">
                      {activeFocusAreas}
                    </div>
                  </div>
                  <div className="client-hero-stat">
                    <div className="client-hero-stat-label">
                      Primary decision lane
                    </div>
                    <div className="client-hero-stat-value client-hero-stat-small">
                      {userData.focusArea}
                    </div>
                  </div>
                </div>

                <div className="client-hero-footer">
                  <p>
                    Your dashboard is the steady base‑camp you come back to as
                    your work, money, and life decisions evolve.
                  </p>
                </div>
              </aside>
            </div>
          </section>

          {/* SNAPSHOT + HOW TO USE */}
          <section className="client-section" id="client-how-section">
            <div className="client-section-head">
              <p className="client-section-kicker">Your space at a glance</p>
              <h2 className="client-section-title">
                Snapshot and how to get the most from Solvenut.
              </h2>
              <p className="client-section-sub">
                Keep your key details in one place, and treat this space as the
                “control room” for your next 3–6 months of decisions.
              </p>
            </div>

            <div className="client-two-grid">
              {/* Client snapshot */}
              <div className="client-card">
                <h3 className="client-card-title">Client snapshot</h3>
                <p className="client-card-sub">
                  The basics experts look at before they talk to you.
                </p>

                <div className="client-snapshot-list">
                  <div className="client-snapshot-row">
                    <Mail size={16} />
                    <span>{userData.email}</span>
                  </div>
                  <div className="client-snapshot-row">
                    <Phone size={16} />
                    <span>{userData.phone}</span>
                  </div>
                  <div className="client-snapshot-row">
                    <MapPin size={16} />
                    <span>{userData.location}</span>
                  </div>
                  <div className="client-snapshot-row">
                    <Briefcase size={16} />
                    <span>{userData.focusArea}</span>
                  </div>
                  <div className="client-snapshot-row">
                    <CalendarDays size={16} />
                    <span>Member since {memberSince}</span>
                  </div>
                </div>

                <div className="client-notes-block">
                  <div className="client-notes-label">
                    What you’re currently exploring
                  </div>
                  <p className="client-notes-body">
                    Use this dashboard as the place where you park the big
                    questions on your mind — job moves, salary or comp
                    decisions, switching cities, taking a sabbatical, or
                    ramping a side‑project.
                  </p>
                </div>

                <button
                  className="client-btn client-btn-outline client-btn-full"
                  onClick={() => go('/settings')}
                >
                  Edit account details
                </button>
              </div>

              {/* How to use */}
              <div className="client-card">
                <h3 className="client-card-title">Best way to use this space</h3>
                <p className="client-card-sub">
                  A simple flow so you’re not just venting, but actually moving.
                </p>

                <ol className="client-steps-list">
                  <li>
                    Pick one real decision that feels stuck — not ten things at
                    once.
                  </li>
                  <li>
                    Write your context honestly, including constraints and
                    non‑negotiables.
                  </li>
                  <li>
                    Shortlist 1–3 experts whose backgrounds match your reality,
                    not just their titles.
                  </li>
                  <li>
                    Do focused sessions around that one decision and leave with
                    a 30–90 day plan.
                  </li>
                  <li>
                    Come back here to adjust your plan as you learn more.
                  </li>
                </ol>

                <div className="client-mini-card">
                  <p>
                    Clients who treat this dashboard as a living workspace — not
                    a static profile — get the most value from Solvenut.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* PROFILE & WORKING STYLE */}
          <section
            className="client-section client-section-alt"
            id="client-profile-section"
          >
            <div className="client-section-head">
              <p className="client-section-kicker">How experts see you</p>
              <h2 className="client-section-title">
                Your profile and preferred working style.
              </h2>
            </div>

            <div className="client-two-grid">
              {/* Profile summary */}
              <div className="client-card flat">
                <div className="client-profile-head">
                  <div className="client-profile-avatar">
                    {usernameInitial}
                  </div>
                  <div>
                    <div className="client-profile-name">
                      {userData.username}
                    </div>
                    <div className="client-profile-meta">
                      {userData.email} • Member since {memberSince}
                    </div>
                    <div className="client-profile-meta">
                      Role: {userData.role} • Focus: {userData.focusArea}
                    </div>
                  </div>
                </div>

                <div className="client-profile-stats">
                  <div className="client-profile-stat">
                    <div className="client-profile-stat-number">
                      {totalSessions}
                    </div>
                    <div className="client-profile-stat-label">
                      Total sessions
                    </div>
                  </div>
                  <div className="client-profile-stat">
                    <div className="client-profile-stat-number">4.9</div>
                    <div className="client-profile-stat-label">
                      Avg expert rating
                    </div>
                  </div>
                  <div className="client-profile-stat">
                    <div className="client-profile-stat-number">
                      {activeFocusAreas}
                    </div>
                    <div className="client-profile-stat-label">
                      Active focus areas
                    </div>
                  </div>
                </div>

                <div className="client-profile-actions">
                  <button
                    className="client-btn client-btn-ghost"
                    onClick={() => go('/settings')}
                  >
                    Edit profile
                  </button>
                  <button
                    className="client-btn client-btn-outline"
                    onClick={() => go('/experts')}
                  >
                    View expert directory
                  </button>
                </div>
              </div>

              {/* Working style */}
              <div className="client-card flat">
                <h3 className="client-card-title">How to work with you</h3>
                <p className="client-card-sub">
                  A short guide for experts so sessions feel sharp, not fluffy.
                </p>

                <ul className="client-working-list">
                  <li>
                    You prefer structured, actionable advice over generic
                    motivation or feel‑good pep talks.
                  </li>
                  <li>
                    You value experts who share their assumptions and
                    thought‑process, not just the answer.
                  </li>
                  <li>
                    You want clear trade‑offs, risks, and “if X, then Y”
                    branches — not one rigid recommendation.
                  </li>
                  <li>
                    You’re comfortable with honest feedback as long as it’s
                    anchored in your reality, not theory.
                  </li>
                  <li>
                    The most useful sessions leave you with 3–5 moves you can
                    actually calendar.
                  </li>
                </ul>

                {isLoggedIn ? (
                  <button
                    className="client-btn client-btn-primary client-btn-full"
                    onClick={() => go('/experts')}
                  >
                    Book your next session
                  </button>
                ) : (
                  <button
                    className="client-btn client-btn-primary client-btn-full"
                    onClick={() => go('/signup-client')}
                  >
                    Create your client account
                  </button>
                )}
              </div>
            </div>
          </section>

          {/* FINAL CTA */}
          <section className="client-section client-cta-section">
            <div className="client-cta-inner">
              <div className="client-cta-copy">
                <p className="client-section-kicker">Ready when you are</p>
                <h2 className="client-section-title">
                  One focused session can unblock your next 3–6 months.
                </h2>
                <p className="client-section-sub">
                  Use this dashboard as the start and end point of each
                  decision cycle — arrive with context, leave with a concrete
                  plan, and then come back to adjust.
                </p>
              </div>
              <div className="client-cta-actions">
                <button
                  className="client-btn client-btn-primary"
                  onClick={() =>
                    isLoggedIn ? go('/experts') : go('/signup-client')
                  }
                >
                  {isLoggedIn ? 'Find an expert' : 'Start as client'}
                </button>
                <button
                  className="client-btn client-btn-outline"
                  onClick={() => go('/support')}
                >
                  Ask a question first
                </button>
              </div>
            </div>
          </section>
        </div>
      </main>

      {/* FOOTER – reusing Home layout */}
      <footer className="client-footer" aria-label="Site footer">
        <div className="client-shell client-footer-row">
          <div className="client-footer-left">
            <div className="client-footer-brand">
              <span className="client-footer-logo">🥜</span>
              <span className="client-footer-name">Solvenut</span>
            </div>
            <p className="client-footer-text">
              Human experts + structured tools for real‑world decisions. Not a
              replacement for medical, legal, or emergency advice.
            </p>
            <div className="client-footer-badges">
              <span className="client-footer-badge">No subscriptions</span>
              <span className="client-footer-badge">
                Human + AI blended
              </span>
              <span className="client-footer-badge">Private by default</span>
            </div>
            <span className="client-footer-meta">
              © 2026 Solvenut. All rights reserved.
            </span>
          </div>

          <div className="client-footer-right">
            <div className="client-footer-col">
              <h4>Product</h4>
              <button onClick={() => go('/experts')}>Experts</button>
              <button onClick={() => go('/client-dashboard')}>
                Client dashboard
              </button>
              <button onClick={() => go('/pricing')}>Pricing</button>
            </div>
            <div className="client-footer-col">
              <h4>Company</h4>
              <button onClick={() => go('/about')}>About</button>
              <button onClick={() => go('/blog')}>Blog</button>
              <button onClick={() => go('/careers')}>Careers</button>
            </div>
            <div className="client-footer-col">
              <h4>Resources</h4>
              <button onClick={() => go('/use-cases')}>Use cases</button>
              <button onClick={() => go('/security')}>Security</button>
              <button onClick={() => go('/support')}>Support</button>
            </div>
            <div className="client-footer-col">
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

        <div className="client-shell client-footer-bottom">
          <div className="client-footer-links">
            <button onClick={() => go('/terms')}>Terms</button>
            <button onClick={() => go('/privacy')}>Privacy</button>
            <button onClick={() => go('/cookies')}>Cookies</button>
          </div>
          <div className="client-footer-social">
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

export default ClientDashboard;
