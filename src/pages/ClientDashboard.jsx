import React, { useMemo, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Mail,
  Phone,
  MapPin,
  Briefcase,
  CalendarDays,
  MessageCircle,
  Rocket,
  ListChecks,
  CheckCircle2,
  Clock3,
  Sparkles,
  ArrowRight,
} from 'lucide-react';
import '../styles/ClientDashboard.css';
import ChatBot from '../components/ChatBot';

const ChatBotStyles = `
.chatbot-overlay { position: fixed !important; inset: 0 !important; background: rgba(0, 0, 0, 0.6) !important; z-index: 99999 !important; display: flex !important; align-items: flex-end !important; justify-content: center !important; padding: 1rem !important; }
.chatbot-modal { background: white !important; border-radius: 20px 20px 0 0 !important; width: 100% !important; max-width: 500px !important; max-height: 85vh !important; display: flex !important; flex-direction: column !important; box-shadow: 0 -20px 60px rgba(0,0,0,0.3) !important; animation: slideUp 0.3s ease-out !important; }
@keyframes slideUp { from { transform: translateY(100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
.chatbot-header { display: flex !important; justify-content: space-between !important; align-items: center !important; padding: 1.5rem 1.5rem 1rem !important; background: linear-gradient(135deg, #4f46e5, #7c3aed) !important; color: white !important; border-radius: 20px 20px 0 0 !important; }
.chatbot-title { font-size: 1.2rem !important; font-weight: 700 !important; }
.chatbot-subtitle { font-size: 0.9rem !important; opacity: 0.9; margin-top: 2px !important; }
.chatbot-close-btn, .chatbot-escalate-btn { padding: 0.75rem !important; border: none !important; border-radius: 12px !important; background: rgba(255,255,255,0.2) !important; color: white !important; cursor: pointer !important; }
.chatbot-messages { flex: 1 !important; padding: 1.5rem !important; overflow-y: auto !important; background: #f8fafc !important; display: flex !important; flex-direction: column !important; }
.chatbot-message { margin-bottom: 1rem !important; display: flex !important; }
.chatbot-message.user { justify-content: flex-end !important; }
.chatbot-message-content { padding: 1rem 1.25rem !important; border-radius: 20px !important; max-width: 85% !important; font-size: 0.95rem !important; box-shadow: 0 2px 10px rgba(0,0,0,0.1) !important; }
.chatbot-message.assistant .chatbot-message-content { background: white !important; color: #374151 !important; border-radius: 20px 20px 6px 20px !important; }
.chatbot-message.user .chatbot-message-content { background: linear-gradient(135deg, #4f46e5, #7c3aed) !important; color: white !important; border-radius: 20px 20px 6px 20px !important; }
.chatbot-input-container { padding: 1.25rem 1.5rem 1.75rem !important; background: white !important; border-top: 1px solid #e2e8f0 !important; display: flex !important; gap: 1rem !important; }
.chatbot-input { flex: 1 !important; border: 2px solid #e2e8f0 !important; border-radius: 16px !important; padding: 1rem 1.25rem !important; font-size: 1rem !important; resize: vertical !important; min-height: 50px !important; max-height: 150px !important; }
.chatbot-input:focus { outline: none !important; border-color: #4f46e5 !important; box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1) !important; }
.chatbot-send-btn { width: 52px !important; height: 52px !important; border-radius: 16px !important; border: none !important; background: linear-gradient(135deg, #4f46e5, #7c3aed) !important; color: white !important; cursor: pointer !important; }
.chatbot-typing-dots { display: flex !important; gap: 4px !important; }
.chatbot-typing-dots span { width: 10px !important; height: 10px !important; border-radius: 50% !important; background: #94a3b8 !important; animation: dots 1.4s infinite ease-in-out !important; }
.chatbot-typing-dots span:nth-child(2) { animation-delay: 0.2s !important; }
.chatbot-typing-dots span:nth-child(3) { animation-delay: 0.4s !important; }
@keyframes dots { 0%, 60%, 100% { transform: scale(1); opacity: 0.4; } 30% { transform: scale(1.3); opacity: 1; } }
@media (max-width: 640px) { .chatbot-modal { border-radius: 20px 20px 0 0 !important; margin-bottom: 0 !important; } }
`;

const ClientDashboard = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const style = document.createElement('style');
    style.textContent = ChatBotStyles;
    document.head.appendChild(style);
    return () => {
      document.head.removeChild(style);
    };
  }, []);

  const token =
    typeof window !== 'undefined' ? localStorage.getItem('token') : null;
  const email =
    typeof window !== 'undefined' ? localStorage.getItem('email') : null;
  const name =
    typeof window !== 'undefined' ? localStorage.getItem('username') : null;

  const isLoggedIn = Boolean(token && email);

  const [userData] = useState({
    username: name || 'Client',
    email: email || 'you@example.com',
    phone: '+91-98765-43210',
    location: 'Lucknow, Uttar Pradesh',
    role: 'Client',
    focusArea: 'Career and Side Projects',
    reqCount:
      typeof window !== 'undefined'
        ? parseInt(localStorage.getItem('reqCount') || '0', 10) || 0
        : 0,
  });

  const memberSince = useMemo(() => '2025', []);
  const usernameInitial =
    userData.username?.trim()?.charAt(0)?.toUpperCase() || 'C';

  const totalSessions = userData.reqCount;
  const activeFocusAreas = 2;
  const profileStrength = Math.min(95, 55 + totalSessions * 8);

  const [chatOpen, setChatOpen] = useState(false);

  const quickActions = [
    {
      icon: <Rocket size={18} />,
      title: 'Find Best Expert',
      sub: 'Match with experts for your current decision',
      onClick: () => navigate('/experts'),
    },
    {
      icon: <Sparkles size={18} />,
      title: 'Ask AI First',
      sub: 'Get a quick draft before booking session',
      onClick: () => setChatOpen(true),
    },
    {
      icon: <ListChecks size={18} />,
      title: 'Update Context',
      sub: 'Keep your current goals and constraints fresh',
      onClick: () => navigate('/settings'),
    },
  ];

  const currentBoard = [
    {
      title: 'Should I switch jobs this quarter?',
      status: 'In review',
      eta: 'This week',
    },
    {
      title: 'Side project monetization plan',
      status: 'Planning',
      eta: 'Next 14 days',
    },
    {
      title: 'Compensation negotiation strategy',
      status: 'Ready',
      eta: 'Actionable now',
    },
  ];

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

      <header className="client-header" role="banner">
        <div className="client-shell client-header-inner">
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
                  .getElementById('client-board-section')
                  ?.scrollIntoView({ behavior: 'smooth' })
              }
            >
              Decision board
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

      <main className="client-main">
        <div className="client-shell">
          <section className="client-hero">
            <div className="client-hero-grid">
              <div className="client-hero-copy">
                <p className="client-hero-kicker">Client workspace</p>
                <h1 className="client-hero-title">
                  Clear dashboard for your next important decision.
                </h1>
                <p className="client-hero-sub">
                  Track decisions, prepare context, and take action with expert
                  guidance without clutter.
                </p>

                <div className="client-hero-pill-row">
                  <span className="client-hero-pill">Career decisions</span>
                  <span className="client-hero-pill">Money strategy</span>
                  <span className="client-hero-pill">Side project growth</span>
                </div>

                <div className="client-hero-cta-row">
                  <button
                    className="client-btn client-btn-primary"
                    onClick={() => go('/experts')}
                  >
                    Start session
                  </button>
                  <button
                    className="client-btn client-btn-outline"
                    onClick={() => setChatOpen(true)}
                  >
                    <MessageCircle size={16} />
                    Ask AI assistant
                  </button>
                </div>

                <div className="client-stat-strip">
                  <div className="client-stat-chip">
                    <span className="num">{totalSessions}</span>
                    <span className="lbl">sessions</span>
                  </div>
                  <div className="client-stat-chip">
                    <span className="num">{activeFocusAreas}</span>
                    <span className="lbl">focus areas</span>
                  </div>
                  <div className="client-stat-chip">
                    <span className="num">{profileStrength}%</span>
                    <span className="lbl">profile strength</span>
                  </div>
                </div>
              </div>

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
                    <p>Member since {memberSince}</p>
                  </div>
                </div>

                <div className="client-hero-stats">
                  <div className="client-hero-stat">
                    <div className="client-hero-stat-label">Primary lane</div>
                    <div className="client-hero-stat-value client-hero-stat-small">
                      {userData.focusArea}
                    </div>
                  </div>
                  <div className="client-hero-stat">
                    <div className="client-hero-stat-label">Next milestone</div>
                    <div className="client-hero-stat-value">Book 1 session</div>
                  </div>
                </div>

                <div className="client-progress">
                  <div className="client-progress-top">
                    <span>Decision readiness</span>
                    <span>{profileStrength}%</span>
                  </div>
                  <div className="client-progress-track">
                    <div
                      className="client-progress-fill"
                      style={{ width: `${profileStrength}%` }}
                    />
                  </div>
                </div>
              </aside>
            </div>
          </section>

          <section className="client-section client-section-default">
            <div className="client-section-head">
              <p className="client-section-kicker">Quick actions</p>
              <h2 className="client-section-title">Do the next best step now</h2>
            </div>
            <div className="client-quick-grid">
              {quickActions.map((item) => (
                <button
                  key={item.title}
                  className="client-quick-card"
                  onClick={item.onClick}
                >
                  <div className="client-quick-icon">{item.icon}</div>
                  <div className="client-quick-copy">
                    <div className="client-quick-title">{item.title}</div>
                    <div className="client-quick-sub">{item.sub}</div>
                  </div>
                  <ArrowRight size={16} />
                </button>
              ))}
            </div>
          </section>

          <section className="client-section" id="client-board-section">
            <div className="client-section-head">
              <p className="client-section-kicker">Decision board</p>
              <h2 className="client-section-title">
                Keep all active decisions in one place
              </h2>
              <p className="client-section-sub">
                This helps experts understand your current priorities quickly.
              </p>
            </div>
            <div className="client-board-grid">
              {currentBoard.map((card) => (
                <article key={card.title} className="client-board-card">
                  <div className="client-board-top">
                    <h3>{card.title}</h3>
                    <span className="client-board-status">{card.status}</span>
                  </div>
                  <div className="client-board-meta">
                    <Clock3 size={14} />
                    <span>{card.eta}</span>
                  </div>
                  <button className="client-btn client-btn-outline client-board-btn">
                    Refine with expert
                  </button>
                </article>
              ))}
            </div>
          </section>

          <section className="client-section client-section-alt" id="client-profile-section">
            <div className="client-section-head">
              <p className="client-section-kicker">Profile</p>
              <h2 className="client-section-title">
                Your context card for faster expert sessions
              </h2>
            </div>
            <div className="client-two-grid">
              <div className="client-card flat">
                <h3 className="client-card-title">Client details</h3>
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
                <button
                  className="client-btn client-btn-outline client-btn-full"
                  onClick={() => go('/settings')}
                >
                  Update profile
                </button>
              </div>

              <div className="client-card flat">
                <h3 className="client-card-title">Session readiness checklist</h3>
                <ul className="client-ready-list">
                  <li>
                    <CheckCircle2 size={16} /> Define one clear decision outcome
                  </li>
                  <li>
                    <CheckCircle2 size={16} /> Add your current constraints
                  </li>
                  <li>
                    <CheckCircle2 size={16} /> List top 2 options you are considering
                  </li>
                  <li>
                    <CheckCircle2 size={16} /> Share timeline and urgency
                  </li>
                </ul>
                <button
                  className="client-btn client-btn-primary client-btn-full"
                  onClick={() => go('/experts')}
                >
                  Book next session
                </button>
              </div>
            </div>
          </section>
        </div>
      </main>

      <footer className="client-footer" aria-label="Site footer">
        <div className="client-shell client-footer-row">
          <div className="client-footer-left">
            <div className="client-footer-brand">
              <span className="client-footer-logo">🥜</span>
              <span className="client-footer-name">Solvenut</span>
            </div>
            <p className="client-footer-text">
              Decision support that combines expert insight, structure, and
              practical execution.
            </p>
            <div className="client-footer-badges">
              <span className="client-footer-badge">Client focused</span>
              <span className="client-footer-badge">Practical outcomes</span>
              <span className="client-footer-badge">Private sessions</span>
            </div>
            <span className="client-footer-meta">
              © 2026 Solvenut. All rights reserved.
            </span>
          </div>

          <div className="client-footer-right">
            <div className="client-footer-col">
              <h4>Platform</h4>
              <button onClick={() => go('/experts')}>Experts</button>
              <button onClick={() => go('/client-dashboard')}>Dashboard</button>
              <button onClick={() => go('/support')}>Support</button>
            </div>
            <div className="client-footer-col">
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
      </footer>

      <ChatBot
        open={chatOpen}
        onClose={() => setChatOpen(false)}
        onEscalate={() => {
          setChatOpen(false);
          go('/experts');
        }}
        user={{ name: userData.username, email: userData.email }}
      />
    </div>
  );
};

export default ClientDashboard;
