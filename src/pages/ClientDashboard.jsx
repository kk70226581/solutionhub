import React, { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Mail, Phone, MapPin, Briefcase, CalendarDays,
  MessageCircle, Rocket, ListChecks, CheckCircle2,
  Clock3, Sparkles, ArrowRight, TrendingUp, Target,
  BookOpen, Star, Bell, Settings, ChevronDown,
  Plus, Edit3, Trash2, BarChart3, Zap, Shield,
} from 'lucide-react';
import '../styles/ClientDashboard.css';
import ChatBot from '../components/ChatBot';

const API = import.meta.env.VITE_API_BASE || 'http://localhost:3000';

/* ── ChatBot styles injection ── */
const ChatBotStyles = `
.chatbot-overlay{position:fixed!important;inset:0!important;background:rgba(0,0,0,.65)!important;z-index:99999!important;display:flex!important;align-items:flex-end!important;justify-content:center!important;padding:1rem!important;backdrop-filter:blur(6px)!important;}
.chatbot-modal{background:white!important;border-radius:20px 20px 0 0!important;width:100%!important;max-width:520px!important;max-height:88vh!important;display:flex!important;flex-direction:column!important;box-shadow:0 -24px 80px rgba(0,0,0,.4)!important;animation:slideUp .3s cubic-bezier(.22,1,.36,1)!important;}
@keyframes slideUp{from{transform:translateY(100%);opacity:0}to{transform:none;opacity:1}}
.chatbot-header{display:flex!important;justify-content:space-between!important;align-items:center!important;padding:1.5rem 1.5rem 1rem!important;background:linear-gradient(135deg,#0d9488,#059669)!important;color:white!important;border-radius:20px 20px 0 0!important;}
.chatbot-title{font-size:1.15rem!important;font-weight:700!important;}
.chatbot-subtitle{font-size:.875rem!important;opacity:.88;margin-top:2px!important;}
.chatbot-close-btn,.chatbot-escalate-btn{padding:.65rem!important;border:none!important;border-radius:10px!important;background:rgba(255,255,255,.18)!important;color:white!important;cursor:pointer!important;}
.chatbot-messages{flex:1!important;padding:1.25rem!important;overflow-y:auto!important;background:#f8fafc!important;display:flex!important;flex-direction:column!important;}
.chatbot-message{margin-bottom:.875rem!important;display:flex!important;}
.chatbot-message.user{justify-content:flex-end!important;}
.chatbot-message-content{padding:.875rem 1.1rem!important;border-radius:18px!important;max-width:85%!important;font-size:.925rem!important;box-shadow:0 2px 8px rgba(0,0,0,.08)!important;}
.chatbot-message.assistant .chatbot-message-content{background:white!important;color:#374151!important;border-radius:18px 18px 6px 18px!important;}
.chatbot-message.user .chatbot-message-content{background:linear-gradient(135deg,#0d9488,#059669)!important;color:white!important;border-radius:18px 18px 6px 18px!important;}
.chatbot-input-container{padding:1rem 1.25rem 1.5rem!important;background:white!important;border-top:1px solid #e2e8f0!important;display:flex!important;gap:.875rem!important;}
.chatbot-input{flex:1!important;border:2px solid #e2e8f0!important;border-radius:14px!important;padding:.875rem 1rem!important;font-size:.95rem!important;resize:none!important;min-height:46px!important;max-height:140px!important;}
.chatbot-input:focus{outline:none!important;border-color:#0d9488!important;box-shadow:0 0 0 3px rgba(13,148,136,.1)!important;}
.chatbot-send-btn{width:48px!important;height:48px!important;border-radius:14px!important;border:none!important;background:linear-gradient(135deg,#0d9488,#059669)!important;color:white!important;cursor:pointer!important;}
.chatbot-typing-dots{display:flex!important;gap:4px!important;}
.chatbot-typing-dots span{width:9px!important;height:9px!important;border-radius:50%!important;background:#94a3b8!important;animation:dots 1.4s infinite ease-in-out!important;}
.chatbot-typing-dots span:nth-child(2){animation-delay:.2s!important;}
.chatbot-typing-dots span:nth-child(3){animation-delay:.4s!important;}
@keyframes dots{0%,60%,100%{transform:scale(1);opacity:.4}30%{transform:scale(1.3);opacity:1}}
`;

/* ── Intersection observer hook ── */
function useInView(threshold = 0.12) {
  const ref = useRef(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setInView(true); obs.disconnect(); } },
      { threshold }
    );
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [threshold]);
  return [ref, inView];
}

/* ── Animated counter hook ── */
function useCounter(target, duration = 1400, start = false) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!start) return;
    let t0 = null;
    const step = (ts) => {
      if (!t0) t0 = ts;
      const p = Math.min((ts - t0) / duration, 1);
      const e = 1 - Math.pow(1 - p, 3);
      setVal(Math.floor(e * target));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target, duration, start]);
  return val;
}

/* ── Status badge colors ── */
const STATUS_META = {
  'In review':     { color: '#22d3ee', bg: 'rgba(34,211,238,.1)',  border: 'rgba(34,211,238,.3)' },
  'Planning':      { color: '#fbbf24', bg: 'rgba(251,191,36,.1)',  border: 'rgba(251,191,36,.3)' },
  'Ready':         { color: '#34d399', bg: 'rgba(52,211,153,.1)',  border: 'rgba(52,211,153,.3)' },
  'On hold':       { color: '#a78bfa', bg: 'rgba(167,139,250,.1)', border: 'rgba(167,139,250,.3)' },
  'Completed':     { color: '#34d399', bg: 'rgba(52,211,153,.1)',  border: 'rgba(52,211,153,.3)' },
};

const STATUSES = ['Planning', 'In review', 'Ready', 'On hold', 'Completed'];

const ACTIVITY_ITEMS = [
  { icon: '🎯', text: 'Decision framed: Job switch analysis', time: '2h ago', color: '#22d3ee' },
  { icon: '💬', text: 'AI assistant session completed', time: '5h ago', color: '#34d399' },
  { icon: '📋', text: 'Action plan updated', time: '1d ago', color: '#fbbf24' },
  { icon: '🤝', text: 'Expert session booked', time: '2d ago', color: '#a78bfa' },
  { icon: '✅', text: 'Milestone: Compensation research done', time: '3d ago', color: '#34d399' },
];

const TIPS = [
  'Define your decision in one clear sentence before booking a session.',
  'List your top 2 options and what would make you choose each one.',
  'Share your timeline — urgency changes what advice is most useful.',
  'Write down your biggest fear about each option before your session.',
  'Experts work best when you have context ready, not just a question.',
];

/* ═══════════════════════════════════════
   DECISION BOARD CARD
═══════════════════════════════════════ */
function BoardCard({ card, onEdit, onDelete, onStatusChange }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const meta = STATUS_META[card.status] || STATUS_META['Planning'];

  return (
    <article className="cd-board-card" style={{ '--card-accent': meta.color }}>
      <div className="cd-board-card-top">
        <div className="cd-board-card-accent-bar" />
        <div className="cd-board-card-body">
          <div className="cd-board-card-head">
            <h3 className="cd-board-card-title">{card.title}</h3>
            <div className="cd-board-card-menu-wrap">
              <button className="cd-board-card-menu-btn" onClick={() => setMenuOpen(v => !v)} aria-label="Card options">
                <span />
                <span />
                <span />
              </button>
              {menuOpen && (
                <div className="cd-board-card-menu">
                  <button onClick={() => { onEdit(card); setMenuOpen(false); }}>
                    <Edit3 size={13} /> Edit
                  </button>
                  <button onClick={() => { onDelete(card.id); setMenuOpen(false); }} className="cd-menu-danger">
                    <Trash2 size={13} /> Delete
                  </button>
                </div>
              )}
            </div>
          </div>

          <div className="cd-board-card-status-row">
            <span className="cd-board-status" style={{ color: meta.color, background: meta.bg, borderColor: meta.border }}>
              {card.status}
            </span>
            <div className="cd-board-card-meta">
              <Clock3 size={12} />
              <span>{card.eta}</span>
            </div>
          </div>

          <div className="cd-board-status-change">
            <span className="cd-board-status-label">Move to:</span>
            <div className="cd-board-status-pills">
              {STATUSES.filter(s => s !== card.status).map(s => {
                const sm = STATUS_META[s];
                return (
                  <button key={s} className="cd-status-pill" style={{ color: sm.color, borderColor: sm.border }}
                    onClick={() => onStatusChange(card.id, s)}>
                    {s}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
      <div className="cd-board-card-footer">
        <button className="cd-board-card-cta">
          <Rocket size={13} />
          Refine with expert
        </button>
      </div>
    </article>
  );
}

/* ═══════════════════════════════════════
   ADD / EDIT DECISION MODAL
═══════════════════════════════════════ */
function DecisionModal({ card, onSave, onClose }) {
  const [title, setTitle] = useState(card?.title || '');
  const [status, setStatus] = useState(card?.status || 'Planning');
  const [eta, setEta] = useState(card?.eta || '');
  const isEdit = Boolean(card?.id);

  const handleSave = () => {
    if (!title.trim()) return;
    onSave({ id: card?.id || Date.now(), title: title.trim(), status, eta: eta.trim() || 'No deadline set' });
  };

  return (
    <div className="cd-modal-overlay" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="cd-modal">
        <div className="cd-modal-head">
          <h3>{isEdit ? 'Edit decision' : 'Add new decision'}</h3>
          <button className="cd-modal-close" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="cd-modal-body">
          <div className="cd-field">
            <label className="cd-field-label">Decision topic *</label>
            <input
              className="cd-field-input"
              placeholder="e.g. Should I switch jobs this quarter?"
              value={title}
              onChange={e => setTitle(e.target.value)}
              autoFocus
            />
          </div>
          <div className="cd-field-row">
            <div className="cd-field">
              <label className="cd-field-label">Status</label>
              <div className="cd-field-select-wrap">
                <select className="cd-field-select" value={status} onChange={e => setStatus(e.target.value)}>
                  {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <ChevronDown size={13} className="cd-field-select-arrow" />
              </div>
            </div>
            <div className="cd-field">
              <label className="cd-field-label">Timeline</label>
              <input
                className="cd-field-input"
                placeholder="e.g. This week"
                value={eta}
                onChange={e => setEta(e.target.value)}
              />
            </div>
          </div>
        </div>
        <div className="cd-modal-foot">
          <button className="cd-btn cd-btn-ghost" onClick={onClose}>Cancel</button>
          <button className="cd-btn cd-btn-primary" onClick={handleSave} disabled={!title.trim()}>
            {isEdit ? 'Save changes' : 'Add decision'}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════
   MAIN COMPONENT
═══════════════════════════════════════ */
const ClientDashboard = () => {
  const navigate = useNavigate();

  /* ── Inject chatbot styles ── */
  useEffect(() => {
    const s = document.createElement('style');
    s.textContent = ChatBotStyles;
    document.head.appendChild(s);
    return () => document.head.removeChild(s);
  }, []);

  /* ── Auth ── */
  const token = localStorage.getItem('token');
  const email = localStorage.getItem('email');
  const name  = localStorage.getItem('username') || localStorage.getItem('name');
  const isLoggedIn = Boolean(token && email);

  /* ── User data ── */
  const [userData] = useState({
    username: name || 'Client',
    email: email || 'you@example.com',
    phone: '+91-98765-43210',
    location: 'Lucknow, Uttar Pradesh',
    focusArea: 'Career and Side Projects',
    reqCount: parseInt(localStorage.getItem('reqCount') || '0', 10) || 0,
  });

  /* ── UI state ── */
  const [chatOpen, setChatOpen] = useState(false);
  const [headerScrolled, setHeaderScrolled] = useState(false);
  const [heroVisible, setHeroVisible] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [tipIndex, setTipIndex] = useState(0);
  const [activityIndex, setActivityIndex] = useState(0);

  /* ── Decision board state ── */
  const [decisions, setDecisions] = useState([
    { id: 1, title: 'Should I switch jobs this quarter?', status: 'In review', eta: 'This week' },
    { id: 2, title: 'Side project monetization plan', status: 'Planning', eta: 'Next 14 days' },
    { id: 3, title: 'Compensation negotiation strategy', status: 'Ready', eta: 'Actionable now' },
  ]);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingCard, setEditingCard] = useState(null);
  const [boardFilter, setBoardFilter] = useState('all');

  /* ── Stats ── */
  const [statsRef, statsInView] = useInView(0.3);
  const totalSessions   = userData.reqCount;
  const profileStrength = Math.min(95, 55 + totalSessions * 8);
  const sessionsCount   = useCounter(totalSessions || 3, 1200, statsInView);
  const profilePct      = useCounter(profileStrength, 1600, statsInView);
  const decisionsCount  = useCounter(decisions.length, 1000, statsInView);

  const memberSince = useMemo(() => '2025', []);
  const usernameInitial = (userData.username?.trim()?.charAt(0) || 'C').toUpperCase();

  /* ── Scroll / entrance ── */
  useEffect(() => {
    const t = setTimeout(() => setHeroVisible(true), 60);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    const fn = () => setHeaderScrolled(window.scrollY > 20);
    window.addEventListener('scroll', fn, { passive: true });
    return () => window.removeEventListener('scroll', fn);
  }, []);

  /* ── Auto-rotate tip & activity ── */
  useEffect(() => {
    const t = setInterval(() => setTipIndex(v => (v + 1) % TIPS.length), 5000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const t = setInterval(() => setActivityIndex(v => (v + 1) % ACTIVITY_ITEMS.length), 3200);
    return () => clearInterval(t);
  }, []);

  /* ── Decision board handlers ── */
  const filteredDecisions = useMemo(() => {
    if (boardFilter === 'all') return decisions;
    return decisions.filter(d => d.status === boardFilter);
  }, [decisions, boardFilter]);

  const handleSaveDecision = useCallback((card) => {
    setDecisions(prev => {
      const exists = prev.find(d => d.id === card.id);
      return exists ? prev.map(d => d.id === card.id ? card : d) : [...prev, card];
    });
    setModalOpen(false);
    setEditingCard(null);
  }, []);

  const handleDeleteDecision = useCallback((id) => {
    setDecisions(prev => prev.filter(d => d.id !== id));
  }, []);

  const handleStatusChange = useCallback((id, status) => {
    setDecisions(prev => prev.map(d => d.id === id ? { ...d, status } : d));
  }, []);

  /* ── Helpers ── */
  const go = useCallback((path) => navigate(path), [navigate]);

  const scrollTo = useCallback((id) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  const handleLogout = () => {
    ['token', 'email', 'name', 'username', 'role'].forEach(k => localStorage.removeItem(k));
    navigate('/login');
  };

  return (
    <div className="cd-page">
      {/* ── Canvas ── */}
      <div className="cd-canvas" aria-hidden>
        <div className="cd-orb cd-orb-1" />
        <div className="cd-orb cd-orb-2" />
        <div className="cd-orb cd-orb-3" />
        <div className="cd-grid" />
      </div>

      {/* ══════ HEADER ══════ */}
      <header className={`cd-header ${headerScrolled ? 'cd-header--scrolled' : ''}`} role="banner">
        <div className="cd-shell cd-header-inner">
          <button className="cd-logo" onClick={() => go('/')} aria-label="Solvenut home">
            <div className="cd-logo-mark">🥜</div>
            <div className="cd-logo-info">
              <span className="cd-logo-name">Solve<span className="cd-logo-accent">nut</span></span>
              <span className="cd-logo-sub">Client workspace</span>
            </div>
          </button>

          <nav className="cd-nav" aria-label="Dashboard navigation">
            <button className="cd-nav-link cd-nav-link--active" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>Overview</button>
            <button className="cd-nav-link" onClick={() => scrollTo('cd-board-section')}>Decision board</button>
            <button className="cd-nav-link" onClick={() => scrollTo('cd-profile-section')}>Profile</button>
          </nav>

          <div className="cd-header-right">
            {/* Notification bell */}
            <div className="cd-notif-wrap">
              <button className="cd-notif-btn" onClick={() => setNotifOpen(v => !v)} aria-label="Notifications">
                <Bell size={16} />
                <span className="cd-notif-dot" />
              </button>
              {notifOpen && (
                <div className="cd-notif-panel">
                  <div className="cd-notif-head">Notifications</div>
                  {ACTIVITY_ITEMS.slice(0, 3).map((item, i) => (
                    <div key={i} className="cd-notif-item">
                      <span className="cd-notif-icon">{item.icon}</span>
                      <div>
                        <div className="cd-notif-text">{item.text}</div>
                        <div className="cd-notif-time">{item.time}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <button className="cd-btn cd-btn-ghost" onClick={() => go('/experts')}>Browse experts</button>
            {isLoggedIn
              ? <button className="cd-btn cd-btn-primary" onClick={handleLogout}>Logout</button>
              : <button className="cd-btn cd-btn-primary" onClick={() => go('/login')}>Log in</button>
            }
          </div>
        </div>
      </header>

      {/* ══════ MAIN ══════ */}
      <main className="cd-main">
        <div className="cd-shell">

          {/* ── HERO ── */}
          <section className={`cd-hero ${heroVisible ? 'cd-hero--visible' : ''}`}>
            <div className="cd-hero-layout">
              {/* Left copy */}
              <div className="cd-hero-copy">
                <div className="cd-hero-badge">
                  <span className="cd-hero-badge-dot" />
                  Client workspace
                </div>
                <h1 className="cd-hero-title">
                  Welcome back,
                  <span className="cd-hero-gradient"> {userData.username}</span>
                </h1>
                <p className="cd-hero-sub">
                  Your decision hub — track what you're working through, get expert guidance, and turn clarity into confident action.
                </p>

                <div className="cd-hero-tags">
                  {['Career decisions', 'Money strategy', 'Side project growth', 'Leadership clarity'].map(t => (
                    <span key={t} className="cd-tag">{t}</span>
                  ))}
                </div>

                <div className="cd-hero-ctas">
                  <button className="cd-btn cd-btn-primary cd-btn-lg" onClick={() => go('/experts')}>
                    <Rocket size={16} />
                    Find an expert
                  </button>
                  <button className="cd-btn cd-btn-outline cd-btn-lg" onClick={() => setChatOpen(true)}>
                    <MessageCircle size={16} />
                    Ask AI first
                  </button>
                </div>

                {/* Rotating tip */}
                <div className="cd-tip-strip">
                  <div className="cd-tip-icon"><Zap size={13} /></div>
                  <p className="cd-tip-text">{TIPS[tipIndex]}</p>
                </div>
              </div>

              {/* Right profile card */}
              <div className="cd-hero-card">
                <div className="cd-profile-card-top">
                  <div className="cd-profile-avatar">{usernameInitial}</div>
                  <div className="cd-profile-info">
                    <h2 className="cd-profile-name">{userData.username}</h2>
                    <div className="cd-profile-role">Client · Member since {memberSince}</div>
                  </div>
                  <button className="cd-profile-settings" onClick={() => go('/settings')} aria-label="Settings">
                    <Settings size={15} />
                  </button>
                </div>

                <div className="cd-profile-stats-grid" ref={statsRef}>
                  {[
                    { icon: <BarChart3 size={16} />, value: sessionsCount, label: 'Sessions', color: '#22d3ee' },
                    { icon: <Target size={16} />, value: decisionsCount, label: 'Decisions', color: '#34d399' },
                    { icon: <TrendingUp size={16} />, value: `${profilePct}%`, label: 'Readiness', color: '#fbbf24', noAnim: true },
                  ].map(({ icon, value, label, color }) => (
                    <div key={label} className="cd-profile-stat" style={{ '--stat-color': color }}>
                      <div className="cd-profile-stat-icon">{icon}</div>
                      <div className="cd-profile-stat-value">{statsInView ? value : 0}</div>
                      <div className="cd-profile-stat-label">{label}</div>
                    </div>
                  ))}
                </div>

                {/* Progress bar */}
                <div className="cd-progress-section">
                  <div className="cd-progress-header">
                    <span>Decision readiness</span>
                    <span className="cd-progress-pct">{statsInView ? profilePct : 0}%</span>
                  </div>
                  <div className="cd-progress-track">
                    <div className="cd-progress-fill" style={{ width: statsInView ? `${profileStrength}%` : '0%' }} />
                  </div>
                  <p className="cd-progress-hint">
                    {profileStrength < 70 ? 'Complete your profile to unlock better expert matching.' : 'Great readiness! Book a session to take next steps.'}
                  </p>
                </div>

                {/* Focus area */}
                <div className="cd-focus-row">
                  <div className="cd-focus-label">Primary focus</div>
                  <div className="cd-focus-value">
                    <Briefcase size={13} />
                    {userData.focusArea}
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* ── STATS BAR ── */}
          <div className="cd-stats-bar">
            {[
              { icon: <BookOpen size={18} />, value: '3+', label: 'Active decisions', color: '#22d3ee' },
              { icon: <Star size={18} />, value: '4.9', label: 'Avg expert rating', color: '#fbbf24' },
              { icon: <Shield size={18} />, value: '100%', label: 'Session privacy', color: '#34d399' },
              { icon: <Zap size={18} />, value: '<24h', label: 'Expert response', color: '#a78bfa' },
            ].map(({ icon, value, label, color }) => (
              <div key={label} className="cd-stat-bar-item">
                <div className="cd-stat-bar-icon" style={{ color }}>{icon}</div>
                <div className="cd-stat-bar-value" style={{ color }}>{value}</div>
                <div className="cd-stat-bar-label">{label}</div>
              </div>
            ))}
          </div>

          {/* ── QUICK ACTIONS ── */}
          <section className="cd-section">
            <div className="cd-section-head">
              <div className="cd-kicker">Quick actions</div>
              <h2 className="cd-section-title">Do the next best thing right now</h2>
            </div>
            <div className="cd-quick-grid">
              {[
                {
                  icon: <Rocket size={20} />, color: '#22d3ee',
                  title: 'Find the right expert',
                  sub: 'Browse vetted domain experts matched to your decision type.',
                  cta: 'Browse experts', onClick: () => go('/experts'),
                },
                {
                  icon: <Sparkles size={20} />, color: '#fbbf24',
                  title: 'Ask the AI assistant',
                  sub: 'Get a structured first-draft analysis before booking a session.',
                  cta: 'Open AI chat', onClick: () => setChatOpen(true),
                },
                {
                  icon: <Plus size={20} />, color: '#34d399',
                  title: 'Add a decision',
                  sub: 'Log a new decision to your board and track it to resolution.',
                  cta: 'Add decision', onClick: () => { setEditingCard(null); setModalOpen(true); },
                },
                {
                  icon: <ListChecks size={20} />, color: '#a78bfa',
                  title: 'Prep for your session',
                  sub: 'Complete the readiness checklist to maximise your expert session.',
                  cta: 'View checklist', onClick: () => scrollTo('cd-profile-section'),
                },
              ].map(({ icon, color, title, sub, cta, onClick }) => (
                <button key={title} className="cd-quick-card" onClick={onClick} style={{ '--q-color': color }}>
                  <div className="cd-quick-icon-wrap" style={{ color, background: `${color}18` }}>{icon}</div>
                  <div className="cd-quick-text">
                    <div className="cd-quick-title">{title}</div>
                    <div className="cd-quick-sub">{sub}</div>
                  </div>
                  <div className="cd-quick-cta">{cta} <ArrowRight size={13} /></div>
                </button>
              ))}
            </div>
          </section>

          {/* ── DECISION BOARD ── */}
          <section className="cd-section" id="cd-board-section">
            <div className="cd-section-head">
              <div className="cd-kicker">Decision board</div>
              <h2 className="cd-section-title">Everything you're working through</h2>
              <p className="cd-section-sub">Experts see your board before sessions — keep it current for better guidance.</p>
            </div>

            {/* Board controls */}
            <div className="cd-board-controls">
              <div className="cd-board-filters">
                <button className={`cd-board-filter ${boardFilter === 'all' ? 'cd-board-filter--active' : ''}`}
                  onClick={() => setBoardFilter('all')}>
                  All ({decisions.length})
                </button>
                {STATUSES.map(s => {
                  const count = decisions.filter(d => d.status === s).length;
                  if (!count) return null;
                  const meta = STATUS_META[s];
                  return (
                    <button key={s}
                      className={`cd-board-filter ${boardFilter === s ? 'cd-board-filter--active' : ''}`}
                      style={boardFilter === s ? { color: meta.color, borderColor: meta.border } : {}}
                      onClick={() => setBoardFilter(s)}>
                      {s} ({count})
                    </button>
                  );
                })}
              </div>
              <button className="cd-btn cd-btn-primary cd-btn-sm" onClick={() => { setEditingCard(null); setModalOpen(true); }}>
                <Plus size={14} />
                Add decision
              </button>
            </div>

            {filteredDecisions.length === 0 ? (
              <div className="cd-board-empty">
                <div className="cd-board-empty-icon">📋</div>
                <p>No decisions in this category yet.</p>
                <button className="cd-btn cd-btn-outline" onClick={() => setBoardFilter('all')}>Show all</button>
              </div>
            ) : (
              <div className="cd-board-grid">
                {filteredDecisions.map(card => (
                  <BoardCard
                    key={card.id}
                    card={card}
                    onEdit={c => { setEditingCard(c); setModalOpen(true); }}
                    onDelete={handleDeleteDecision}
                    onStatusChange={handleStatusChange}
                  />
                ))}
                {/* Add new card placeholder */}
                <button className="cd-board-add-card" onClick={() => { setEditingCard(null); setModalOpen(true); }}>
                  <Plus size={22} />
                  <span>Add decision</span>
                </button>
              </div>
            )}
          </section>

          {/* ── ACTIVITY + TIP ── */}
          <section className="cd-section">
            <div className="cd-two-col">
              {/* Recent activity */}
              <div className="cd-card">
                <div className="cd-card-head">
                  <h3 className="cd-card-title">Recent activity</h3>
                  <span className="cd-live-pill"><span className="cd-live-dot" />Live</span>
                </div>
                <div className="cd-activity-list">
                  {ACTIVITY_ITEMS.map((item, i) => (
                    <div key={i} className={`cd-activity-item ${i === activityIndex ? 'cd-activity-item--active' : ''}`}>
                      <div className="cd-activity-icon-wrap" style={{ background: `${item.color}18`, color: item.color }}>
                        {item.icon}
                      </div>
                      <div className="cd-activity-text-col">
                        <span className="cd-activity-text">{item.text}</span>
                        <span className="cd-activity-time">{item.time}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Session prep checklist */}
              <div className="cd-card" id="cd-profile-section">
                <div className="cd-card-head">
                  <h3 className="cd-card-title">Session readiness</h3>
                  <span className="cd-card-badge">4 steps</span>
                </div>
                <div className="cd-checklist">
                  {[
                    { text: 'Define one clear decision outcome', done: true },
                    { text: 'Add your current constraints', done: true },
                    { text: 'List your top 2 options', done: false },
                    { text: 'Share timeline and urgency', done: false },
                  ].map(({ text, done }) => (
                    <div key={text} className={`cd-checklist-item ${done ? 'cd-checklist-item--done' : ''}`}>
                      <CheckCircle2 size={16} />
                      <span>{text}</span>
                    </div>
                  ))}
                </div>
                <div className="cd-checklist-progress">
                  <div className="cd-checklist-bar">
                    <div className="cd-checklist-fill" style={{ width: '50%' }} />
                  </div>
                  <span className="cd-checklist-pct">2 / 4 complete</span>
                </div>
                <button className="cd-btn cd-btn-primary cd-btn-full" onClick={() => go('/experts')}>
                  <Rocket size={14} />
                  Book next session
                </button>
              </div>
            </div>
          </section>

          {/* ── PROFILE DETAILS ── */}
          <section className="cd-section cd-section-alt">
            <div className="cd-section-head">
              <div className="cd-kicker">Profile</div>
              <h2 className="cd-section-title">Your context card for faster sessions</h2>
              <p className="cd-section-sub">Experts review this before sessions — keep it accurate for better guidance.</p>
            </div>
            <div className="cd-profile-grid">
              <div className="cd-card">
                <div className="cd-card-head">
                  <h3 className="cd-card-title">Contact details</h3>
                  <button className="cd-card-edit-btn" onClick={() => go('/settings')}>
                    <Edit3 size={13} /> Edit
                  </button>
                </div>
                <div className="cd-profile-rows">
                  {[
                    { icon: <Mail size={15} />, label: 'Email', value: userData.email },
                    { icon: <Phone size={15} />, label: 'Phone', value: userData.phone },
                    { icon: <MapPin size={15} />, label: 'Location', value: userData.location },
                    { icon: <Briefcase size={15} />, label: 'Focus area', value: userData.focusArea },
                    { icon: <CalendarDays size={15} />, label: 'Member since', value: memberSince },
                  ].map(({ icon, label, value }) => (
                    <div key={label} className="cd-profile-row">
                      <div className="cd-profile-row-icon">{icon}</div>
                      <div className="cd-profile-row-content">
                        <span className="cd-profile-row-label">{label}</span>
                        <span className="cd-profile-row-value">{value}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="cd-card">
                <div className="cd-card-head">
                  <h3 className="cd-card-title">What experts know about you</h3>
                </div>
                <div className="cd-context-chips">
                  {['Career growth focus', 'Open to relocation', 'Tech industry', 'Early-stage side project', 'Mid-career professional', 'Risk-moderate'].map(chip => (
                    <span key={chip} className="cd-context-chip">{chip}</span>
                  ))}
                </div>
                <p className="cd-context-hint">
                  These context signals help experts tailor their advice to your specific situation.
                  <button className="cd-context-edit" onClick={() => go('/settings')}>Update context →</button>
                </p>
              </div>
            </div>
          </section>

          {/* ── CTA BANNER ── */}
          <section className="cd-cta-banner">
            <div className="cd-cta-glow" aria-hidden />
            <div className="cd-cta-content">
              <div className="cd-kicker" style={{ color: 'rgba(34,211,238,.8)' }}>Ready to move forward</div>
              <h2 className="cd-cta-title">Turn your next decision into a clear plan.</h2>
              <p className="cd-cta-sub">Pick an expert, run a focused session, and walk away with a written roadmap.</p>
              <div className="cd-cta-actions">
                <button className="cd-btn cd-btn-primary cd-btn-lg" onClick={() => go('/experts')}>
                  <Rocket size={16} />
                  Browse experts
                </button>
                <button className="cd-btn cd-btn-outline cd-btn-lg" onClick={() => setChatOpen(true)}>
                  <Sparkles size={16} />
                  Try AI first
                </button>
              </div>
              <div className="cd-cta-trust">
                <span>✓ Vetted experts only</span>
                <span>✓ Private sessions</span>
                <span>✓ Actionable output</span>
              </div>
            </div>
          </section>

        </div>{/* /shell */}
      </main>

      {/* ══════ FOOTER ══════ */}
      <footer className="cd-footer" aria-label="Site footer">
        <div className="cd-shell cd-footer-main">
          <div className="cd-footer-brand-col">
            <div className="cd-footer-logo">
              <span className="cd-footer-logo-mark">🥜</span>
              <span className="cd-footer-brand-name">Solve<span>nut</span></span>
            </div>
            <p className="cd-footer-desc">Decision support that combines expert insight, structure, and practical execution plans.</p>
            <div className="cd-footer-badges">
              {['Client focused', 'Practical outcomes', 'Private sessions'].map(b => (
                <span key={b} className="cd-footer-badge">{b}</span>
              ))}
            </div>
          </div>
          <div className="cd-footer-nav-grid">
            {[
              { heading: 'Platform', links: [{ l: 'Browse experts', p: '/experts' }, { l: 'Client dashboard', p: '/client-dashboard' }, { l: 'Expert dashboard', p: '/expert-dashboard' }] },
              { heading: 'Account', links: isLoggedIn
                  ? [{ l: 'Dashboard', p: '/client-dashboard' }, { l: 'Settings', p: '/settings' }]
                  : [{ l: 'Log in', p: '/login' }, { l: 'Get started', p: '/signup-client' }]
              },
            ].map(({ heading, links }) => (
              <div key={heading} className="cd-footer-col">
                <h4>{heading}</h4>
                {links.map(({ l, p }) => <button key={l} onClick={() => go(p)}>{l}</button>)}
                {heading === 'Account' && isLoggedIn && (
                  <button onClick={handleLogout}>Logout</button>
                )}
              </div>
            ))}
          </div>
        </div>
        <div className="cd-shell cd-footer-bottom">
          <span>© 2026 Solvenut. All rights reserved.</span>
          <div className="cd-footer-social">
            <a href="https://x.com" target="_blank" rel="noreferrer">X</a>
            <a href="https://linkedin.com" target="_blank" rel="noreferrer">LinkedIn</a>
            <a href="mailto:hello@solvenut.com">Email</a>
          </div>
        </div>
      </footer>

      {/* ── ChatBot ── */}
      <ChatBot
        open={chatOpen}
        onClose={() => setChatOpen(false)}
        onEscalate={() => { setChatOpen(false); go('/experts'); }}
        user={{ name: userData.username, email: userData.email }}
      />

      {/* ── Decision modal ── */}
      {modalOpen && (
        <DecisionModal
          card={editingCard}
          onSave={handleSaveDecision}
          onClose={() => { setModalOpen(false); setEditingCard(null); }}
        />
      )}
    </div>
  );
};

export default ClientDashboard;