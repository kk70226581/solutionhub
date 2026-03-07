
import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import io from 'socket.io-client';
import {
  TrendingUp, Star, Clock, MessageCircle, Users, Briefcase,
  DollarSign, BarChart3, Settings, Bell, Edit3, Eye, CheckCircle,
  XCircle, Calendar, Award, ArrowRight, Zap, Mail, MapPin, ArrowUp, ArrowDown, House, Send,
} from 'lucide-react';
import '../styles/ExpertDashboard.css';

const API = import.meta.env.VITE_API_BASE || 'https://solutionhub66.onrender.com';

const fmtInr = (n) => {
  const v = Number(n || 0);
  if (!Number.isFinite(v)) return 'INR 0';
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    maximumFractionDigits: 0,
  }).format(v);
};

const fmtShortInr = (n) => {
  const v = Number(n || 0);
  if (!Number.isFinite(v)) return 'INR 0';
  if (v >= 100000) return `INR ${(v / 100000).toFixed(1)}L`;
  if (v >= 1000) return `INR ${(v / 1000).toFixed(1)}k`;
  return `INR ${Math.round(v)}`;
};

const toNum = (v, d = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

const formatRelative = (ts) => {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' });
};

const monthKey = (d) => `${d.getFullYear()}-${String(d.getMonth()).padStart(2, '0')}`;
const toAssetUrl = (p) => {
  if (!p) return '';
  if (/^https?:\/\//i.test(p)) return p;
  const normalized = String(p).replace(/\\/g, '/').replace(/^\.?\//, '');
  return `${API}/${normalized}`;
};

function useInView(threshold = 0.15) {
  const ref = useRef(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) {
        setInView(true);
        obs.disconnect();
      }
    }, { threshold });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [threshold]);
  return [ref, inView];
}

function useCounter(target, duration = 1400, start = false) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!start || !target) return;
    let t0 = null;
    const step = (ts) => {
      if (!t0) t0 = ts;
      const p = Math.min((ts - t0) / duration, 1);
      const e = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(e * target));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target, duration, start]);
  return val;
}

const DOMAIN_COLORS = {
  programming: '#22d3ee', devops: '#34d399', academics: '#a78bfa',
  career: '#fbbf24', business: '#fb7185', medical: '#38bdf8', default: '#22d3ee',
};
function getDomainColor(field = '') {
  const f = String(field || '').toLowerCase();
  for (const [k, v] of Object.entries(DOMAIN_COLORS)) if (f.includes(k)) return v;
  return DOMAIN_COLORS.default;
}

const TIPS = [
  'Respond quickly to improve expert ranking.',
  'Keep your profile headline updated for better conversion.',
  'Clear session summaries improve repeat client rate.',
  'Use specific domain keywords in your profile field.',
  'Track pending payments weekly to avoid payout confusion.',
];
function SessionRow({ session }) {
  const STATUS = {
    upcoming: { label: 'Upcoming', color: '#22d3ee', bg: 'rgba(34,211,238,.1)', border: 'rgba(34,211,238,.3)' },
    completed: { label: 'Completed', color: '#34d399', bg: 'rgba(52,211,153,.1)', border: 'rgba(52,211,153,.3)' },
    cancelled: { label: 'Cancelled', color: '#fb7185', bg: 'rgba(251,113,133,.1)', border: 'rgba(251,113,133,.3)' },
  };
  const meta = STATUS[session.status] || STATUS.upcoming;

  return (
    <div className={`ed-session-row ed-session-row--${session.status}`}>
      <div className="ed-session-client">
        <div className="ed-session-avatar">{(session.client || 'C')[0].toUpperCase()}</div>
        <div>
          <div className="ed-session-name">{session.client}</div>
          <div className="ed-session-topic">{session.topic}</div>
        </div>
      </div>
      <div className="ed-session-date">
        <Calendar size={13} />
        {session.date}
      </div>
      {session.rating ? (
        <div className="ed-session-rating">
          {Array.from({ length: 5 }).map((_, i) => (
            <Star key={i} size={13} fill={i < session.rating ? '#fbbf24' : 'none'} color={i < session.rating ? '#fbbf24' : '#4b5563'} />
          ))}
        </div>
      ) : <div className="ed-session-rating-empty">—</div>}
      <div className="ed-session-amount" style={{ color: session.amount ? '#34d399' : '#4b5563' }}>
        {session.amount ? fmtInr(session.amount) : '—'}
      </div>
      <span className="ed-session-status-badge" style={{ color: meta.color, background: meta.bg, borderColor: meta.border }}>
        {meta.label}
      </span>
    </div>
  );
}

function EarningsChart({ data }) {
  const max = Math.max(...data.map(d => d.amount), 1);
  return (
    <div className="ed-chart">
      {data.map((d, i) => (
        <div key={`${d.month}-${i}`} className="ed-chart-col">
          <div className="ed-chart-bar-wrap">
            <div className="ed-chart-bar" style={{ height: `${(d.amount / max) * 100}%`, animationDelay: `${i * 80}ms` }} />
          </div>
          <div className="ed-chart-label">{d.month}</div>
          <div className="ed-chart-val">{fmtShortInr(d.amount)}</div>
        </div>
      ))}
    </div>
  );
}

function EditProfileModal({ profile, onSave, onClose, saving }) {
  const [form, setForm] = useState({ ...profile });
  const [avatarFile, setAvatarFile] = useState(null);
  const [avatarPreview, setAvatarPreview] = useState(profile.avatar ? toAssetUrl(profile.avatar) : '');
  const set = (k, v) => setForm(p => ({ ...p, [k]: v }));

  return (
    <div className="ed-modal-overlay" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="ed-modal">
        <div className="ed-modal-head">
          <h3>Edit expert profile</h3>
          <button className="ed-modal-close" onClick={onClose}>x</button>
        </div>
        <div className="ed-modal-body">
          <div className="ed-avatar-edit">
            <div className="ed-avatar-edit-preview">
              {avatarPreview ? (
                <img src={avatarPreview} alt="Preview" />
              ) : (
                <span>{(form.name?.[0] || 'E').toUpperCase()}</span>
              )}
            </div>
            <label className="ed-avatar-upload-btn">
              Change Photo
              <input
                type="file"
                accept="image/*"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  setAvatarFile(f);
                  setAvatarPreview(URL.createObjectURL(f));
                }}
              />
            </label>
          </div>
          {[
            { label: 'Display name', key: 'name', placeholder: 'Your full name' },
            { label: 'Headline', key: 'headline', placeholder: 'e.g. Senior Product Manager' },
            { label: 'Field / domain', key: 'field', placeholder: 'e.g. Career, Business, Programming' },
            { label: 'Location', key: 'location', placeholder: 'e.g. Mumbai' },
            { label: 'Session fee (INR)', key: 'price', placeholder: '500', type: 'number' },
            { label: 'Years of experience', key: 'experience', placeholder: '5', type: 'number' },
          ].map(({ label, key, placeholder, type = 'text' }) => (
            <div key={key} className="ed-field">
              <label className="ed-field-label">{label}</label>
              <input className="ed-field-input" type={type} placeholder={placeholder} value={form[key] || ''} onChange={e => set(key, e.target.value)} />
            </div>
          ))}
          <div className="ed-field">
            <label className="ed-field-label">Bio</label>
            <textarea className="ed-field-input ed-field-textarea" rows={4} placeholder="Write a short bio" value={form.bio || ''} onChange={e => set('bio', e.target.value)} />
          </div>
        </div>
        <div className="ed-modal-foot">
          <button className="ed-btn ed-btn-ghost" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="ed-btn ed-btn-primary" onClick={() => onSave({ ...form, avatarFile })} disabled={saving}>{saving ? 'Saving...' : 'Save changes'}</button>
        </div>
      </div>
    </div>
  );
}

const ExpertDashboard = () => {
  const navigate = useNavigate();

  const token = localStorage.getItem('token');
  const email = localStorage.getItem('email');
  const storedRole = localStorage.getItem('role');
  const normalizedRole = String(storedRole || '').toLowerCase();
  const storedName = localStorage.getItem('name') || localStorage.getItem('username') || 'Expert';
  const [profile, setProfile] = useState({
    name: storedName,
    email: email || '',
    field: 'Expert',
    headline: 'Building trust through structured consultations',
    location: '',
    price: 500,
    experience: 0,
    bio: '',
    avatar: '',
    rating: 0,
    ratingsCount: 0,
    responseRate: 96,
    repeatRate: 0,
    status: 'pending',
  });

  const [payments, setPayments] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);

  const [activeTab, setActiveTab] = useState('overview');
  const [headerScrolled, setHeaderScrolled] = useState(false);
  const [heroVisible, setHeroVisible] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [tipIndex, setTipIndex] = useState(0);
  const [activityIndex, setActivityIndex] = useState(0);
  const [sessionFilter, setSessionFilter] = useState('all');
  const [sessionQuery, setSessionQuery] = useState('');
  const [activeRoom, setActiveRoom] = useState('');
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [loadingChat, setLoadingChat] = useState(false);
  const socketRef = useRef(null);
  const activeRoomRef = useRef('');
  const msgsEndRef = useRef(null);

  const [statsRef, statsInView] = useInView(0.25);

  useEffect(() => {
    if (!token || !email || normalizedRole !== 'expert') {
      navigate('/login', { replace: true });
    }
  }, [token, email, normalizedRole, navigate]);

  const loadDashboardData = useCallback(async () => {
    if (!token || !email) return;

    setLoading(true);
    setLoadError('');
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [pRes, cRes, payRes] = await Promise.all([
        fetch(`${API}/api/profile?email=${encodeURIComponent(email)}`, { headers }),
        fetch(`${API}/api/conversations?email=${encodeURIComponent(email)}`, { headers }),
        fetch(`${API}/api/my-payments`, { headers }),
      ]);

      const [pData, cData, payData] = await Promise.all([
        pRes.json().catch(() => ({})),
        cRes.json().catch(() => ([])),
        payRes.json().catch(() => ([])),
      ]);

      if (!pData?.error) {
        setProfile((prev) => ({
          ...prev,
          ...pData,
          name: pData.name || prev.name,
          email: pData.email || prev.email,
          field: pData.field || prev.field,
          headline: pData.headline || prev.headline,
          location: pData.location || prev.location || '',
          price: toNum(pData.price, prev.price),
          experience: toNum(pData.experience, prev.experience),
          bio: pData.summary || pData.bio || prev.bio,
          avatar: pData.avatar || prev.avatar,
          status: pData.status || prev.status,
          rating: toNum(pData.avgRating ?? pData.rating, prev.rating),
          ratingsCount: toNum(pData.ratingsCount, prev.ratingsCount),
        }));
      }

      setConversations(Array.isArray(cData) ? cData : []);
      setPayments(Array.isArray(payData) ? payData : []);
    } catch {
      setLoadError('Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  }, [token, email]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  useEffect(() => {
    const t = setTimeout(() => setHeroVisible(true), 60);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    const fn = () => setHeaderScrolled(window.scrollY > 20);
    window.addEventListener('scroll', fn, { passive: true });
    return () => window.removeEventListener('scroll', fn);
  }, []);

  useEffect(() => {
    const t = setInterval(() => setTipIndex((v) => (v + 1) % TIPS.length), 5000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!token) return;
    const s = io(API, { auth: { token }, transports: ['websocket'] });
    socketRef.current = s;

    s.on('connect', () => s.emit('authenticate', { token }));
    s.on('receive_message', (msg) => {
      if (!msg?.room || msg.room !== activeRoomRef.current) return;
      setChatMessages((prev) => {
        const last = prev[prev.length - 1];
        if (last && last.author === msg.author && last.message === msg.message && Math.abs(new Date(last.createdAt || 0) - new Date(msg.createdAt || 0)) < 3000) {
          return prev;
        }
        return [...prev, msg];
      });
      setTimeout(() => msgsEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 40);
    });

    return () => {
      try { s.disconnect(); } catch (err) { console.error(err); }
    };
  }, [token]);

  const paidPayments = useMemo(
    () => payments.filter((p) => String(p?.status || '').toLowerCase() === 'paid'),
    [payments]
  );

  const totalEarnings = useMemo(
    () => paidPayments.reduce((sum, p) => sum + toNum(p.amount), 0),
    [paidPayments]
  );
  const sessions = useMemo(() => {
    const paymentByClient = new Map();
    for (const p of payments) {
      const key = String(p.clientEmail || '').toLowerCase();
      if (!key) continue;
      if (!paymentByClient.has(key)) paymentByClient.set(key, []);
      paymentByClient.get(key).push(p);
    }

    for (const arr of paymentByClient.values()) {
      arr.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    }

    const fromConversations = conversations.map((c) => {
      const clientEmail = String(c.otherEmail || '').toLowerCase();
      const clientName = (c.otherEmail || 'Client').split('@')[0];
      const pArr = paymentByClient.get(clientEmail) || [];
      const latest = pArr[0];
      const latestStatus = String(latest?.status || '').toLowerCase();

      const status = latestStatus === 'paid' ? 'completed' : latestStatus === 'failed' ? 'cancelled' : 'upcoming';

      return {
        id: c.room || `${clientEmail}-${c.lastMessageTime || ''}`,
        client: clientName,
        topic: c.lastMessage || 'Conversation started',
        date: formatRelative(c.lastMessageTime),
        status,
        amount: latest ? toNum(latest.amount, 0) : 0,
        rating: null,
        activityTs: c.lastMessageTime || latest?.createdAt,
      };
    });

    const known = new Set(fromConversations.map((s) => s.client.toLowerCase()));
    const fromPayments = [];
    for (const p of payments) {
      const name = p.clientName || (p.clientEmail ? p.clientEmail.split('@')[0] : 'Client');
      if (known.has(String(name).toLowerCase())) continue;
      const statusRaw = String(p.status || '').toLowerCase();
      const status = statusRaw === 'paid' ? 'completed' : statusRaw === 'failed' ? 'cancelled' : 'upcoming';
      fromPayments.push({
        id: p._id || `${p.clientEmail}-${p.createdAt}`,
        client: name,
        topic: p?.notes?.purpose || 'Consultation payment',
        date: formatRelative(p.createdAt),
        status,
        amount: toNum(p.amount, 0),
        rating: null,
        activityTs: p.createdAt,
      });
      known.add(String(name).toLowerCase());
    }

    return [...fromConversations, ...fromPayments].sort((a, b) => new Date(b.activityTs || 0) - new Date(a.activityTs || 0));
  }, [conversations, payments]);

  const filteredSessions = useMemo(() => {
    const byStatus = sessionFilter === 'all'
      ? sessions
      : sessions.filter((s) => s.status === sessionFilter);

    const q = sessionQuery.trim().toLowerCase();
    if (!q) return byStatus;

    return byStatus.filter((s) => (
      String(s.client || '').toLowerCase().includes(q)
      || String(s.topic || '').toLowerCase().includes(q)
    ));
  }, [sessions, sessionFilter, sessionQuery]);

  const earningsData = useMemo(() => {
    const out = [];
    const now = new Date();
    const map = new Map();

    for (const p of paidPayments) {
      const d = new Date(p.createdAt || Date.now());
      const key = monthKey(d);
      map.set(key, (map.get(key) || 0) + toNum(p.amount));
    }

    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const key = monthKey(d);
      out.push({ month: d.toLocaleDateString('en-IN', { month: 'short' }), amount: map.get(key) || 0, key });
    }

    return out;
  }, [paidPayments]);

  const totalThisMonth = earningsData[earningsData.length - 1]?.amount || 0;
  const totalLastMonth = earningsData[earningsData.length - 2]?.amount || 0;
  const earningsGrowth = totalLastMonth > 0 ? Math.round(((totalThisMonth - totalLastMonth) / totalLastMonth) * 100) : (totalThisMonth > 0 ? 100 : 0);

  const activity = useMemo(() => {
    const rows = [];
    for (const c of conversations.slice(0, 5)) {
      rows.push({ icon: 'MSG', text: `New message from ${c.otherEmail || 'client'}`, time: formatRelative(c.lastMessageTime), color: '#22d3ee' });
    }
    for (const p of payments.slice(0, 5)) {
      const st = String(p.status || '').toLowerCase();
      rows.push({ icon: st === 'paid' ? 'INR' : 'PAY', text: `${fmtInr(p.amount)} ${st} (${p.clientName || p.clientEmail || 'client'})`, time: formatRelative(p.createdAt), color: st === 'paid' ? '#34d399' : st === 'failed' ? '#fb7185' : '#a78bfa' });
    }
    if (!rows.length) rows.push({ icon: 'OK', text: 'Your dashboard is connected', time: 'now', color: '#34d399' });
    return rows.slice(0, 8);
  }, [conversations, payments]);

  useEffect(() => {
    const t = setInterval(() => setActivityIndex((v) => (v + 1) % activity.length), 3200);
    return () => clearInterval(t);
  }, [activity.length]);

  const uniqueClients = useMemo(() => {
    const set = new Set();
    payments.forEach((p) => p.clientEmail && set.add(String(p.clientEmail).toLowerCase()));
    conversations.forEach((c) => c.otherEmail && set.add(String(c.otherEmail).toLowerCase()));
    return set;
  }, [payments, conversations]);

  const repeatRate = useMemo(() => {
    const counts = new Map();
    paidPayments.forEach((p) => {
      const key = String(p.clientEmail || '').toLowerCase();
      if (!key) return;
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    if (!counts.size) return 0;
    const repeat = [...counts.values()].filter((v) => v > 1).length;
    return Math.round((repeat / counts.size) * 100);
  }, [paidPayments]);

  const computedProfile = useMemo(() => ({ ...profile, totalSessions: sessions.length, totalEarnings, repeatRate }), [profile, sessions.length, totalEarnings, repeatRate]);
  const statusRaw = String(computedProfile.status || 'pending').toLowerCase();
  const statusLabel = statusRaw === 'approved'
    ? 'Verified by Company'
    : statusRaw === 'rejected'
      ? 'Not Verified'
      : 'Verification Pending';
  const helpHighlights = useMemo(() => {
    const items = [];
    if (computedProfile.headline) items.push(computedProfile.headline);
    if (computedProfile.bio) {
      const firstSentence = String(computedProfile.bio).split(/[.!?]/).map((s) => s.trim()).find(Boolean);
      if (firstSentence) items.push(firstSentence);
    }
    if (computedProfile.field) items.push(`Specialized in ${computedProfile.field} support`);
    if (toNum(computedProfile.experience) > 0) items.push(`${toNum(computedProfile.experience)}+ years practical guidance`);
    return items.slice(0, 3);
  }, [computedProfile.headline, computedProfile.bio, computedProfile.field, computedProfile.experience]);

  const domainColor = getDomainColor(computedProfile.field);

  const cSessions = useCounter(computedProfile.totalSessions, 1400, statsInView);
  const cEarnings = useCounter(computedProfile.totalEarnings, 1800, statsInView);
  const cRating = useCounter(Math.round((computedProfile.rating || 4.8) * 10), 1200, statsInView);
  const cRepeat = useCounter(computedProfile.repeatRate || 0, 1200, statsInView);

  const go = useCallback((path) => navigate(path), [navigate]);

  const openConversation = useCallback(async (c) => {
    if (!c?.room || !token) return;
    setActiveTab('chat');
    setActiveRoom(c.room);
    activeRoomRef.current = c.room;
    setLoadingChat(true);
    try {
      const r = await fetch(`${API}/api/messages?room=${encodeURIComponent(c.room)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await r.json().catch(() => []);
      setChatMessages(Array.isArray(data) ? data : []);
      setTimeout(() => msgsEndRef.current?.scrollIntoView({ behavior: 'auto' }), 40);
      socketRef.current?.emit('join_private', c.room);
    } catch {
      setChatMessages([]);
    } finally {
      setLoadingChat(false);
    }
  }, [token]);

  const sendChatMessage = useCallback(() => {
    const room = activeRoomRef.current || activeRoom;
    const txt = chatInput.trim();
    if (!room || !txt || !email) return;
    const local = {
      _id: `local-${Date.now()}`,
      room,
      author: email,
      authorRole: 'expert',
      message: txt,
      createdAt: new Date().toISOString(),
    };
    setChatMessages((prev) => [...prev, local]);
    setChatInput('');
    socketRef.current?.emit('send_private_message', {
      room,
      author: email,
      authorRole: 'expert',
      message: txt,
    });
    setTimeout(() => msgsEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 40);
  }, [activeRoom, chatInput, email]);

  const handleLogout = () => {
    ['token', 'email', 'name', 'username', 'role', 'field', 'headline', 'price', 'experience'].forEach((k) => localStorage.removeItem(k));
    navigate('/login');
  };

  const handleSaveProfile = async (updatedProfile) => {
    if (!token) return;
    setSavingProfile(true);
    try {
      const payload = {
        name: updatedProfile.name,
        field: updatedProfile.field,
        headline: updatedProfile.headline,
        location: updatedProfile.location,
        price: toNum(updatedProfile.price, 0),
        experience: toNum(updatedProfile.experience, 0),
        bio: updatedProfile.bio || '',
      };

      const applySavedProfile = (next) => {
        setProfile((prev) => ({ ...prev, ...next }));
        localStorage.setItem('name', next.name || storedName);
        localStorage.setItem('field', next.field || '');
        localStorage.setItem('headline', next.headline || '');
        localStorage.setItem('price', String(next.price || 0));
        localStorage.setItem('experience', String(next.experience || 0));
        setEditModalOpen(false);
      };

      const r = await fetch(`${API}/api/profile`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      });

      const d = await r.json().catch(() => ({}));
      if (r.status === 404) {
        throw new Error('Profile API route not found on backend (PUT /api/profile). Please redeploy backend.');
      }
      if (!r.ok || d?.error) throw new Error(d?.error || 'Failed to update profile');

      let nextAvatar = d?.expert?.avatar || profile.avatar;
      const avatarFile = updatedProfile.avatarFile;
      if (avatarFile) {
        const fd = new FormData();
        fd.append('photo', avatarFile);
        const pr = await fetch(`${API}/api/profile/photo`, {
          method: 'PUT',
          headers: { Authorization: `Bearer ${token}` },
          body: fd,
        });
        const pd = await pr.json().catch(() => ({}));
        if (!pr.ok || pd?.error) throw new Error(pd?.error || 'Failed to update profile photo');
        nextAvatar = pd?.expert?.avatar || nextAvatar;
      }

      applySavedProfile({ ...payload, bio: d?.expert?.summary || payload.bio, avatar: nextAvatar });
    } catch (err) {
      alert(err.message || 'Profile update failed');
    } finally {
      setSavingProfile(false);
    }
  };

  const usernameInitial = (computedProfile.name?.charAt(0) || 'E').toUpperCase();
  const avatarSrc = toAssetUrl(computedProfile.avatar);

  const TABS = [
    { id: 'overview', label: 'Overview', icon: <BarChart3 size={15} /> },
    { id: 'sessions', label: 'Sessions', icon: <MessageCircle size={15} /> },
    { id: 'chat', label: 'Chat', icon: <Send size={15} /> },
    { id: 'earnings', label: 'Earnings', icon: <DollarSign size={15} /> },
    { id: 'profile', label: 'Profile', icon: <Settings size={15} /> },
  ];

  if (loading) {
    return (
      <div className="ed-page"><main className="ed-main"><div className="ed-shell"><div className="ed-empty-state"><div className="ed-empty-icon">...</div><p>Loading expert dashboard...</p></div></div></main></div>
    );
  }
  return (
    <div className="ed-page">
      <div className="ed-canvas" aria-hidden>
        <div className="ed-orb ed-orb-1" style={{ '--orb-color': domainColor }} />
        <div className="ed-orb ed-orb-2" />
        <div className="ed-orb ed-orb-3" />
        <div className="ed-grid" />
      </div>

      <header className={`ed-header ${headerScrolled ? 'ed-header--scrolled' : ''}`} role="banner">
        <div className="ed-shell ed-header-inner">
          <button className="ed-logo" onClick={() => go('/')} aria-label="Solvenut home">
            <div className="ed-logo-mark"><House size={17} /></div>
            <div className="ed-logo-info"><span className="ed-logo-name">Solve<span className="ed-logo-accent">nut</span></span><span className="ed-logo-sub">Expert workspace</span></div>
          </button>

          <nav className="ed-tab-nav" aria-label="Dashboard sections">
            {TABS.map((tab) => (
              <button key={tab.id} className={`ed-tab-btn ${activeTab === tab.id ? 'ed-tab-btn--active' : ''}`} onClick={() => setActiveTab(tab.id)}>
                {tab.icon}{tab.label}
              </button>
            ))}
          </nav>

          <div className="ed-header-right">
            <div className="ed-notif-wrap">
              <button className="ed-icon-btn" onClick={() => setNotifOpen((v) => !v)} aria-label="Notifications"><Bell size={16} /><span className="ed-notif-dot" /></button>
              {notifOpen && (
                <div className="ed-notif-panel">
                  <div className="ed-notif-head">Notifications</div>
                  {activity.slice(0, 3).map((item, i) => (
                    <div key={i} className="ed-notif-item"><span className="ed-notif-icon">{item.icon}</span><div><div className="ed-notif-text">{item.text}</div><div className="ed-notif-time">{item.time}</div></div></div>
                  ))}
                </div>
              )}
            </div>

            <button className="ed-icon-btn" onClick={() => setEditModalOpen(true)} aria-label="Edit profile"><Edit3 size={15} /></button>
            <button className="ed-home-btn" onClick={() => go('/')}><House size={14} />Home</button>

            <div className="ed-user-chip">
              <div className="ed-user-avatar" style={{ background: domainColor, color: '#02131d' }}>
                {avatarSrc ? <img src={avatarSrc} alt={computedProfile.name} /> : usernameInitial}
              </div>
              <div className="ed-user-info"><span className="ed-user-name">{computedProfile.name}</span><span className="ed-user-role">Expert · {statusRaw === 'approved' ? 'Verified' : statusRaw === 'rejected' ? 'Rejected' : 'Pending'}</span></div>
            </div>

            <button className="ed-btn ed-btn-ghost ed-btn-sm" onClick={() => go('/experts')}>View listing</button>
            <button className="ed-btn ed-btn-primary ed-btn-sm" onClick={handleLogout}>Logout</button>
          </div>
        </div>
      </header>

      <main className="ed-main">
        <div className="ed-shell">
          {loadError && (
            <section className="ed-section"><div className="ed-card"><div className="ed-empty-state"><div className="ed-empty-icon">!</div><p>{loadError}</p><button className="ed-btn ed-btn-primary" onClick={loadDashboardData}>Retry</button></div></div></section>
          )}

          <section className={`ed-hero ${heroVisible ? 'ed-hero--visible' : ''}`}>
            <div className="ed-hero-layout">
              <div className="ed-hero-copy">
                <div className="ed-hero-badge" style={{ color: domainColor, borderColor: `${domainColor}40`, background: `${domainColor}10` }}>
                  <span className="ed-badge-dot" style={{ background: domainColor, boxShadow: `0 0 6px ${domainColor}` }} />Expert dashboard
                </div>
                <h1 className="ed-hero-title">Welcome back,<span className="ed-hero-gradient" style={{ '--grad-color': domainColor }}> {computedProfile.name}</span></h1>
                <p className="ed-hero-sub">{computedProfile.headline || 'Your expert workspace is ready.'}</p>
                <div className="ed-hero-domain-pill" style={{ color: domainColor, borderColor: `${domainColor}35`, background: `${domainColor}0D` }}><Briefcase size={13} />{computedProfile.field || 'Expert'}</div>
                <div className="ed-hero-actions">
                  <button className="ed-btn ed-btn-primary ed-btn-lg" onClick={() => go('/experts')}><Eye size={16} />View public profile</button>
                  <button className="ed-btn ed-btn-outline ed-btn-lg" onClick={() => setEditModalOpen(true)}><Edit3 size={16} />Edit profile</button>
                </div>
                <div className="ed-tip-strip"><div className="ed-tip-icon"><Zap size={13} /></div><p className="ed-tip-text" key={tipIndex}>{TIPS[tipIndex]}</p></div>
              </div>

              <div className="ed-hero-card">
                <div className="ed-profile-top">
                  <div className="ed-profile-avatar-wrap"><div className="ed-profile-avatar" style={{ background: domainColor, color: '#02131d' }}>{avatarSrc ? <img src={avatarSrc} alt={computedProfile.name} /> : usernameInitial}</div><div className="ed-profile-verified" title={statusLabel}><CheckCircle size={14} /></div></div>
                  <div className="ed-profile-identity">
                    <h2 className="ed-profile-name">{computedProfile.name}</h2>
                    <div className="ed-profile-field" style={{ color: domainColor }}>{computedProfile.field}</div>
                    <div className={`ed-verify-pill ed-verify-${statusRaw}`}>{statusLabel}</div>
                    <div className="ed-profile-stars">{Array.from({ length: 5 }).map((_, i) => (<Star key={i} size={13} fill={i < Math.floor(computedProfile.rating || 0) ? '#fbbf24' : 'none'} color={i < Math.floor(computedProfile.rating || 0) ? '#fbbf24' : '#374151'} />))}<span className="ed-profile-rating-text">{computedProfile.rating ? `${computedProfile.rating} (${computedProfile.ratingsCount || 0})` : 'No ratings yet'}</span></div>
                  </div>
                  <button className="ed-profile-edit-btn" onClick={() => setEditModalOpen(true)} aria-label="Edit profile"><Edit3 size={14} /></button>
                </div>

                <div className="ed-profile-stats" ref={statsRef}>
                  {[
                    { icon: <MessageCircle size={16} />, value: statsInView ? cSessions : 0, label: 'Sessions', color: domainColor },
                    { icon: <DollarSign size={16} />, value: statsInView ? fmtShortInr(cEarnings) : 'INR 0', label: 'Earnings', color: '#34d399' },
                    { icon: <Star size={16} />, value: statsInView ? (cRating / 10).toFixed(1) : '0', label: 'Avg rating', color: '#fbbf24' },
                    { icon: <Users size={16} />, value: statsInView ? `${cRepeat}%` : '0%', label: 'Repeat clients', color: '#a78bfa' },
                  ].map(({ icon, value, label, color }) => (<div key={label} className="ed-profile-stat" style={{ '--s-color': color }}><div className="ed-profile-stat-icon">{icon}</div><div className="ed-profile-stat-value">{value}</div><div className="ed-profile-stat-label">{label}</div></div>))}
                </div>

                <div className="ed-profile-info-rows">
                  {[
                    { icon: <MapPin size={13} />, value: computedProfile.location || 'Location not set' },
                    { icon: <Clock size={13} />, value: `${toNum(computedProfile.experience)}+ years experience` },
                    { icon: <DollarSign size={13} />, value: `${fmtInr(computedProfile.price)} per session` },
                    { icon: <Award size={13} />, value: `${computedProfile.responseRate || 96}% response rate` },
                  ].map(({ icon, value }) => (<div key={value} className="ed-info-row"><span className="ed-info-row-icon">{icon}</span><span>{value}</span></div>))}
                </div>
                <div className="ed-help-box">
                  <div className="ed-help-title">How you help clients</div>
                  <div className="ed-help-list">
                    {helpHighlights.length === 0 ? (
                      <div className="ed-help-item">Add headline and bio to show clients what help you provide.</div>
                    ) : helpHighlights.map((item) => (
                      <div key={item} className="ed-help-item">{item}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </section>

          <div className="ed-stats-bar">
            {[
              { icon: <TrendingUp size={18} />, value: fmtShortInr(totalThisMonth), label: 'This month', color: '#34d399', trend: earningsGrowth },
              { icon: <MessageCircle size={18} />, value: `${sessions.filter((s) => s.status === 'completed').length}`, label: 'Completed sessions', color: domainColor },
              { icon: <Star size={18} />, value: computedProfile.rating || '—', label: 'Overall rating', color: '#fbbf24' },
              { icon: <Users size={18} />, value: `${uniqueClients.size}`, label: 'Unique clients', color: '#a78bfa' },
            ].map(({ icon, value, label, color, trend }) => (
              <div key={label} className="ed-stat-bar-item"><div className="ed-stat-bar-icon" style={{ color }}>{icon}</div><div className="ed-stat-bar-value" style={{ color }}>{value}{trend !== undefined && (<span className={`ed-trend ${trend >= 0 ? 'ed-trend--up' : 'ed-trend--down'}`}>{trend >= 0 ? <ArrowUp size={11} /> : <ArrowDown size={11} />}{Math.abs(trend)}%</span>)}</div><div className="ed-stat-bar-label">{label}</div></div>
            ))}
          </div>

          {activeTab === 'overview' && (
            <>
              <section className="ed-section">
                <div className="ed-section-head"><div className="ed-kicker">Quick actions</div><h2 className="ed-section-title">Manage your expert presence</h2></div>
                <div className="ed-quick-grid">
                  {[
                    { icon: <Eye size={20} />, color: domainColor, title: 'View public profile', sub: 'See how clients discover you.', onClick: () => go('/experts') },
                    { icon: <Edit3 size={20} />, color: '#fbbf24', title: 'Update your profile', sub: 'Keep headline, domain and price current.', onClick: () => setEditModalOpen(true) },
                    { icon: <MessageCircle size={20} />, color: '#34d399', title: 'Chat with clients', sub: 'Open live conversation and reply in real-time.', onClick: () => setActiveTab('chat') },
                    { icon: <BarChart3 size={20} />, color: '#a78bfa', title: 'Earnings overview', sub: 'Track monthly income trends.', onClick: () => setActiveTab('earnings') },
                  ].map(({ icon, color, title, sub, onClick }) => (<button key={title} className="ed-quick-card" onClick={onClick} style={{ '--q-color': color }}><div className="ed-quick-icon" style={{ color, background: `${color}18` }}>{icon}</div><div className="ed-quick-text"><div className="ed-quick-title">{title}</div><div className="ed-quick-sub">{sub}</div></div><div className="ed-quick-cta" style={{ color }}>Go <ArrowRight size={13} /></div></button>))}
                </div>
              </section>
              <section className="ed-section">
                <div className="ed-two-col">
                  <div className="ed-card">
                    <div className="ed-card-head"><h3 className="ed-card-title">Recent sessions</h3><button className="ed-card-link" onClick={() => setActiveTab('sessions')}>View all <ArrowRight size={13} /></button></div>
                    <div className="ed-sessions-mini">
                      {sessions.length === 0 ? (
                        <div className="ed-empty-state"><div className="ed-empty-icon">...</div><p>No sessions yet.</p></div>
                      ) : sessions.slice(0, 3).map((s) => (
                        <div key={s.id} className="ed-session-mini-row" onClick={() => {
                          const c = conversations.find((x) => (x.otherEmail || '').toLowerCase().startsWith((s.client || '').toLowerCase()));
                          if (c) openConversation(c);
                        }}><div className="ed-session-mini-avatar">{(s.client || 'C')[0].toUpperCase()}</div><div className="ed-session-mini-info"><div className="ed-session-mini-name">{s.client}</div><div className="ed-session-mini-topic">{s.topic}</div></div><div className={`ed-session-mini-status ed-status--${s.status}`}>{s.status}</div></div>
                      ))}
                    </div>
                  </div>

                  <div className="ed-card">
                    <div className="ed-card-head"><h3 className="ed-card-title">Live activity</h3><span className="ed-live-pill"><span className="ed-live-dot" />Live</span></div>
                    <div className="ed-activity-list">
                      {activity.map((item, i) => (
                        <div key={`${item.text}-${i}`} className={`ed-activity-item ${i === activityIndex ? 'ed-activity-item--active' : ''}`}><div className="ed-activity-icon" style={{ background: `${item.color}18`, color: item.color }}>{item.icon}</div><div><div className="ed-activity-text">{item.text}</div><div className="ed-activity-time">{item.time}</div></div></div>
                      ))}
                    </div>
                  </div>
                </div>
              </section>
            </>
          )}

          {activeTab === 'sessions' && (
            <section className="ed-section">
              <div className="ed-section-head"><div className="ed-kicker">Sessions</div><h2 className="ed-section-title">All your client sessions</h2><p className="ed-section-sub">Live data from conversations and payments.</p></div>
              <div className="ed-session-controls">
                <div className="ed-filter-pills">{['all', 'upcoming', 'completed', 'cancelled'].map((f) => (<button key={f} className={`ed-filter-pill ${sessionFilter === f ? 'ed-filter-pill--active' : ''}`} onClick={() => setSessionFilter(f)}>{f.charAt(0).toUpperCase() + f.slice(1)}{f === 'all' ? ` (${sessions.length})` : ` (${sessions.filter((s) => s.status === f).length})`}</button>))}</div>
                <input className="ed-filter-search" value={sessionQuery} onChange={(e) => setSessionQuery(e.target.value)} placeholder="Search by client or topic" />
              </div>
              <div className="ed-session-table-head"><span>Client</span><span>Date</span><span>Rating</span><span>Earned</span><span>Status</span></div>
              <div className="ed-session-list">{filteredSessions.length === 0 ? (<div className="ed-empty-state"><div className="ed-empty-icon">...</div><p>No sessions in this category.</p></div>) : filteredSessions.map((s) => <SessionRow key={s.id} session={s} />)}</div>
            </section>
          )}

          {activeTab === 'chat' && (
            <section className="ed-section">
              <div className="ed-section-head"><div className="ed-kicker">Client Chat</div><h2 className="ed-section-title">Private conversations</h2><p className="ed-section-sub">Select a client and continue the conversation.</p></div>
              <div className="ed-chat-grid">
                <div className="ed-chat-list ed-card">
                  {conversations.length === 0 ? (
                    <div className="ed-empty-state"><div className="ed-empty-icon">...</div><p>No conversations yet.</p></div>
                  ) : conversations.map((c) => {
                    const who = c.otherEmail || 'client';
                    return (
                      <button key={c.room} className={`ed-chat-item ${activeRoom === c.room ? 'active' : ''}`} onClick={() => openConversation(c)}>
                        <div className="ed-chat-av">{who[0].toUpperCase()}</div>
                        <div className="ed-chat-meta"><div className="ed-chat-name">{who}</div><div className="ed-chat-prev">{c.lastMessage || 'Open chat'}</div></div>
                        <div className="ed-chat-time">{formatRelative(c.lastMessageTime)}</div>
                      </button>
                    );
                  })}
                </div>
                <div className="ed-chat-win ed-card">
                  {!activeRoom ? (
                    <div className="ed-empty-state"><div className="ed-empty-icon">...</div><p>Choose a conversation from the left.</p></div>
                  ) : (
                    <>
                      <div className="ed-chat-head">Room: {activeRoom}</div>
                      <div className="ed-chat-msgs">
                        {loadingChat ? <div className="ed-chat-loading">Loading messages...</div> : chatMessages.map((m, i) => {
                          const mine = m.author === email;
                          return (
                            <div key={m._id || i} className={`ed-chat-msg ${mine ? 'mine' : ''}`}>
                              <div className="ed-chat-bub">{m.message}</div>
                              <div className="ed-chat-msg-time">{formatRelative(m.createdAt)}</div>
                            </div>
                          );
                        })}
                        <div ref={msgsEndRef} />
                      </div>
                      <div className="ed-chat-compose">
                        <textarea className="ed-chat-input" rows={2} value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="Type message... (Enter to send)" onKeyDown={(e) => {
                          if (e.key === 'Enter' && !e.shiftKey) {
                            e.preventDefault();
                            sendChatMessage();
                          }
                        }} />
                        <button className="ed-btn ed-btn-primary" onClick={sendChatMessage} disabled={!chatInput.trim()}><Send size={14} />Send</button>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </section>
          )}

          {activeTab === 'earnings' && (
            <section className="ed-section">
              <div className="ed-section-head"><div className="ed-kicker">Earnings</div><h2 className="ed-section-title">Your income at a glance</h2></div>
              <div className="ed-earnings-metrics">
                {[
                  { label: 'This month', value: fmtInr(totalThisMonth), sub: `${earningsGrowth >= 0 ? '+' : ''}${earningsGrowth}% vs last month`, positive: earningsGrowth >= 0, color: '#34d399' },
                  { label: 'Total earnings', value: fmtInr(totalEarnings), sub: 'All-time paid transactions', color: domainColor },
                  { label: 'Avg per session', value: sessions.length ? fmtInr(Math.round(totalEarnings / sessions.length)) : 'INR 0', sub: `${sessions.length} sessions total`, color: '#fbbf24' },
                  { label: 'Pending payout', value: fmtInr(payments.filter((p) => ['pending', 'created'].includes(String(p.status || '').toLowerCase())).reduce((a, b) => a + toNum(b.amount), 0)), sub: 'Awaiting settlement', color: '#a78bfa' },
                ].map(({ label, value, sub, color, positive }) => (<div key={label} className="ed-earnings-metric-card" style={{ '--m-color': color }}><div className="ed-earnings-metric-label">{label}</div><div className="ed-earnings-metric-value" style={{ color }}>{value}</div><div className={`ed-earnings-metric-sub ${positive === false ? 'ed-sub--negative' : ''}`}>{sub}</div></div>))}
              </div>

              <div className="ed-card ed-card-chart"><div className="ed-card-head"><h3 className="ed-card-title">Monthly earnings (6 months)</h3><span className="ed-card-badge" style={{ color: '#34d399', borderColor: 'rgba(52,211,153,.3)', background: 'rgba(52,211,153,.1)' }}>+{Math.max(earningsGrowth, 0)}% this month</span></div><EarningsChart data={earningsData} /></div>

              <div className="ed-card"><div className="ed-card-head"><h3 className="ed-card-title">Recent payouts</h3></div><div className="ed-payout-list">{paidPayments.length === 0 ? (<div className="ed-empty-state"><div className="ed-empty-icon">...</div><p>No paid transactions yet.</p></div>) : paidPayments.slice(0, 8).map((p) => (<div key={p._id || `${p.clientEmail}-${p.createdAt}`} className="ed-payout-row"><div className="ed-payout-avatar">{(p.clientName || p.clientEmail || 'C')[0].toUpperCase()}</div><div className="ed-payout-info"><div className="ed-payout-name">{p.clientName || p.clientEmail}</div><div className="ed-payout-date">{formatRelative(p.createdAt)}</div></div><div className="ed-payout-amount">+{fmtInr(p.amount)}</div><span className="ed-payout-badge">Credited</span></div>))}</div></div>
            </section>
          )}

          {activeTab === 'profile' && (
            <section className="ed-section">
              <div className="ed-section-head"><div className="ed-kicker">Profile</div><h2 className="ed-section-title">Your expert card on Solvenut</h2><p className="ed-section-sub">This reflects your live expert data.</p></div>
              <div className="ed-profile-tab-grid">
                <div className="ed-card ed-profile-preview">
                  <div className="ed-preview-label">Live preview</div><div className="ed-preview-avatar" style={{ background: domainColor, color: '#02131d' }}>{avatarSrc ? <img src={avatarSrc} alt={computedProfile.name} /> : usernameInitial}</div><h3 className="ed-preview-name">{computedProfile.name}</h3><div className="ed-preview-field" style={{ color: domainColor }}>{computedProfile.field}</div>
                  <div className="ed-preview-stars">{Array.from({ length: 5 }).map((_, i) => (<Star key={i} size={14} fill={i < Math.floor(computedProfile.rating || 0) ? '#fbbf24' : 'none'} color={i < Math.floor(computedProfile.rating || 0) ? '#fbbf24' : '#374151'} />))}<span>{computedProfile.rating ? `${computedProfile.rating} (${computedProfile.ratingsCount || 0})` : 'No ratings yet'} - {toNum(computedProfile.experience)} yrs</span></div>
                  <p className="ed-preview-headline">{computedProfile.headline || 'No headline added yet.'}</p><p className="ed-preview-bio">{computedProfile.bio || 'No profile bio yet.'}</p><div className="ed-preview-price-row"><span className="ed-preview-price" style={{ color: domainColor }}>{fmtInr(computedProfile.price)}</span><span className="ed-preview-price-unit">/ session</span></div><button className="ed-preview-cta">Pay and talk</button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div className="ed-card"><div className="ed-card-head"><h3 className="ed-card-title">Expert details</h3><button className="ed-card-edit-btn" onClick={() => setEditModalOpen(true)}><Edit3 size={13} /> Edit</button></div>
                    <div className="ed-detail-rows">{[{ icon: <Mail size={14} />, label: 'Email', value: computedProfile.email || '—' },{ icon: <MapPin size={14} />, label: 'Location', value: computedProfile.location || 'Not set' },{ icon: <Briefcase size={14} />, label: 'Field', value: computedProfile.field || '—' },{ icon: <Clock size={14} />, label: 'Experience', value: `${toNum(computedProfile.experience)} years` },{ icon: <DollarSign size={14} />, label: 'Session fee', value: fmtInr(computedProfile.price) },{ icon: <Star size={14} />, label: 'Rating', value: computedProfile.rating ? `${computedProfile.rating} / 5.0 (${computedProfile.ratingsCount || 0})` : 'No ratings yet' }].map(({ icon, label, value }) => (<div key={label} className="ed-detail-row"><div className="ed-detail-icon" style={{ color: domainColor }}>{icon}</div><div><div className="ed-detail-label">{label}</div><div className="ed-detail-value">{value}</div></div></div>))}</div>
                  </div>

                  <div className="ed-card"><div className="ed-card-head"><h3 className="ed-card-title">Profile health</h3></div>
                    {[{ label: 'Headline set', done: Boolean(computedProfile.headline) },{ label: 'Bio written', done: Boolean(computedProfile.bio) },{ label: 'Session fee configured', done: Boolean(toNum(computedProfile.price)) },{ label: 'Experience listed', done: Boolean(toNum(computedProfile.experience)) },{ label: 'Domain listed', done: Boolean(computedProfile.field) }].map(({ label, done }) => (<div key={label} className={`ed-health-row ${done ? 'ed-health-row--done' : ''}`}>{done ? <CheckCircle size={15} color="#34d399" /> : <XCircle size={15} color="#374151" />}<span>{label}</span></div>))}
                    <button className="ed-btn ed-btn-primary ed-btn-full" style={{ marginTop: '10px' }} onClick={() => setEditModalOpen(true)}>Complete profile</button>
                  </div>
                </div>
              </div>
            </section>
          )}
        </div>
      </main>

      {editModalOpen && (<EditProfileModal profile={computedProfile} onSave={handleSaveProfile} onClose={() => setEditModalOpen(false)} saving={savingProfile} />)}
    </div>
  );
};

export default ExpertDashboard;
