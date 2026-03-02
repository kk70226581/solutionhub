// src/pages/ExpertDashboard.jsx
import React, {
  useEffect,
  useState,
  useRef,
  useCallback,
  useMemo,
} from "react";
import { useNavigate } from "react-router-dom";
import io from "socket.io-client";

const API = import.meta.env.VITE_API_BASE || "http://localhost:3000";

/* ─── Premium CSS & Design Tokens (Fully Responsive) ─── */
const css = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@400;500&family=Cabinet+Grotesk:wght@400;500;700;800&display=swap');

  :root {
    --home-brand-1: #10b981;
    --home-brand-2: #14b8a6;
    --home-accent: #f59e0b;
    --home-bg: #020617;
    --home-card: rgba(15, 23, 42, 0.94);
    --home-muted: #94a3b8;
    --home-text: #f9fafb;
    --home-border: rgba(148, 163, 184, 0.4);
    --home-glass: rgba(15, 23, 42, 0.92);
    --home-shadow-soft: 0 32px 80px rgba(15, 23, 42, 0.95);
    --home-max-width: 1240px;
    --home-radius-lg: 20px;
    --home-radius-md: 14px;
    --home-radius-pill: 999px;
    --home-transition-fast: 0.18s ease-out;

    --bg-void: var(--home-bg);
    --bg-base: #0d1117;
    --bg-card: var(--home-card);
    --bg-card-hover: rgba(255,255,255,0.03);
    --bg-elevated: var(--home-glass);
    --border: var(--home-border);
    --border-bright: rgba(255,255,255,0.14);
    --gold: var(--home-accent);
    --gold-dim: rgba(245,158,11,0.12);
    --gold-glow: rgba(245,158,11,0.18);
    --emerald: var(--home-brand-1);
    --rose: #fb7185;
    --sky: #38bdf8;
    --violet: #a78bfa;
    --text-primary: var(--home-text);
    --text-secondary: var(--home-muted);
    --text-muted: #4a5568;
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
    --radius-xl: 24px;
    --shadow-gold: 0 0 40px rgba(245,158,11,0.12);
    --font-display: 'Syne', sans-serif;
    --font-body: 'Cabinet Grotesk', sans-serif;
    --font-mono: 'DM Mono', monospace;
    --sidebar-w: 260px;
    --header-h: 64px;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg-void);
    color: var(--text-primary);
    font-family: var(--font-body);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }

  .ed-root {
    display: grid;
    grid-template-rows: var(--header-h) 1fr auto;
    min-height: 100vh;
    background: var(--bg-void);
    overflow-x: hidden;
  }

  .ed-root::before {
    content: '';
    position: fixed; inset: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.03'/%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
    opacity: 0.25;
  }

  /* ─── HEADER ─── */
  .ed-header {
    position: sticky; top: 0; z-index: 200;
    height: var(--header-h);
    background: linear-gradient(180deg, rgba(2,6,23,0.95), rgba(2,6,23,0.86));
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 16px;
    gap: 12px;
  }

  .ed-header-brand { display: flex; align-items: center; gap: 12px; cursor: pointer; }
  .brand-mark { width: 36px; height: 36px; background: linear-gradient(135deg, var(--home-brand-1), var(--home-brand-2)); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-family: var(--font-display); font-weight: 800; font-size: 18px; color: var(--bg-void); flex-shrink: 0; box-shadow: 0 10px 28px rgba(16,185,129,0.14); }
  .brand-text { font-family: var(--font-display); font-weight: 800; font-size: 17px; letter-spacing: -0.3px; color: var(--text-primary); }
  .brand-sub { font-size: 10px; font-family: var(--font-mono); color: var(--gold); letter-spacing: 0.08em; text-transform: uppercase; opacity: 0.9; }

  .ed-header-center { display: flex; align-items: center; gap: 8px; }
  .pill-badge { display: flex; align-items: center; gap: 6px; padding: 5px 12px; border-radius: 100px; font-size: 12px; font-family: var(--font-mono); background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text-secondary); white-space: nowrap; }
  .pulse-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--emerald); animation: pulse 2s ease-in-out infinite; flex-shrink: 0; }
  @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(0.8); } }

  .ed-header-right { display: flex; align-items: center; gap: 10px; }
  .avatar-btn { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg, var(--home-brand-1), var(--home-brand-2)); border: none; cursor: pointer; font-family: var(--font-display); font-weight: 800; font-size: 15px; color: var(--bg-void); display: flex; align-items: center; justify-content: center; transition: transform 0.15s, box-shadow 0.15s; }
  .avatar-btn:hover { transform: scale(1.05); box-shadow: 0 0 16px rgba(16,185,129,0.12); }
  .btn-logout { padding: 7px 12px; background: transparent; border: 1px solid var(--border); border-radius: 8px; color: var(--text-secondary); font-size: 12px; font-family: var(--font-mono); cursor: pointer; transition: all 0.15s; white-space: nowrap; }
  .btn-logout:hover { border-color: var(--rose); color: var(--rose); }

  /* MOBILE MENU BUTTON - larger hit area */
  .mobile-menu-btn {
    display: none;
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-primary);
    font-size: 20px;
    cursor: pointer;
    width: 44px;
    height: 44px;
    border-radius: 10px;
    align-items: center;
    justify-content: center;
  }
  .mobile-menu-btn:focus { outline: 2px solid rgba(245,158,11,0.18); }

  /* ─── TOP HORIZONTAL MOBILE NAV (hidden on desktop) ─── */
  .mobile-top-nav {
    display: none;
    position: sticky;
    top: var(--header-h);
    z-index: 190;
    background: linear-gradient(180deg, rgba(2,6,23,0.94), rgba(2,6,23,0.9));
    border-bottom: 1px solid var(--border);
    padding: 8px 8px;
    gap: 8px;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
  .mobile-top-nav .mobile-nav-btn {
    display: inline-flex;
    gap: 8px;
    align-items: center;
    justify-content: center;
    padding: 8px 12px;
    border-radius: 10px;
    min-width: 84px;
    white-space: nowrap;
    font-family: var(--font-mono);
    font-size: 13px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    cursor: pointer;
  }
  .mobile-top-nav .mobile-nav-btn.active {
    background: linear-gradient(90deg, var(--gold), #e09020);
    color: var(--bg-void);
    border-color: rgba(245,158,11,0.12);
    box-shadow: 0 6px 18px rgba(245,158,11,0.06);
  }

  /* ─── LAYOUT ─── */
  .ed-body { display: grid; grid-template-columns: var(--sidebar-w) 1fr; min-height: calc(100vh - var(--header-h)); position: relative; z-index: 1; }
  .ed-body.collapsed { grid-template-columns: 72px 1fr; }

  /* ─── SIDEBAR ─── */
  .ed-sidebar { background: rgba(2,6,23,0.6); border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 16px 10px; overflow: hidden; transition: width 0.25s cubic-bezier(0.4,0,0.2,1), transform 0.3s ease; position: sticky; top: var(--header-h); height: calc(100vh - var(--header-h)); overflow-y: auto; z-index: 200; }
  .nav-section-label { font-size: 10px; font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); padding: 6px 10px 4px; white-space: nowrap; overflow: hidden; }
  .nav-item { display: flex; align-items: center; gap: 10px; padding: 12px 10px; border-radius: var(--radius-sm); cursor: pointer; transition: all 0.15s; white-space: nowrap; font-size: 14px; font-weight: 500; color: var(--text-secondary); border: 1px solid transparent; margin-bottom: 4px; }
  .nav-item:hover { background: var(--bg-elevated); color: var(--text-primary); }
  .nav-item.active { background: rgba(245,158,11,0.08); border-color: rgba(245,158,11,0.12); color: var(--gold); }
  .nav-icon { width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; border-radius: 9px; font-size: 13px; flex-shrink: 0; background: var(--bg-elevated); transition: background 0.15s; }
  .nav-item.active .nav-icon { background: rgba(245,158,11,0.06); }
  .nav-badge { margin-left: auto; background: var(--rose); color: white; font-size: 10px; font-family: var(--font-mono); padding: 2px 6px; border-radius: 100px; min-width: 18px; text-align: center; flex-shrink: 0; }
  .nav-badge.gold { background: var(--gold); color: var(--bg-void); }
  .sidebar-profile { margin-top: auto; padding: 12px 8px 4px; border-top: 1px solid var(--border); }
  .sidebar-profile-inner { display: flex; gap: 10px; align-items: center; padding: 8px; border-radius: var(--radius-sm); background: var(--bg-elevated); }

  /* ─── MAIN CONTENT ─── */
  .ed-main { overflow-y: auto; padding: 24px; background: transparent; height: calc(100vh - var(--header-h)); }

  /* ─── CARDS ─── */
  .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); transition: border-color 0.2s; }
  .card:hover { border-color: var(--border-bright); }
  .card-p { padding: 20px; }
  .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .card-title { font-family: var(--font-display); font-weight: 700; font-size: 15px; }
  .card-sub { font-size: 12px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 1px; }

  /* ─── STUFF (kept from your original CSS) ─── */
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
  .stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 18px 20px; position: relative; overflow: hidden; transition: all 0.2s; cursor: default; }
  .stat-card::after { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: var(--accent-color, var(--gold)); opacity: 0.6; }
  .stat-card:hover { border-color: var(--border-bright); transform: translateY(-1px); }
  .stat-label { font-size: 11px; font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 8px; }
  .stat-value { font-family: var(--font-display); font-size: 28px; font-weight: 800; color: var(--text-primary); line-height: 1; }
  .stat-delta { font-size: 11px; font-family: var(--font-mono); margin-top: 6px; display: flex; align-items: center; gap: 4px; }
  .stat-delta.up { color: var(--emerald); }
  .stat-delta.down { color: var(--rose); }
  .stat-delta.neutral { color: var(--text-muted); }

  .convo-item { display: flex; gap: 12px; align-items: center; padding: 10px 12px; border-radius: var(--radius-sm); cursor: pointer; transition: background 0.12s; border: 1px solid transparent; }
  .convo-item:hover { background: var(--bg-elevated); }
  .convo-item.active { background: rgba(245,158,11,0.06); border-color: rgba(245,158,11,0.12); }
  .convo-avatar { width: 42px; height: 42px; border-radius: 12px; background: linear-gradient(135deg, #1e2d40, #0d1b2a); border: 1px solid var(--border-bright); display: flex; align-items: center; justify-content: center; font-family: var(--font-display); font-weight: 700; font-size: 16px; flex-shrink: 0; color: var(--gold); }
  .convo-name { font-weight: 700; font-size: 14px; }
  .convo-preview { font-size: 12px; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px; }
  .convo-time { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); white-space: nowrap; }
  .unread-pill { background: var(--gold); color: var(--bg-void); font-size: 10px; font-family: var(--font-mono); font-weight: 700; padding: 2px 7px; border-radius: 100px; flex-shrink: 0; }

  .messages-wrap { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 16px; scroll-behavior: smooth; }
  .msg-row { display: flex; gap: 10px; align-items: flex-end; max-width: 76%; }
  .msg-row.sent { flex-direction: row-reverse; margin-left: auto; }
  .msg-avatar { width: 32px; height: 32px; border-radius: 9px; background: linear-gradient(135deg, #1e2d40, #0d1b2a); border: 1px solid var(--border-bright); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 12px; color: var(--gold); flex-shrink: 0; }
  .msg-bubble { padding: 10px 14px; border-radius: 14px; font-size: 14px; line-height: 1.5; max-width: 100%; word-break: break-word; position: relative; }
  .msg-row.received .msg-bubble { background: var(--bg-elevated); border: 1px solid var(--border); border-bottom-left-radius: 4px; }
  .msg-row.sent .msg-bubble { background: linear-gradient(135deg, #2c2010, #1e1608); border: 1px solid rgba(245,158,11,0.12); border-bottom-right-radius: 4px; color: #f5e8c0; }
  .msg-meta { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 4px; display: flex; align-items: center; gap: 4px; }
  .msg-row.sent .msg-meta { justify-content: flex-end; }

  .input-field { width: 100%; background: var(--bg-elevated); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 9px 12px; color: var(--text-primary); font-family: var(--font-body); font-size: 14px; outline: none; transition: border-color 0.15s; }
  .input-field:focus { border-color: var(--gold); }
  .input-field.chat-input { border-radius: 12px; padding: 12px 16px; font-size: 14px; min-height: 44px; }
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: 7px; padding: 8px 16px; border-radius: var(--radius-sm); font-size: 13px; font-weight: 600; font-family: var(--font-body); cursor: pointer; border: none; transition: all 0.15s; white-space: nowrap; }
  .btn-primary { background: var(--gold); color: var(--bg-void); box-shadow: 0 0 20px var(--gold-glow); }
  .btn-primary:hover { background: #ffd04a; box-shadow: 0 0 30px var(--gold-glow); }
  .btn-secondary { background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text-secondary); }
  .btn-secondary:hover { border-color: var(--border-bright); color: var(--text-primary); }
  .btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text-muted); }
  .btn-ghost:hover { color: var(--text-secondary); border-color: var(--border-bright); }
  .btn-sm { padding: 5px 12px; font-size: 12px; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .btn-send { padding: 12px 18px; border-radius: 12px; min-width: 56px; min-height: 44px; }

  .chat-compose { display: flex; gap: 10px; align-items: flex-end; }

  .toast-stack { position: fixed; bottom: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
  .toast { padding: 12px 18px; border-radius: var(--radius-md); font-size: 13px; display: flex; align-items: center; gap: 10px; min-width: 240px; backdrop-filter: blur(16px); animation: toastIn 0.25s cubic-bezier(0.34,1.56,0.64,1); border: 1px solid var(--border-bright); color: #fff;}
  @keyframes toastIn { from { opacity: 0; transform: translateX(20px) scale(0.95); } to { opacity: 1; transform: translateX(0) scale(1); } }
  .toast.success { background: rgba(52,211,153,0.2); border-color: rgba(52,211,153,0.5); }
  .toast.error { background: rgba(251,113,133,0.2); border-color: rgba(251,113,133,0.5); }
  .toast.info { background: rgba(56,189,248,0.2); border-color: rgba(56,189,248,0.5); }

  .chip { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 100px; font-size: 11px; font-family: var(--font-mono); background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text-secondary); }
  .chip.gold { background: var(--gold-dim); border-color: rgba(245,158,11,0.16); color: var(--gold); }
  .chip.green { background: rgba(52,211,153,0.1); border-color: rgba(52,211,153,0.3); color: var(--emerald); }
  .chip.purple { background: rgba(167,139,250,0.1); border-color: rgba(167,139,250,0.3); color: var(--violet); }
  .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; padding: 40px 20px; color: var(--text-muted); text-align: center; }
  .quick-chips { display: flex; gap: 6px; flex-wrap: wrap; }
  .quick-chip { padding: 8px 12px; border-radius: 100px; background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text-secondary); font-size: 13px; cursor: pointer; transition: all 0.12s; min-height: 40px; display:flex; align-items:center; }
  .quick-chip:hover { border-color: var(--gold); color: var(--gold); }
  .earnings-bar { flex: 1; border-radius: 4px 4px 0 0; background: linear-gradient(180deg, var(--gold) 0%, rgba(245,158,11,0.35) 100%); transition: opacity 0.15s; }
  .progress-wrap { margin: 8px 0; }
  .progress-track { height: 5px; background: var(--bg-elevated); border-radius: 100px; overflow: hidden; }
  .progress-fill { height: 100%; border-radius: 100px; background: linear-gradient(90deg, var(--gold), #e09020); }
  .ai-bubble { padding: 14px 16px; background: linear-gradient(135deg, rgba(167,139,250,0.08), rgba(56,189,248,0.05)); border: 1px solid rgba(167,139,250,0.2); border-radius: var(--radius-md); font-size: 14px; line-height: 1.7; white-space: pre-wrap; color: var(--text-primary); }
  .profile-hero { background: linear-gradient(135deg, rgba(245,158,11,0.04) 0%, rgba(8,11,18,0) 60%); border: 1px solid var(--border); border-radius: var(--radius-xl); padding: 28px; margin-bottom: 20px; }
  .profile-avatar { width: 88px; height: 88px; border-radius: 22px; background: linear-gradient(135deg, var(--gold), #c0850a); display: flex; align-items: center; justify-content: center; font-family: var(--font-display); font-weight: 800; font-size: 36px; color: var(--bg-void); box-shadow: 0 0 40px var(--gold-glow); }
  .cal-strip { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 4px; }
  .cal-day { flex-shrink: 0; width: 48px; height: 64px; border-radius: 10px; background: var(--bg-elevated); border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; justify-content: center; font-family: var(--font-mono); }
  .cal-day.today { border-color: var(--gold); background: var(--gold-dim); }
  .cal-day-num { font-size: 18px; font-weight: 700; line-height: 1; }
  .cal-day-name { font-size: 9px; color: var(--text-muted); margin-top: 3px; text-transform: uppercase; }
  .stars { display: flex; gap: 2px; }
  .star { color: var(--gold); font-size: 13px; }
  .star.empty { color: var(--text-muted); }
  .pay-status { padding: 3px 10px; border-radius: 100px; font-size: 10px; font-family: var(--font-mono); font-weight: 600; text-transform: uppercase; }
  .pay-status.paid { background: rgba(52,211,153,0.12); color: var(--emerald); border: 1px solid rgba(52,211,153,0.3); }
  .pay-status.pending, .pay-status.created { background: rgba(245,158,11,0.08); color: var(--gold); border: 1px solid rgba(245,158,11,0.12); }
  .pay-status.failed { background: rgba(251,113,133,0.1); color: var(--rose); border: 1px solid rgba(251,113,133,0.3); }
  .table-wrapper { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .data-table { width: 100%; border-collapse: collapse; min-width: 500px; }
  .data-table th { text-align: left; font-size: 10px; font-family: var(--font-mono); text-transform: uppercase; color: var(--text-muted); padding: 0 8px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .data-table td { padding: 10px 8px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.03); }
  .fade-in { animation: fadeIn 0.2s ease-out; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.06); border-radius: 100px; }

  .chat-layout-grid {
    display: grid;
    grid-template-columns: 340px 1fr;
    gap: 16px;
    height: calc(100vh - var(--header-h) - 52px - 48px);
    min-height: 0;
  }

  .ed-sidebar.mobile-open { transform: translateX(0); box-shadow: 10px 0 30px rgba(0,0,0,0.6); }
  .mobile-overlay { display: none; position: fixed; inset: 0; top: var(--header-h); background: rgba(0,0,0,0.5); z-index: 150; transition: opacity 0.18s; }
  .mobile-overlay.mobile-open { display: block; }

  @media (max-width: 1024px) {
    .ed-body { grid-template-columns: 72px 1fr; }
    .nav-section-label, .brand-text, .brand-sub, .sidebar-profile-inner > div:last-child { display: none; }
    .sidebar-profile-inner { justify-content: center; background: transparent; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .chat-layout-grid { grid-template-columns: 280px 1fr; }
  }

  @media (max-width: 768px) {
    .ed-header { padding: 0 12px; }
    .mobile-menu-btn { display: flex !important; }
    .ed-header-center { display: none; }
    .ed-header-right { gap: 6px; }
    .hide-on-mobile { display: none !important; }

    /* show the horizontal top nav only on small screens */
    .mobile-top-nav { display: flex; }

    .ed-body { grid-template-columns: 1fr; }
    .ed-sidebar { 
      position: fixed; top: var(--header-h); left: 0; bottom: 0; z-index: 200; 
      transform: translateX(-100%); transition: transform 0.28s ease;
      width: 260px; background: rgba(2,6,23,0.98); backdrop-filter: blur(20px);
      box-shadow: 10px 0 30px rgba(0,0,0,0.5);
    }
    .ed-sidebar.mobile-open { transform: translateX(0); }
    .mobile-overlay.mobile-open { display: block; }

    .stats-grid { grid-template-columns: 1fr; }
    .ed-main { padding: 12px; }
    .profile-hero > div { flex-direction: column; align-items: center; text-align: center; }
    .profile-hero .chip { margin: 0 auto; }

    .chat-layout-grid { display: flex; flex-direction: column; height: calc(100vh - var(--header-h) - 20px); gap: 12px; }
    .chat-sidebar-mobile-hide { display: block !important; }
    .chat-main-mobile-hide { display: block !important; }
    .chat-back-btn { display: flex !important; }
    .msg-bubble { font-size: 13px; }
    .msg-row { max-width: 85%; }
    .chat-layout-grid > .card:first-child { max-height: 36vh; overflow-y: auto; }
    .chat-layout-grid > .card:last-child { flex: 1; display: flex; flex-direction: column; min-height: 0; }
    .messages-wrap { flex: 1; min-height: 0; padding: 12px; }
    .chat-compose { position: sticky; bottom: 0; background: linear-gradient(180deg, rgba(2,6,23,0), rgba(2,6,23,0.02)); padding: 8px; z-index: 80; border-top: 1px solid var(--border); }
  }

  @media (max-width: 480px) {
    .convo-preview { max-width: 120px; }
    .convo-avatar { width: 40px; height: 40px; font-size: 14px; }
    .brand-text { display: none; }
    .brand-sub { display: none; }
  }
`;

/* ─── Utils ─── */
const formatTime = (ts) => {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    const now = new Date();
    const diff = now - d;
    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short" });
  } catch { return ""; }
};

const fmtCurrency = (n, currency = "INR") => {
  if (n == null || n === "") return "—";
  const val = Number(n);
  if (Number.isNaN(val)) return "—";
  try { return new Intl.NumberFormat("en-IN", { style: "currency", currency, maximumFractionDigits: 0 }).format(val); }
  catch { return `${currency} ${val}`; }
};

const Stars = ({ rating = 4.5 }) => {
  const full = Math.floor(rating);
  return (
    <div className="stars">
      {[1, 2, 3, 4, 5].map(i => <span key={i} className={`star ${i <= full ? "" : "empty"}`}>★</span>)}
    </div>
  );
};

/* ─── AI Panel ─── */
const AiPanel = ({ onAsk, response, loading }) => {
  const [prompt, setPrompt] = useState("");
  const suggestions = [
    "Summarize my last 5 conversations",
    "Draft a professional follow-up message",
    "How should I handle an unresponsive client?",
  ];
  return (
    <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="suggestions-grid">
        {suggestions.map((s, i) => (
          <button key={i} className="btn btn-secondary btn-sm" style={{ textAlign: "left", whiteSpace: "normal", lineHeight: 1.4 }} onClick={() => setPrompt(s)}>{s}</button>
        ))}
      </div>
      <div>
        <textarea
          className="input-field" rows={4} placeholder="Ask anything: draft messages, summarize chats, technical explanations…"
          value={prompt} onChange={e => setPrompt(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter" && e.ctrlKey && prompt.trim()) onAsk(prompt); }}
          style={{ marginBottom: 8 }}
        />
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" onClick={() => { if (prompt.trim()) onAsk(prompt); }} disabled={loading || !prompt.trim()}>
            {loading ? "Thinking…" : "✦ Ask AI"}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={() => setPrompt("")}>Clear</button>
        </div>
      </div>
      {(response || loading) && (
        <div>
          <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase" }}>Response</div>
          <div className="ai-bubble">{loading ? "Thinking..." : response}</div>
        </div>
      )}
    </div>
  );
};

/* ─── Main Dashboard ─── */
const ExpertDashboard = () => {
  const navigate = useNavigate();

  const token = localStorage.getItem("token");
  const storedRole = localStorage.getItem("role");
  const expertEmail = localStorage.getItem("email");
  const expertName = localStorage.getItem("name") || "Expert";

  useEffect(() => {
    if (!token || !expertEmail || storedRole !== "expert") {
      navigate("/login", { replace: true });
    }
  }, [token, expertEmail, storedRole, navigate]);

  const NAV = { DASHBOARD: "dashboard", CONVERSATIONS: "conversations", CLIENTS: "clients", PAYMENTS: "payments", AI: "ai", PROFILE: "profile" };

  const [selectedNav, setSelectedNav] = useState(NAV.DASHBOARD);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  
  const [profile, setProfile] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [payments, setPayments] = useState([]);
  const [expertsList, setExpertsList] = useState([]);
  const [loadingApp, setLoadingApp] = useState(true);

  const [activeRoom, setActiveRoom] = useState(null);
  const activeRoomRef = useRef(null); 
  const [activeOther, setActiveOther] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState("");
  const [onlineCount, setOnlineCount] = useState(0);
  const [loadingMessages, setLoadingMessages] = useState(false);

  const [aiResponse, setAiResponse] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [toasts, setToasts] = useState([]);
  
  const socketRef = useRef(null);
  const messagesEndRef = useRef(null);

  const isMobile = () => typeof window !== 'undefined' && window.innerWidth <= 768;

  const showToast = useCallback((text, type = "info", ms = 3000) => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, text, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), ms);
  }, []);

  useEffect(() => {
    // lock body scroll when mobile menu open
    if (mobileMenuOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => { document.body.style.overflow = ''; };
  }, [mobileMenuOpen]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const headers = { Authorization: `Bearer ${token}` };
        const [profRes, convRes, payRes, expRes] = await Promise.all([
          fetch(`${API}/api/profile?email=${expertEmail}`, { headers }),
          fetch(`${API}/api/conversations?email=${expertEmail}`, { headers }),
          fetch(`${API}/api/my-payments`, { headers }),
          fetch(`${API}/api/experts?status=approved`, { headers })
        ]);

        const profData = await profRes.json();
        const convData = await convRes.json();
        const payData = await payRes.json();
        const expData = await expRes.json();

        if (!profData.error) setProfile(profData);
        if (Array.isArray(convData)) setConversations(convData);
        if (Array.isArray(payData)) setPayments(payData);
        if (Array.isArray(expData)) setExpertsList(expData);
      } catch (err) {
        showToast("Error loading dashboard data", "error");
      } finally {
        setLoadingApp(false);
      }
    };
    if (token) fetchData();
  }, [expertEmail, token, showToast]);

  useEffect(() => {
    if (!API || !token) return;
    const s = io(API, { auth: { token }, transports: ["websocket"] });
    socketRef.current = s;
    
    s.on("connect", () => s.emit("authenticate", { token }));
    s.on("online_users", (map) => setOnlineCount(map ? Object.keys(map).length : 0));
    
    s.on("chat_history", (history) => {
      setMessages(Array.isArray(history) ? history : []);
      setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    });
    
    s.on("receive_message", (msg) => {
      if (!msg?.room) return;
      if (msg.room === activeRoomRef.current) {
        setMessages(prev => [...prev, msg]);
        setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }), 80);
      }
      setConversations(prev => {
        const exists = prev.find(c => c.room === msg.room);
        if (exists) {
          return prev.map(c => c.room === msg.room ? { ...c, lastMessage: msg.message, lastMessageTime: msg.createdAt, unread: (c.unread || 0) + (msg.room !== activeRoomRef.current ? 1 : 0) } : c);
        } else {
          return [{ room: msg.room, lastMessage: msg.message, lastMessageTime: msg.createdAt, otherEmail: msg.author, unread: 1 }, ...prev];
        }
      });
    });

    s.on("disconnect", () => {});
    
    return () => { try { s.disconnect(); } catch {} };
  }, [API, token]); 

  const openConversation = useCallback(async (convo) => {
    if (!convo?.room) return;
    const other = convo.otherEmail || convo.room.split("_").find(e => e !== expertEmail) || "User";

    setActiveRoom(convo.room);
    activeRoomRef.current = convo.room;
    setActiveOther(other);
    setMessages([]);
    setLoadingMessages(true);
    setSelectedNav(NAV.CONVERSATIONS);

    try {
      const res = await fetch(`${API}/api/messages?room=${encodeURIComponent(convo.room)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const history = await res.json();
        setMessages(history);
        setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: "instant" }), 50);
      }
    } catch (err) {
      showToast("Failed to fetch message history", "error");
    } finally {
      setLoadingMessages(false);
    }

    setTimeout(() => {
      try {
        socketRef.current?.emit("join_private", convo.room);
      } catch (err) {}
    }, 45);

    setConversations(prev => prev.map(c => c.room === convo.room ? { ...c, unread: 0 } : c));

    if (isMobile()) setMobileMenuOpen(false);
  }, [expertEmail, token, showToast, NAV.CONVERSATIONS]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = useCallback(async () => {
    const roomToUse = activeRoomRef.current || activeRoom;
    if (!roomToUse || !inputValue.trim()) return;
    const text = inputValue.trim();
    setInputValue("");
    
    const optimisticMsg = {
      _id: Date.now().toString(),
      room: roomToUse,
      author: expertEmail,
      authorRole: "expert",
      message: text,
      createdAt: new Date().toISOString()
    };
    setMessages(prev => [...prev, optimisticMsg]);
    setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);

    if (socketRef.current?.connected) {
      socketRef.current.emit("send_private_message", { room: roomToUse, author: expertEmail, authorRole: "expert", message: text });
    }

    try {
      fetch(`${API}/api/messages`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ room: roomToUse, author: expertEmail, message: text }) }).catch(()=>{});
    } catch {}
  }, [inputValue, expertEmail, activeRoom, token]);

  const askAI = useCallback(async (prompt) => {
    setAiLoading(true);
    setAiResponse("");
    try {
      const res = await fetch(`${API}/api/ai/ask`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ prompt }) });
      const data = await res.json();
      setAiResponse(data?.answer || "No response received.");
    } catch { setAiResponse("AI service error — check your connection."); }
    setAiLoading(false);
  }, [token]);

  const logout = () => {
    ["token","email","name","role"].forEach(k => localStorage.removeItem(k));
    navigate("/login");
  };

  const handleNavClick = (id) => {
    setSelectedNav(id);
    setMobileMenuOpen(false);
    // optionally clear activeRoom when switching away from conversations
    if (id !== NAV.CONVERSATIONS) {
      setActiveRoom(null);
      activeRoomRef.current = null;
    }
  };

  const unreadCount = useMemo(() => conversations.reduce((a, c) => a + (c.unread || 0), 0), [conversations]);
  
  const earningsData = useMemo(() => {
    const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const currentMonth = new Date().getMonth();
    let chart = [];
    for(let i=6; i>=0; i--) {
      let d = new Date();
      d.setMonth(currentMonth - i);
      chart.push({ label: months[d.getMonth()], val: 0, current: i === 0, monthNum: d.getMonth(), year: d.getFullYear() });
    }
    payments.forEach(p => {
      const amt = Number(p?.amount || 0);
      if (p?.status === "paid" && !Number.isNaN(amt) && p?.createdAt) {
        const d = new Date(p.createdAt);
        const match = chart.find(c => c.monthNum === d.getMonth() && c.year === d.getFullYear());
        if (match) match.val += amt;
      }
    });
    return chart;
  }, [payments]);

  const totalEarnings = useMemo(() => {
    return payments.reduce((a, b) => {
      const amt = Number(b?.amount || 0);
      if (b?.status === "paid" && !Number.isNaN(amt)) return a + amt;
      return a;
    }, 0);
  }, [payments]);

  const thisMonthEarnings = earningsData[earningsData.length - 1]?.val || 0;

  const calDays = useMemo(() => {
    const days = [];
    const dayNames = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    for (let i = 0; i < 7; i++) {
      const d = new Date();
      d.setDate(d.getDate() + i);
      days.push({ num: d.getDate(), name: dayNames[d.getDay()], isToday: i === 0, status: i % 3 === 0 ? "available" : "booked" });
    }
    return days;
  }, []);

  const navItems = [
    { id: NAV.DASHBOARD, label: "Overview", icon: "⬡" },
    { id: NAV.CONVERSATIONS, label: "Chats", icon: "◈", badge: unreadCount > 0 ? `${unreadCount}` : null },
    { id: NAV.CLIENTS, label: "Clients", icon: "◉" },
    { id: NAV.PAYMENTS, label: "Payments", icon: "◈" },
    { id: NAV.AI, label: "AI", icon: "✦", badgeColor: "gold" },
    { id: NAV.PROFILE, label: "Profile", icon: "◎" },
  ];

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        if (mobileMenuOpen) setMobileMenuOpen(false);
        else if (isMobile() && activeRoom) setActiveRoom(null);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mobileMenuOpen, activeRoom]);

  useEffect(() => {
    const onResize = () => {
      if (isMobile()) setSidebarCollapsed(false);
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  if (loadingApp) return <div style={{ background: "var(--bg-void)", height: "100vh", color: "var(--gold)", display: "flex", alignItems: "center", justifyContent: "center" }}>Initializing Workspace...</div>;

  return (
    <>
      <style>{css}</style>
      <div className="ed-root">
        
        {/* TOASTS */}
        <div className="toast-stack" aria-live="polite">
          {toasts.map(t => (
            <div key={t.id} className={`toast ${t.type}`}>
              <span>{t.type === "success" ? "✓" : t.type === "error" ? "✕" : "i"}</span> <span>{t.text}</span>
            </div>
          ))}
        </div>

        {/* MOBILE OVERLAY */}
        <div className={`mobile-overlay ${mobileMenuOpen ? 'mobile-open' : ''}`} onClick={() => setMobileMenuOpen(false)} aria-hidden={!mobileMenuOpen} />

        {/* HEADER */}
        <header className="ed-header">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              className="mobile-menu-btn"
              onClick={() => setMobileMenuOpen(s => !s)}
              aria-label="Open menu"
              aria-expanded={mobileMenuOpen}
              title="Open menu"
            >
              ☰
            </button>
            <div className="ed-header-brand" onClick={() => handleNavClick(NAV.DASHBOARD)} role="button" tabIndex={0}>
              <div className="brand-mark">S</div>
              <div>
                <div className="brand-text">SolutionHub</div>
                <div className="brand-sub">Expert Console</div>
              </div>
            </div>
          </div>
          <div className="ed-header-center">
            <div className="pill-badge"><div className="pulse-dot" />{onlineCount} online</div>
            <div className="pill-badge" style={{ color: "var(--emerald)", borderColor: "rgba(52,211,153,0.3)" }}>✓ Approved</div>
          </div>
          <div className="ed-header-right">
            <div className="hide-on-mobile" style={{ display: "flex", flexDirection: "column", alignItems: "flex-end" }}>
              <div style={{ fontSize: 13, fontWeight: 700 }}>{profile?.name || expertName}</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{expertEmail}</div>
            </div>
            <div className="avatar-btn" title={profile?.name || expertName}>{(profile?.name || expertName)[0].toUpperCase()}</div>
            <button className="btn-logout hide-on-mobile" onClick={logout}>Sign out</button>
          </div>
        </header>

        {/* HORIZONTAL MOBILE NAV (visible on small screens) */}
        <div className="mobile-top-nav" role="navigation" aria-label="Mobile navigation">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`mobile-nav-btn ${selectedNav === item.id ? "active" : ""}`}
              onClick={() => handleNavClick(item.id)}
              aria-current={selectedNav === item.id}
              title={item.label}
            >
              <span style={{ fontSize: 14 }}>{item.icon}</span>
              <span style={{ opacity: 0.95, marginLeft: 6 }}>{item.label}</span>
              {item.badge && <span style={{ marginLeft: 8, fontFamily: 'var(--font-mono)', fontSize: 12 }}>{item.badge}</span>}
            </button>
          ))}
        </div>

        {/* BODY */}
        <div className={`ed-body ${sidebarCollapsed ? "collapsed" : ""}`}>
          
          {/* SIDEBAR */}
          <aside className={`ed-sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`} aria-hidden={!mobileMenuOpen && isMobile()}>
            <button className="btn btn-ghost btn-sm hide-on-mobile" style={{ marginBottom: 16, display: "flex", gap: 6 }} onClick={() => setSidebarCollapsed(s => !s)}>
              {sidebarCollapsed ? "→" : "← Collapse"}
            </button>
            <nav>
              {navItems.map(item => (
                <div
                  key={item.id}
                  className={`nav-item ${selectedNav === item.id ? "active" : ""}`}
                  onClick={() => { handleNavClick(item.id); setMobileMenuOpen(false); }}
                  role="button"
                  tabIndex={0}
                  aria-current={selectedNav === item.id}
                >
                  <div className="nav-icon" style={{ fontSize: 16 }}>{item.icon}</div>
                  {(!sidebarCollapsed || mobileMenuOpen) && (
                    <>
                      <span style={{ flex: 1 }}>{item.label}</span>
                      {item.badge && <span className={`nav-badge ${item.badgeColor || ""}`}>{item.badge}</span>}
                    </>
                  )}
                </div>
              ))}
            </nav>
            {(!sidebarCollapsed || mobileMenuOpen) && (
              <div className="sidebar-profile">
                <div className="sidebar-profile-inner">
                  <div style={{ width: 32, height: 32, borderRadius: 9, background: "var(--gold)", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, color: "var(--bg-void)", fontSize: 14 }}>
                    {(profile?.name || expertName)[0].toUpperCase()}
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 700, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis" }}>{profile?.name || expertName}</div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{profile?.field || "Expert"}</div>
                  </div>
                </div>
              </div>
            )}
          </aside>

          {/* MAIN VIEWPORT */}
          <main className="ed-main">

            {/* OVERVIEW TAB */}
            {selectedNav === NAV.DASHBOARD && (
              <div className="fade-in">
                <div style={{ marginBottom: 24 }}>
                  <h1 style={{ fontFamily: "var(--font-display)", fontSize: "clamp(20px, 3vw, 26px)", fontWeight: 800, marginBottom: 4 }}>Good morning, {(profile?.name || expertName).split(" ")[0]} ☀️</h1>
                  <div style={{ color: "var(--text-secondary)", fontSize: 14 }}>Here's an overview of your expert activity.</div>
                </div>

                <div className="stats-grid">
                  {[
                    { label: "Total Revenue", value: fmtCurrency(totalEarnings), delta: `${payments.filter(p => p.status === "paid").length} paid tx`, dir: "up", icon: "◉", accent: "var(--gold)" },
                    { label: "This Month", value: fmtCurrency(thisMonthEarnings), delta: "Current Cycle", dir: "neutral", icon: "◈", accent: "var(--emerald)" },
                    { label: "Active Chats", value: conversations.length, delta: `${unreadCount} unread`, dir: "up", icon: "◇", accent: "var(--sky)" },
                    { label: "Session Rate", value: profile?.price ? fmtCurrency(Number(profile.price), profile.currency || "INR") : "—", delta: "Per session", dir: "neutral", icon: "⬡", accent: "var(--violet)" },
                  ].map((s, i) => (
                    <div key={i} className="stat-card" style={{ "--accent-color": s.accent }}>
                      <div className="stat-label">{s.label}</div>
                      <div className="stat-value">{s.value}</div>
                      <div className={`stat-delta ${s.dir}`}>{s.dir === "up" ? "▲" : s.dir === "down" ? "▼" : "—"} {s.delta}</div>
                      <div className="stat-icon">{s.icon}</div>
                    </div>
                  ))}
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: 16 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                    
                    <div className="card card-p">
                      <div className="card-header">
                        <div>
                          <div className="card-title">Earnings Overview</div>
                          <div className="card-sub">Last 7 months (Live)</div>
                        </div>
                        <div style={{ textAlign: "right" }}>
                          <div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: 20, color: "var(--gold)" }}>{fmtCurrency(totalEarnings)}</div>
                        </div>
                      </div>
                      <div>
                        <div style={{ display: "flex", alignItems: "flex-end", gap: 6, height: 80 }}>
                          {earningsData.map((d, i) => {
                             const max = Math.max(...earningsData.map(e => e.val), 1);
                             return (
                               <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center" }}>
                                 <div className="earnings-bar" style={{ height: `${Math.max(8, (d.val / max) * 100) * 0.8}%`, width: "100%", background: d.current ? "var(--gold)" : "rgba(245,158,11,0.22)" }} title={`₹${d.val}`} />
                               </div>
                             );
                          })}
                        </div>
                        <div style={{ display: "flex", gap: 6 }}>
                          {earningsData.map((d, i) => (
                            <div key={i} style={{ flex: 1, textAlign: "center" }}>
                              <div className="month-label" style={{ color: d.current ? "var(--gold)" : "var(--text-muted)" }}>{d.label}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="card card-p">
                      <div className="card-header">
                        <div className="card-title">Recent Chats</div>
                        <button className="btn btn-ghost btn-sm" onClick={() => handleNavClick(NAV.CONVERSATIONS)}>View all →</button>
                      </div>
                      {conversations.slice(0, 5).map((c, i) => {
                        const other = c.otherEmail || c.room?.split("_").find(e => e !== expertEmail) || "User";
                        return (
                          <div key={c.room} className="convo-item" onClick={() => openConversation(c)}>
                            <div className="convo-avatar">{other[0].toUpperCase()}</div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div className="convo-name">{other}</div>
                              <div className="convo-preview">{c.lastMessage || "—"}</div>
                            </div>
                            <div style={{ textAlign: "right", flexShrink: 0 }}>
                              <div className="convo-time">{formatTime(c.lastMessageTime)}</div>
                              {c.unread > 0 && <div className="unread-pill" style={{ marginTop: 4 }}>{c.unread}</div>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                    <div className="card card-p">
                      <div style={{ display: "flex", gap: 14, alignItems: "center", marginBottom: 14 }}>
                        <div className="avatar-btn" style={{ width: 52, height: 52, fontSize: 22 }}>{(profile?.name || expertName)[0].toUpperCase()}</div>
                        <div>
                          <div style={{ fontWeight: 800, fontFamily: "var(--font-display)" }}>{profile?.name || expertName}</div>
                          <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>{profile?.field}</div>
                          <Stars rating={4.8} />
                        </div>
                      </div>
                      <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 12 }}>{profile?.headline}</div>
                      <button className="btn btn-secondary btn-sm" style={{ width: "100%" }} onClick={() => handleNavClick(NAV.PROFILE)}>Edit Profile</button>
                    </div>

                    <div className="card card-p">
                      <div className="card-header">
                        <div className="card-title">Availability</div>
                      </div>
                      <div className="cal-strip">
                        {calDays.map((d, i) => (
                          <div key={i} className={`cal-day ${d.isToday ? "today" : d.status}`}>
                            <div className="cal-day-num" style={{ color: d.isToday ? "var(--gold)" : "var(--text-primary)" }}>{d.num}</div>
                            <div className="cal-day-name">{d.name}</div>
                            {d.status && <div className="cal-day-dot" style={{ width: 5, height: 5, borderRadius: "50%", marginTop: 4, background: d.status === "available" ? "var(--emerald)" : "var(--rose)" }} />}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* CONVERSATIONS TAB */}
            {selectedNav === NAV.CONVERSATIONS && (
              <div className="fade-in chat-layout-grid">
                {/* List Side */}
                <div className={`card ${activeRoom ? 'chat-sidebar-mobile-hide' : ''}`} style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
                  <div style={{ padding: "16px 16px 8px" }}>
                    <div className="card-title" style={{ marginBottom: 12 }}>Conversations ({conversations.length})</div>
                  </div>
                  <div style={{ flex: 1, overflowY: "auto", padding: "0 8px 8px" }}>
                    {conversations.length === 0 ? <div className="empty-state">No conversations yet</div> : conversations.map(c => {
                      const other = c.otherEmail || c.room?.split("_").find(e => e !== expertEmail) || "User";
                      return (
                        <div key={c.room} className={`convo-item ${activeRoom === c.room ? "active" : ""}`} onClick={() => openConversation(c)}>
                          <div className="convo-avatar" style={{ background: activeRoom === c.room ? "var(--gold-dim)" : undefined, color: activeRoom === c.room ? "var(--gold)" : undefined }}>{other[0].toUpperCase()}</div>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div className="convo-name">{other}</div>
                            <div className="convo-preview">{c.lastMessage || "Start conversation"}</div>
                          </div>
                          <div style={{ textAlign: "right" }}>
                            <div className="convo-time">{formatTime(c.lastMessageTime)}</div>
                            {c.unread > 0 && <div className="unread-pill" style={{ marginTop: 4 }}>{c.unread}</div>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Chat Window Side */}
                <div className={`card ${!activeRoom ? 'chat-main-mobile-hide' : ''}`} style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
                  <div style={{ padding: "14px 20px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 12 }}>
                    {activeRoom && <button className="chat-back-btn" onClick={() => setActiveRoom(null)}>← Back</button>}
                    {activeOther ? (
                      <>
                        <div className="convo-avatar">{activeOther[0].toUpperCase()}</div>
                        <div>
                          <div style={{ fontWeight: 800 }}>{activeOther}</div>
                          <div style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>Live • Private Room</div>
                        </div>
                      </>
                    ) : <div style={{ color: "var(--text-muted)", fontSize: 14 }}>Select a conversation to start chatting</div>}
                  </div>
                  <div className="messages-wrap" style={{ flex: 1, overflowY: "auto" }}>
                    {loadingMessages && <div style={{ color: "var(--gold)", textAlign: "center", padding: "10px" }}>Loading messages...</div>}
                    {!loadingMessages && messages.length === 0 && activeRoom && <div className="empty-state">No messages yet. Send a greeting!</div>}
                    {messages.map((m, i) => {
                      const isMe = m.author === expertEmail;
                      return (
                        <div key={m._id || i} className={`msg-row ${isMe ? "sent" : "received"}`}>
                          {!isMe && <div className="msg-avatar">{(m.author || "U")[0].toUpperCase()}</div>}
                          <div>
                            <div className={`msg-bubble`}>{m.message}</div>
                            <div className="msg-meta">{isMe && <span style={{ color: "var(--gold)" }}>✓✓</span>} {formatTime(m.createdAt)}</div>
                          </div>
                        </div>
                      );
                    })}
                    <div ref={messagesEndRef} />
                  </div>
                  <div style={{ padding: "12px 16px", borderTop: "1px solid var(--border)" }}>
                    <div className="quick-chips" style={{ marginBottom: 10 }}>
                      {["Thanks, noted!", "Are you available for a quick call?", "Could you share more details?"].map((q, i) => (
                        <button key={i} className="quick-chip" disabled={!activeRoom} onClick={() => setInputValue(p => p ? `${p} ${q}` : q)}>{q}</button>
                      ))}
                    </div>
                    <div className="chat-compose">
                      <textarea className="input-field chat-input" style={{ flex: 1 }} rows={2} placeholder={activeRoom ? "Type a message… (Enter to send)" : "Select a conversation first…"} disabled={!activeRoom} value={inputValue} onChange={e => setInputValue(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }} />
                      <button className="btn btn-primary btn-send" onClick={sendMessage} disabled={!activeRoom || !inputValue.trim()} style={{ alignSelf: "flex-end" }}>➤ Send</button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* PAYMENTS TAB */}
            {selectedNav === NAV.PAYMENTS && (
              <div className="fade-in">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                  <div>
                    <h2 style={{ fontFamily: "var(--font-display)", fontWeight: 800 }}>Payments Ledger</h2>
                    <div style={{ color: "var(--text-muted)", fontSize: 13, fontFamily: "var(--font-mono)" }}>{payments.length} transactions</div>
                  </div>
                </div>
                <div className="card">
                  <div className="table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr><th>Client Name</th><th>Service</th><th>Amount</th><th>Date</th><th>Status</th></tr>
                      </thead>
                      <tbody>
                        {payments.map(p => (
                          <tr key={p._id}>
                            <td>
                              <div style={{ fontWeight: 700, fontSize: 13 }}>{p.clientName}</div>
                              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{p.clientEmail}</div>
                            </td>
                            <td style={{ fontSize: 13, color: "var(--text-secondary)" }}>{p.notes?.purpose || "Consultation"}</td>
                            <td style={{ fontFamily: "var(--font-display)", fontWeight: 700, color: "var(--gold)" }}>{fmtCurrency(p.amount, p.currency)}</td>
                            <td style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>{formatTime(p.createdAt)}</td>
                            <td><div className={`pay-status ${p.status}`}>{p.status}</div></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* CLIENTS TAB */}
            {selectedNav === NAV.CLIENTS && (
              <div className="fade-in">
                 <h2 style={{ fontFamily: "var(--font-display)", fontWeight: 800, marginBottom: 20 }}>Client Management</h2>
                 <div className="card">
                    <div className="table-wrapper">
                      <table className="data-table">
                        <thead><tr><th>Client Email</th><th>Total Spend</th><th>Last Action</th></tr></thead>
                        <tbody>
                          {Array.from(new Set(payments.map(p => p.clientEmail || ""))).map(email => {
                             if(!email) return null;
                             const clientPayments = payments.filter(p => p.clientEmail === email);
                             const total = clientPayments.reduce((a, b) => b.status === 'paid' ? a + Number(b.amount || 0) : a, 0);
                             return (
                               <tr key={email}>
                                  <td style={{ fontWeight: 700 }}>{email}</td>
                                  <td style={{ color: "var(--gold)", fontWeight: "bold" }}>{fmtCurrency(total)}</td>
                                  <td style={{ color: "var(--text-muted)" }}>{formatTime(clientPayments[0]?.createdAt)}</td>
                               </tr>
                             );
                          })}
                        </tbody>
                      </table>
                    </div>
                 </div>
              </div>
            )}

            {/* AI TAB */}
            {selectedNav === NAV.AI && (
              <div className="fade-in" style={{ maxWidth: 860 }}>
                <h2 style={{ fontFamily: "var(--font-display)", fontWeight: 800, marginBottom: 8 }}>AI Assistant</h2>
                <div className="chip purple" style={{ marginBottom: 20 }}>✦ Powered by Gemini API</div>
                <div className="card card-p"><AiPanel onAsk={askAI} response={aiResponse} loading={aiLoading} /></div>
              </div>
            )}

            {/* PROFILE TAB */}
            {selectedNav === NAV.PROFILE && (
              <div className="fade-in" style={{ maxWidth: 800 }}>
                <h2 style={{ fontFamily: "var(--font-display)", fontWeight: 800, marginBottom: 20 }}>Expert Profile</h2>
                <div className="profile-hero">
                  <div style={{ display: "flex", gap: 24, alignItems: "flex-start" }}>
                    <div className="profile-avatar">{(profile?.name || "E")[0].toUpperCase()}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 6 }}>
                        <div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: "clamp(20px, 3vw, 24px)" }}>{profile?.name}</div>
                        <div className="chip green">✓ {profile?.status}</div>
                      </div>
                      <div style={{ color: "var(--text-secondary)", marginBottom: 4 }}>{profile?.headline}</div>
                      <div style={{ fontSize: 13, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 12 }}>{profile?.email} • {profile?.field}</div>
                    </div>
                  </div>
                </div>
                <div className="card card-p">
                  <div className="card-title" style={{ marginBottom: 12 }}>About</div>
                  <textarea className="input-field" rows={4} defaultValue={profile?.summary || ""} readOnly />
                </div>
              </div>
            )}

          </main>
        </div>
      </div>
    </>
  );
};

export default ExpertDashboard;