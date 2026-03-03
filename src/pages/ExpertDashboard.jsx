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

/* ─── Premium CSS ─── */
const css = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@400;500&family=Cabinet+Grotesk:wght@400;500;700;800&display=swap');

  :root {
    --brand-1: #10b981;
    --brand-2: #14b8a6;
    --accent: #f59e0b;
    --bg: #020617;
    --card: rgba(13, 20, 38, 0.97);
    --card-hover: rgba(20, 30, 55, 0.97);
    --muted: #94a3b8;
    --text: #f1f5f9;
    --border: rgba(148, 163, 184, 0.12);
    --border-bright: rgba(255,255,255,0.1);
    --glass: rgba(13, 20, 38, 0.92);
    --gold: #f59e0b;
    --gold-dim: rgba(245,158,11,0.10);
    --gold-glow: rgba(245,158,11,0.22);
    --emerald: #10b981;
    --rose: #fb7185;
    --sky: #38bdf8;
    --violet: #a78bfa;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #475569;
    --radius-sm: 10px;
    --radius-md: 14px;
    --radius-lg: 18px;
    --radius-xl: 24px;
    --font-display: 'Syne', sans-serif;
    --font-body: 'Cabinet Grotesk', sans-serif;
    --font-mono: 'DM Mono', monospace;
    --sidebar-w: 240px;
    --header-h: 60px;
    --safe: 16px;
    --transition: 0.2s cubic-bezier(0.4,0,0.2,1);
  }

  html, body {
    margin: 0; padding: 0;
    overflow-x: hidden;
    background: var(--bg);
    color: var(--text-primary);
    font-family: var(--font-body);
    -webkit-font-smoothing: antialiased;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  /* scrollbar */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 100px; }

  /* ─── ROOT LAYOUT ─── */
  .ed-root { min-height: 100vh; background: var(--bg); overflow-x: hidden; }

  /* ambient glow blobs */
  .ambient {
    position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden;
  }
  .ambient-blob {
    position: absolute; border-radius: 50%;
    filter: blur(120px); opacity: 0.07;
  }
  .ambient-blob-1 { width: 600px; height: 600px; background: var(--brand-1); top: -200px; left: -200px; }
  .ambient-blob-2 { width: 500px; height: 500px; background: var(--gold); bottom: -150px; right: -150px; }
  .ambient-blob-3 { width: 400px; height: 400px; background: var(--violet); top: 40%; left: 40%; }

  /* ─── HEADER ─── */
  .ed-header {
    position: sticky; top: 0; z-index: 300;
    height: var(--header-h);
    background: rgba(2, 6, 23, 0.92);
    backdrop-filter: blur(20px) saturate(1.6);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 20px; gap: 12px;
  }

  .header-left { display: flex; align-items: center; gap: 10px; }
  .brand-mark {
    width: 34px; height: 34px;
    background: linear-gradient(135deg, var(--brand-1), var(--brand-2));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-family: var(--font-display); font-weight: 800; font-size: 17px;
    color: #020617; flex-shrink: 0;
    box-shadow: 0 0 20px rgba(16,185,129,0.2);
  }
  .brand-text { font-family: var(--font-display); font-weight: 800; font-size: 16px; color: var(--text-primary); letter-spacing: -0.3px; }
  .brand-sub { font-size: 9px; font-family: var(--font-mono); color: var(--gold); text-transform: uppercase; letter-spacing: 0.1em; }

  .header-center { display: flex; align-items: center; gap: 8px; }
  .pill-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 4px 11px; border-radius: 100px;
    font-size: 11px; font-family: var(--font-mono);
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .pill-badge.green { border-color: rgba(16,185,129,0.25); color: var(--emerald); }
  .pulse-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--emerald); flex-shrink: 0;
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.45; transform:scale(0.75); } }

  .header-right { display: flex; align-items: center; gap: 8px; }
  .header-user-info { display: flex; flex-direction: column; align-items: flex-end; }
  .header-user-name { font-size: 12px; font-weight: 700; color: var(--text-primary); }
  .header-user-email { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }
  .avatar-btn {
    width: 34px; height: 34px; border-radius: 10px;
    background: linear-gradient(135deg, var(--brand-1), var(--brand-2));
    border: none; cursor: pointer;
    font-family: var(--font-display); font-weight: 800; font-size: 14px;
    color: #020617; display: flex; align-items: center; justify-content: center;
    transition: transform var(--transition), box-shadow var(--transition);
    flex-shrink: 0;
  }
  .avatar-btn:hover { transform: scale(1.06); box-shadow: 0 0 18px rgba(16,185,129,0.18); }
  .btn-logout {
    padding: 6px 14px;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text-secondary);
    font-size: 11px; font-family: var(--font-mono);
    cursor: pointer; transition: all 0.15s; white-space: nowrap;
  }
  .btn-logout:hover { border-color: var(--rose); color: var(--rose); }
  .mobile-menu-btn {
    display: none;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 9px;
    color: var(--text-primary);
    font-size: 18px;
    cursor: pointer;
    width: 36px; height: 36px;
    align-items: center; justify-content: center;
    transition: border-color 0.15s;
    flex-shrink: 0;
  }
  .mobile-menu-btn:hover { border-color: var(--border-bright); }

  /* ─── MOBILE TAB NAV ─── */
  .mobile-tab-nav {
    display: none;
    position: sticky; top: var(--header-h); z-index: 200;
    background: rgba(2,6,23,0.95);
    backdrop-filter: blur(16px);
    border-bottom: 1px solid var(--border);
    padding: 8px 12px;
    gap: 6px;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: none;
  }
  .mobile-tab-nav::-webkit-scrollbar { display: none; }
  .mobile-tab-btn {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 7px 13px; border-radius: 9px;
    white-space: nowrap;
    font-family: var(--font-mono); font-size: 12px;
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border);
    color: var(--text-secondary);
    cursor: pointer; flex-shrink: 0;
    transition: all 0.15s;
  }
  .mobile-tab-btn.active {
    background: linear-gradient(90deg, rgba(245,158,11,0.18), rgba(245,158,11,0.08));
    color: var(--gold); border-color: rgba(245,158,11,0.25);
  }

  /* ─── MAIN LAYOUT ─── */
  .ed-layout {
    display: grid;
    grid-template-columns: var(--sidebar-w) 1fr;
    min-height: calc(100vh - var(--header-h));
    position: relative; z-index: 1;
  }

  /* ─── SIDEBAR ─── */
  .ed-sidebar {
    background: rgba(5, 10, 25, 0.85);
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    padding: 14px 10px;
    position: sticky; top: var(--header-h);
    height: calc(100vh - var(--header-h));
    overflow-y: auto;
    transition: transform 0.28s cubic-bezier(0.4,0,0.2,1);
    z-index: 200;
  }

  .nav-section { margin-bottom: 4px; }
  .nav-section-label {
    font-size: 9px; font-family: var(--font-mono);
    text-transform: uppercase; letter-spacing: 0.12em;
    color: var(--text-muted); padding: 4px 10px 6px;
  }
  .nav-item {
    display: flex; align-items: center; gap: 10px;
    padding: 9px 10px; border-radius: 10px;
    cursor: pointer; transition: all 0.16s;
    font-size: 13.5px; font-weight: 500;
    color: var(--text-secondary);
    border: 1px solid transparent;
    margin-bottom: 2px; position: relative;
  }
  .nav-item:hover { background: rgba(255,255,255,0.04); color: var(--text-primary); }
  .nav-item.active {
    background: linear-gradient(90deg, rgba(245,158,11,0.12), rgba(245,158,11,0.04));
    border-color: rgba(245,158,11,0.2); color: var(--gold);
  }
  .nav-icon {
    width: 30px; height: 30px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 8px; font-size: 13px; flex-shrink: 0;
    background: rgba(255,255,255,0.04);
    transition: background 0.15s;
  }
  .nav-item.active .nav-icon { background: rgba(245,158,11,0.08); }
  .nav-label { flex: 1; }
  .nav-badge {
    background: var(--rose); color: white;
    font-size: 9px; font-family: var(--font-mono); font-weight: 700;
    padding: 2px 6px; border-radius: 100px; flex-shrink: 0; min-width: 16px; text-align: center;
  }
  .nav-badge.gold { background: var(--gold); color: #020617; }

  .sidebar-divider { height: 1px; background: var(--border); margin: 10px 0; }

  .sidebar-bottom { margin-top: auto; padding-top: 10px; }
  .sidebar-profile {
    display: flex; gap: 10px; align-items: center;
    padding: 10px; border-radius: 10px;
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--border);
  }
  .sidebar-avatar {
    width: 32px; height: 32px; border-radius: 9px;
    background: var(--gold); display: flex; align-items: center; justify-content: center;
    font-weight: 800; color: #020617; font-size: 14px; flex-shrink: 0;
  }
  .sidebar-name { font-weight: 700; font-size: 12px; color: var(--text-primary); }
  .sidebar-role { font-size: 10px; color: var(--text-muted); }

  /* ─── MAIN ─── */
  .ed-main { overflow-y: auto; padding: 28px 24px; height: calc(100vh - var(--header-h)); }

  /* ─── MOBILE OVERLAY ─── */
  .mobile-overlay {
    display: none; position: fixed; inset: 0;
    top: var(--header-h); background: rgba(0,0,0,0.6);
    z-index: 180; backdrop-filter: blur(2px);
  }
  .mobile-overlay.open { display: block; }

  /* ─── FADE IN ─── */
  .fade-in { animation: fadeIn 0.22s ease-out; }
  @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }

  /* ─── PAGE HEADER ─── */
  .page-header { margin-bottom: 24px; }
  .page-title { font-family: var(--font-display); font-weight: 800; font-size: clamp(20px, 3vw, 26px); color: var(--text-primary); }
  .page-sub { font-size: 13px; color: var(--text-secondary); margin-top: 3px; }

  /* ─── CARDS ─── */
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    transition: border-color var(--transition), box-shadow var(--transition);
  }
  .card:hover { border-color: var(--border-bright); }
  .card-p { padding: 20px; }
  .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .card-title { font-family: var(--font-display); font-weight: 700; font-size: 14px; color: var(--text-primary); }
  .card-sub { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px; }

  /* ─── STATS GRID ─── */
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 18px 20px;
    position: relative; overflow: hidden;
    transition: all 0.22s; cursor: default;
  }
  .stat-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent-c, var(--gold)); opacity: 0.7;
  }
  .stat-card::after {
    content: var(--stat-icon, '');
    position: absolute; right: 14px; bottom: 10px;
    font-size: 36px; opacity: 0.06;
    font-family: var(--font-display);
  }
  .stat-card:hover { border-color: var(--border-bright); transform: translateY(-2px); box-shadow: 0 12px 40px rgba(0,0,0,0.25); }
  .stat-label { font-size: 10px; font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.09em; color: var(--text-muted); margin-bottom: 10px; }
  .stat-value { font-family: var(--font-display); font-size: 26px; font-weight: 800; color: var(--text-primary); line-height: 1; }
  .stat-delta { font-size: 11px; font-family: var(--font-mono); margin-top: 7px; display: flex; align-items: center; gap: 4px; }
  .stat-delta.up { color: var(--emerald); }
  .stat-delta.down { color: var(--rose); }
  .stat-delta.neutral { color: var(--text-muted); }

  /* ─── BUTTONS ─── */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    padding: 8px 16px; border-radius: var(--radius-sm);
    font-size: 13px; font-weight: 600; font-family: var(--font-body);
    cursor: pointer; border: none; transition: all 0.15s; white-space: nowrap;
  }
  .btn-primary { background: var(--gold); color: #020617; box-shadow: 0 0 24px var(--gold-glow); }
  .btn-primary:hover { background: #fbbf24; box-shadow: 0 0 36px var(--gold-glow); }
  .btn-secondary { background: rgba(255,255,255,0.05); border: 1px solid var(--border); color: var(--text-secondary); }
  .btn-secondary:hover { background: rgba(255,255,255,0.08); border-color: var(--border-bright); color: var(--text-primary); }
  .btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text-muted); }
  .btn-ghost:hover { color: var(--text-secondary); border-color: var(--border-bright); }
  .btn-danger { background: rgba(251,113,133,0.12); border: 1px solid rgba(251,113,133,0.2); color: var(--rose); }
  .btn-danger:hover { background: rgba(251,113,133,0.2); }
  .btn-sm { padding: 5px 12px; font-size: 11px; }
  .btn:disabled { opacity: 0.35; cursor: not-allowed; }
  .btn-icon { width: 32px; height: 32px; padding: 0; border-radius: 8px; }

  /* ─── INPUT ─── */
  .input-field {
    width: 100%;
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 10px 14px;
    color: var(--text-primary);
    font-family: var(--font-body); font-size: 13.5px;
    outline: none; transition: border-color 0.15s, background 0.15s;
    resize: vertical;
  }
  .input-field::placeholder { color: var(--text-muted); }
  .input-field:focus { border-color: rgba(245,158,11,0.4); background: rgba(255,255,255,0.05); }
  .input-search {
    padding-left: 36px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E");
    background-repeat: no-repeat; background-position: 12px center;
  }

  /* ─── CHIPS ─── */
  .chip { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 100px; font-size: 11px; font-family: var(--font-mono); background: rgba(255,255,255,0.05); border: 1px solid var(--border); color: var(--text-secondary); }
  .chip.gold { background: var(--gold-dim); border-color: rgba(245,158,11,0.2); color: var(--gold); }
  .chip.green { background: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.25); color: var(--emerald); }
  .chip.purple { background: rgba(167,139,250,0.1); border-color: rgba(167,139,250,0.25); color: var(--violet); }
  .chip.rose { background: rgba(251,113,133,0.1); border-color: rgba(251,113,133,0.2); color: var(--rose); }
  .chip.sky { background: rgba(56,189,248,0.1); border-color: rgba(56,189,248,0.2); color: var(--sky); }

  /* ─── CONVERSATIONS ─── */
  .chat-grid { display: grid; grid-template-columns: 300px 1fr; gap: 14px; height: calc(100vh - var(--header-h) - 56px - 48px); min-height: 0; }
  .convo-item { display: flex; gap: 11px; align-items: center; padding: 10px 12px; border-radius: 10px; cursor: pointer; transition: background 0.12s; border: 1px solid transparent; }
  .convo-item:hover { background: rgba(255,255,255,0.04); }
  .convo-item.active { background: rgba(245,158,11,0.07); border-color: rgba(245,158,11,0.15); }
  .convo-avatar { width: 40px; height: 40px; border-radius: 11px; background: linear-gradient(135deg, #1e2d40, #0d1b2a); border: 1px solid var(--border-bright); display: flex; align-items: center; justify-content: center; font-family: var(--font-display); font-weight: 700; font-size: 15px; flex-shrink: 0; color: var(--gold); }
  .convo-name { font-weight: 700; font-size: 13px; }
  .convo-preview { font-size: 11.5px; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 180px; margin-top: 2px; }
  .convo-time { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); white-space: nowrap; }
  .unread-pill { background: var(--gold); color: #020617; font-size: 9px; font-family: var(--font-mono); font-weight: 700; padding: 2px 6px; border-radius: 100px; flex-shrink: 0; margin-top: 4px; text-align: center; }

  /* ─── MESSAGES ─── */
  .messages-wrap { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 14px; scroll-behavior: smooth; }
  .msg-row { display: flex; gap: 10px; align-items: flex-end; max-width: 74%; }
  .msg-row.sent { flex-direction: row-reverse; margin-left: auto; }
  .msg-avatar { width: 30px; height: 30px; border-radius: 8px; background: linear-gradient(135deg, #1e2d40, #0d1b2a); border: 1px solid var(--border-bright); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 11px; color: var(--gold); flex-shrink: 0; }
  .msg-bubble { padding: 10px 14px; border-radius: 14px; font-size: 13.5px; line-height: 1.55; max-width: 100%; word-break: break-word; }
  .msg-row.received .msg-bubble { background: rgba(255,255,255,0.05); border: 1px solid var(--border); border-bottom-left-radius: 4px; color: var(--text-primary); }
  .msg-row.sent .msg-bubble { background: linear-gradient(135deg, rgba(45,32,8,0.9), rgba(30,21,5,0.9)); border: 1px solid rgba(245,158,11,0.15); border-bottom-right-radius: 4px; color: #f5e8c0; }
  .msg-meta { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 4px; display: flex; align-items: center; gap: 4px; }
  .msg-row.sent .msg-meta { justify-content: flex-end; }
  .typing-indicator { display: flex; gap: 4px; padding: 10px 14px; background: rgba(255,255,255,0.04); border-radius: 14px; width: fit-content; }
  .typing-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--text-muted); animation: typingPulse 1.4s ease-in-out infinite; }
  .typing-dot:nth-child(2) { animation-delay: 0.2s; }
  .typing-dot:nth-child(3) { animation-delay: 0.4s; }
  @keyframes typingPulse { 0%,80%,100%{transform:scale(0.7);opacity:0.5} 40%{transform:scale(1);opacity:1} }

  /* compose */
  .compose-bar { padding: 12px 16px; border-top: 1px solid var(--border); background: rgba(2,6,23,0.6); }
  .quick-chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
  .quick-chip { padding: 6px 12px; border-radius: 100px; background: rgba(255,255,255,0.04); border: 1px solid var(--border); color: var(--text-secondary); font-size: 12px; cursor: pointer; transition: all 0.12s; }
  .quick-chip:hover { border-color: rgba(245,158,11,0.3); color: var(--gold); }
  .quick-chip:disabled { opacity: 0.3; cursor: default; }
  .compose-row { display: flex; gap: 8px; align-items: flex-end; }
  .chat-input { border-radius: 12px; padding: 11px 14px; font-size: 13.5px; min-height: 44px; resize: none; }
  .btn-send { padding: 11px 18px; border-radius: 12px; min-width: 56px; min-height: 44px; align-self: flex-end; }

  /* ─── EARNINGS CHART ─── */
  .earnings-chart { display: flex; align-items: flex-end; gap: 6px; height: 80px; margin-bottom: 8px; }
  .earnings-bar-wrap { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 4px; height: 100%; justify-content: flex-end; }
  .earnings-bar { width: 100%; border-radius: 5px 5px 0 0; background: rgba(245,158,11,0.22); transition: opacity 0.15s; min-height: 4px; }
  .earnings-bar.current { background: linear-gradient(180deg, var(--gold) 0%, rgba(245,158,11,0.5) 100%); }
  .earnings-month { font-size: 9px; font-family: var(--font-mono); color: var(--text-muted); }
  .earnings-month.current { color: var(--gold); }

  /* ─── CALENDAR ─── */
  .cal-strip { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 4px; }
  .cal-day { flex-shrink: 0; width: 46px; height: 62px; border-radius: 10px; background: rgba(255,255,255,0.03); border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; justify-content: center; font-family: var(--font-mono); gap: 2px; }
  .cal-day.today { border-color: rgba(245,158,11,0.4); background: var(--gold-dim); }
  .cal-day-num { font-size: 16px; font-weight: 700; line-height: 1; }
  .cal-day-name { font-size: 8px; color: var(--text-muted); text-transform: uppercase; }
  .cal-dot { width: 5px; height: 5px; border-radius: 50%; margin-top: 2px; }

  /* ─── STARS ─── */
  .stars { display: flex; gap: 2px; }
  .star { font-size: 12px; }

  /* ─── TABLE ─── */
  .table-wrapper { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .data-table { width: 100%; border-collapse: collapse; min-width: 460px; }
  .data-table th { text-align: left; font-size: 10px; font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.09em; color: var(--text-muted); padding: 0 10px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .data-table td { padding: 11px 10px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.03); }
  .data-table tr:last-child td { border-bottom: none; }
  .data-table tr:hover td { background: rgba(255,255,255,0.02); }

  /* ─── PAY STATUS ─── */
  .pay-status { padding: 3px 10px; border-radius: 100px; font-size: 10px; font-family: var(--font-mono); font-weight: 600; text-transform: uppercase; display: inline-block; }
  .pay-status.paid { background: rgba(16,185,129,0.12); color: var(--emerald); border: 1px solid rgba(16,185,129,0.25); }
  .pay-status.pending, .pay-status.created { background: rgba(245,158,11,0.09); color: var(--gold); border: 1px solid rgba(245,158,11,0.18); }
  .pay-status.failed { background: rgba(251,113,133,0.1); color: var(--rose); border: 1px solid rgba(251,113,133,0.2); }

  /* ─── EMPTY STATE ─── */
  .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px; padding: 40px 20px; color: var(--text-muted); text-align: center; }
  .empty-state-icon { font-size: 32px; opacity: 0.4; }
  .empty-state-title { font-size: 14px; font-weight: 600; color: var(--text-secondary); }
  .empty-state-desc { font-size: 12px; font-family: var(--font-mono); }

  /* ─── TOASTS ─── */
  .toast-stack { position: fixed; bottom: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
  .toast { padding: 12px 16px; border-radius: 12px; font-size: 13px; display: flex; align-items: center; gap: 10px; min-width: 220px; backdrop-filter: blur(20px); animation: toastIn 0.22s cubic-bezier(0.34,1.56,0.64,1); border: 1px solid var(--border-bright); color: #fff; }
  @keyframes toastIn { from { opacity:0; transform:translateX(18px) scale(0.94); } to { opacity:1; transform:translateX(0) scale(1); } }
  .toast.success { background: rgba(16,185,129,0.18); border-color: rgba(16,185,129,0.35); }
  .toast.error { background: rgba(251,113,133,0.18); border-color: rgba(251,113,133,0.35); }
  .toast.info { background: rgba(56,189,248,0.15); border-color: rgba(56,189,248,0.3); }

  /* ─── AI PANEL ─── */
  .ai-suggestions { display: grid; grid-template-columns: repeat(3,1fr); gap: 8px; margin-bottom: 16px; }
  .ai-suggestion-btn { padding: 10px 12px; border-radius: 10px; background: rgba(167,139,250,0.07); border: 1px solid rgba(167,139,250,0.15); color: var(--text-secondary); font-size: 12px; line-height: 1.4; text-align: left; cursor: pointer; transition: all 0.15s; font-family: var(--font-body); }
  .ai-suggestion-btn:hover { background: rgba(167,139,250,0.12); border-color: rgba(167,139,250,0.25); color: var(--text-primary); }
  .ai-bubble { padding: 16px; background: linear-gradient(135deg, rgba(167,139,250,0.07), rgba(56,189,248,0.04)); border: 1px solid rgba(167,139,250,0.18); border-radius: 12px; font-size: 13.5px; line-height: 1.75; white-space: pre-wrap; color: var(--text-primary); }

  /* ─── PROFILE ─── */
  .profile-hero { background: linear-gradient(135deg, rgba(245,158,11,0.05), rgba(8,11,18,0)); border: 1px solid var(--border); border-radius: var(--radius-xl); padding: 28px; margin-bottom: 20px; }
  .profile-avatar { width: 80px; height: 80px; border-radius: 20px; background: linear-gradient(135deg, var(--gold), #c0850a); display: flex; align-items: center; justify-content: center; font-family: var(--font-display); font-weight: 800; font-size: 32px; color: #020617; box-shadow: 0 0 40px var(--gold-glow); flex-shrink: 0; }

  /* ─── PROGRESS ─── */
  .progress-track { height: 4px; background: rgba(255,255,255,0.06); border-radius: 100px; overflow: hidden; }
  .progress-fill { height: 100%; border-radius: 100px; background: linear-gradient(90deg, var(--gold), #e09020); transition: width 0.6s ease; }

  /* ─── OVERVIEW GRID ─── */
  .overview-grid { display: grid; grid-template-columns: 1fr 360px; gap: 16px; }
  .overview-left { display: flex; flex-direction: column; gap: 16px; }
  .overview-right { display: flex; flex-direction: column; gap: 16px; }

  /* ─── RESPONSIVE ─── */
  @media (max-width: 1100px) {
    :root { --sidebar-w: 200px; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .overview-grid { grid-template-columns: 1fr; }
    .overview-right { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .chat-grid { grid-template-columns: 260px 1fr; }
    .ai-suggestions { grid-template-columns: repeat(2,1fr); }
  }

  @media (max-width: 820px) {
    .ed-layout { grid-template-columns: 1fr; }
    .ed-sidebar {
      position: fixed; top: var(--header-h); left: 0; bottom: 0;
      width: 240px; transform: translateX(-100%);
      background: rgba(2,6,23,0.98); backdrop-filter: blur(24px);
      box-shadow: 8px 0 32px rgba(0,0,0,0.5);
    }
    .ed-sidebar.open { transform: translateX(0); }
    .mobile-menu-btn { display: flex; }
    .header-center { display: none; }
    .header-user-info { display: none; }
    .mobile-tab-nav { display: flex; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .overview-grid { grid-template-columns: 1fr; }
    .overview-right { display: grid; grid-template-columns: 1fr 1fr; }
    .chat-grid { grid-template-columns: 1fr; height: auto; display: flex; flex-direction: column; }
    .chat-list-panel { max-height: 38vh; }
    .chat-window-panel { flex: 1; min-height: 0; display: flex; flex-direction: column; }
    .msg-row { max-width: 90%; }
    .ai-suggestions { grid-template-columns: 1fr; }
    .ed-main { padding: 16px 14px; }
    .hide-mobile { display: none !important; }
  }

  @media (max-width: 540px) {
    .stats-grid { grid-template-columns: 1fr; }
    .overview-right { grid-template-columns: 1fr; }
    .ed-main { padding: 12px 12px; }
    .chat-list-panel { max-height: 32vh; }
    .brand-text { display: none; }
    .stat-value { font-size: 22px; }
    .convo-preview { max-width: 130px; }
    .profile-hero { padding: 18px; }
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
    if (diff < 604800000) return d.toLocaleDateString("en-IN", { weekday: "short" });
    return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short" });
  } catch { return ""; }
};

const fmtCurrency = (n, currency = "INR") => {
  if (n == null || n === "") return "—";
  const val = Number(n);
  if (Number.isNaN(val)) return "—";
  try {
    return new Intl.NumberFormat("en-IN", {
      style: "currency", currency,
      maximumFractionDigits: 0
    }).format(val);
  } catch { return `${currency} ${val}`; }
};

const Stars = ({ rating = 4.5 }) => {
  const full = Math.floor(rating);
  return (
    <div className="stars">
      {[1,2,3,4,5].map(i => (
        <span key={i} className="star" style={{ color: i <= full ? "var(--gold)" : "var(--text-muted)" }}>★</span>
      ))}
    </div>
  );
};

/* ─── AI PANEL ─── */
const AiPanel = ({ onAsk, response, loading }) => {
  const [prompt, setPrompt] = useState("");
  const suggestions = [
    "Summarize my last 5 conversations",
    "Draft a professional follow-up message",
    "How should I handle an unresponsive client?",
    "Tips to improve client retention",
    "Write an introduction for my profile",
    "What questions should I ask new clients?",
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="ai-suggestions">
        {suggestions.map((s, i) => (
          <button key={i} className="ai-suggestion-btn" onClick={() => setPrompt(s)}>{s}</button>
        ))}
      </div>
      <div>
        <textarea
          className="input-field"
          rows={4}
          placeholder="Ask anything: draft messages, summarize chats, explain concepts, client strategies…"
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter" && e.ctrlKey && prompt.trim()) onAsk(prompt); }}
          style={{ marginBottom: 10 }}
        />
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" onClick={() => { if (prompt.trim()) onAsk(prompt); }} disabled={loading || !prompt.trim()}>
            {loading ? "⟳ Thinking…" : "✦ Ask AI"}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={() => setPrompt("")}>Clear</button>
          {prompt.trim() && (
            <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", alignSelf: "center" }}>
              Ctrl+Enter to send
            </span>
          )}
        </div>
      </div>
      {(response || loading) && (
        <div>
          <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.1em" }}>
            ✦ AI Response
          </div>
          <div className="ai-bubble">
            {loading ? (
              <div style={{ display: "flex", gap: 8, alignItems: "center", color: "var(--text-muted)" }}>
                <div className="typing-indicator">
                  <div className="typing-dot" />
                  <div className="typing-dot" />
                  <div className="typing-dot" />
                </div>
                Generating response…
              </div>
            ) : response}
          </div>
        </div>
      )}
    </div>
  );
};

/* ─── MAIN COMPONENT ─── */
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
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [profile, setProfile] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [payments, setPayments] = useState([]);
  const [loadingApp, setLoadingApp] = useState(true);

  const [activeRoom, setActiveRoom] = useState(null);
  const activeRoomRef = useRef(null);
  const [activeOther, setActiveOther] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState("");
  const [onlineCount, setOnlineCount] = useState(0);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [convoSearch, setConvoSearch] = useState("");

  const [aiResponse, setAiResponse] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [toasts, setToasts] = useState([]);

  const socketRef = useRef(null);
  const messagesEndRef = useRef(null);

  const showToast = useCallback((text, type = "info", ms = 3000) => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, text, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), ms);
  }, []);

  useEffect(() => {
    document.body.style.overflow = sidebarOpen ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [sidebarOpen]);

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const headers = { Authorization: `Bearer ${token}` };
        const [profRes, convRes, payRes] = await Promise.all([
          fetch(`${API}/api/profile?email=${expertEmail}`, { headers }),
          fetch(`${API}/api/conversations?email=${expertEmail}`, { headers }),
          fetch(`${API}/api/my-payments`, { headers }),
        ]);
        const profData = await profRes.json();
        const convData = await convRes.json();
        const payData = await payRes.json();
        if (!profData.error) setProfile(profData);
        if (Array.isArray(convData)) setConversations(convData);
        if (Array.isArray(payData)) setPayments(payData);
      } catch {
        showToast("Error loading dashboard data", "error");
      } finally {
        setLoadingApp(false);
      }
    };
    if (token) fetchData();
  }, [expertEmail, token, showToast]);

  // Socket
  useEffect(() => {
    if (!API || !token) return;
    const s = io(API, { auth: { token }, transports: ["websocket"] });
    socketRef.current = s;
    s.on("connect", () => s.emit("authenticate", { token }));
    s.on("online_users", (map) => setOnlineCount(map ? Object.keys(map).length : 0));
    s.on("receive_message", (msg) => {
      if (!msg?.room) return;
      if (msg.room === activeRoomRef.current) {
        setMessages(prev => [...prev, msg]);
        setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }), 80);
      }
      setConversations(prev => {
        const exists = prev.find(c => c.room === msg.room);
        if (exists) {
          return prev.map(c => c.room === msg.room
            ? { ...c, lastMessage: msg.message, lastMessageTime: msg.createdAt, unread: (c.unread || 0) + (msg.room !== activeRoomRef.current ? 1 : 0) }
            : c);
        }
        return [{ room: msg.room, lastMessage: msg.message, lastMessageTime: msg.createdAt, otherEmail: msg.author, unread: 1 }, ...prev];
      });
    });
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
    } catch {
      showToast("Failed to fetch message history", "error");
    } finally {
      setLoadingMessages(false);
    }
    setTimeout(() => {
      try { socketRef.current?.emit("join_private", convo.room); } catch {}
    }, 45);
    setConversations(prev => prev.map(c => c.room === convo.room ? { ...c, unread: 0 } : c));
    setSidebarOpen(false);
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
      room: roomToUse, author: expertEmail, authorRole: "expert",
      message: text, createdAt: new Date().toISOString()
    };
    setMessages(prev => [...prev, optimisticMsg]);
    setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
    if (socketRef.current?.connected) {
      socketRef.current.emit("send_private_message", { room: roomToUse, author: expertEmail, authorRole: "expert", message: text });
    }
    try {
      fetch(`${API}/api/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ room: roomToUse, author: expertEmail, message: text })
      }).catch(() => {});
    } catch {}
  }, [inputValue, expertEmail, activeRoom, token]);

  const askAI = useCallback(async (prompt) => {
    setAiLoading(true);
    setAiResponse("");
    try {
      const res = await fetch(`${API}/api/ai/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ prompt })
      });
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
    setSidebarOpen(false);
    if (id !== NAV.CONVERSATIONS) { setActiveRoom(null); activeRoomRef.current = null; }
  };

  const unreadCount = useMemo(() => conversations.reduce((a, c) => a + (c.unread || 0), 0), [conversations]);

  const earningsData = useMemo(() => {
    const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const current = new Date().getMonth();
    let chart = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setMonth(current - i);
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

  const totalEarnings = useMemo(() => payments.reduce((a, b) => {
    const amt = Number(b?.amount || 0);
    return b?.status === "paid" && !Number.isNaN(amt) ? a + amt : a;
  }, 0), [payments]);

  const thisMonthEarnings = earningsData[earningsData.length - 1]?.val || 0;

  const calDays = useMemo(() => {
    const dayNames = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    return Array.from({ length: 7 }, (_, i) => {
      const d = new Date(); d.setDate(d.getDate() + i);
      return { num: d.getDate(), name: dayNames[d.getDay()], isToday: i === 0, status: i % 3 === 0 ? "available" : "busy" };
    });
  }, []);

  const filteredConvos = useMemo(() => {
    if (!convoSearch.trim()) return conversations;
    const q = convoSearch.toLowerCase();
    return conversations.filter(c => {
      const other = (c.otherEmail || c.room || "").toLowerCase();
      return other.includes(q) || (c.lastMessage || "").toLowerCase().includes(q);
    });
  }, [conversations, convoSearch]);

  const navItems = [
    { id: NAV.DASHBOARD, label: "Overview", icon: "⬡" },
    { id: NAV.CONVERSATIONS, label: "Chats", icon: "◈", badge: unreadCount > 0 ? `${unreadCount}` : null },
    { id: NAV.CLIENTS, label: "Clients", icon: "◉" },
    { id: NAV.PAYMENTS, label: "Payments", icon: "◈" },
    { id: NAV.AI, label: "AI Assistant", icon: "✦", badgeColor: "gold" },
    { id: NAV.PROFILE, label: "Profile", icon: "◎" },
  ];

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") { setSidebarOpen(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (loadingApp) {
    return (
      <div style={{ background: "var(--bg)", height: "100vh", color: "var(--gold)", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 12, fontFamily: "var(--font-display)" }}>
        <div style={{ fontSize: 36 }}>⬡</div>
        <div style={{ fontSize: 16, fontWeight: 700 }}>Initializing Workspace…</div>
      </div>
    );
  }

  return (
    <>
      <style>{css}</style>
      <div className="ed-root">

        {/* AMBIENT */}
        <div className="ambient" aria-hidden>
          <div className="ambient-blob ambient-blob-1" />
          <div className="ambient-blob ambient-blob-2" />
          <div className="ambient-blob ambient-blob-3" />
        </div>

        {/* TOASTS */}
        <div className="toast-stack" aria-live="polite">
          {toasts.map(t => (
            <div key={t.id} className={`toast ${t.type}`}>
              <span>{t.type === "success" ? "✓" : t.type === "error" ? "✕" : "i"}</span>
              <span>{t.text}</span>
            </div>
          ))}
        </div>

        {/* MOBILE OVERLAY */}
        <div className={`mobile-overlay ${sidebarOpen ? "open" : ""}`} onClick={() => setSidebarOpen(false)} aria-hidden />

        {/* ─── HEADER ─── */}
        <header className="ed-header">
          <div className="header-left">
            <button className="mobile-menu-btn" onClick={() => setSidebarOpen(s => !s)} aria-label="Toggle menu" aria-expanded={sidebarOpen}>
              {sidebarOpen ? "✕" : "☰"}
            </button>
            <div style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }} onClick={() => handleNavClick(NAV.DASHBOARD)}>
              <div className="brand-mark">S</div>
              <div>
                <div className="brand-text">SolutionHub</div>
                <div className="brand-sub">Expert Console</div>
              </div>
            </div>
          </div>

          <div className="header-center">
            <div className="pill-badge"><div className="pulse-dot" />{onlineCount} online</div>
            <div className="pill-badge green">✓ Approved</div>
          </div>

          <div className="header-right">
            <div className="header-user-info">
              <div className="header-user-name">{profile?.name || expertName}</div>
              <div className="header-user-email">{expertEmail}</div>
            </div>
            <div className="avatar-btn" title={profile?.name || expertName}>
              {(profile?.name || expertName)[0].toUpperCase()}
            </div>
            <button className="btn-logout hide-mobile" onClick={logout}>Sign out</button>
          </div>
        </header>

        {/* ─── MOBILE TAB NAV ─── */}
        <nav className="mobile-tab-nav" aria-label="Mobile navigation">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`mobile-tab-btn ${selectedNav === item.id ? "active" : ""}`}
              onClick={() => handleNavClick(item.id)}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
              {item.badge && <span style={{ background: "var(--rose)", color: "#fff", borderRadius: 100, padding: "1px 5px", fontSize: 9, fontFamily: "var(--font-mono)" }}>{item.badge}</span>}
            </button>
          ))}
        </nav>

        {/* ─── BODY ─── */}
        <div className="ed-layout">

          {/* ─── SIDEBAR ─── */}
          <aside className={`ed-sidebar ${sidebarOpen ? "open" : ""}`} aria-label="Sidebar navigation">
            <nav className="nav-section">
              <div className="nav-section-label">Main</div>
              {navItems.slice(0, 4).map(item => (
                <div
                  key={item.id}
                  className={`nav-item ${selectedNav === item.id ? "active" : ""}`}
                  onClick={() => handleNavClick(item.id)}
                  role="button" tabIndex={0}
                  onKeyDown={e => e.key === "Enter" && handleNavClick(item.id)}
                  aria-current={selectedNav === item.id}
                >
                  <div className="nav-icon">{item.icon}</div>
                  <span className="nav-label">{item.label}</span>
                  {item.badge && <span className={`nav-badge ${item.badgeColor || ""}`}>{item.badge}</span>}
                </div>
              ))}
            </nav>

            <div className="sidebar-divider" />

            <nav className="nav-section">
              <div className="nav-section-label">Tools</div>
              {navItems.slice(4).map(item => (
                <div
                  key={item.id}
                  className={`nav-item ${selectedNav === item.id ? "active" : ""}`}
                  onClick={() => handleNavClick(item.id)}
                  role="button" tabIndex={0}
                  onKeyDown={e => e.key === "Enter" && handleNavClick(item.id)}
                  aria-current={selectedNav === item.id}
                >
                  <div className="nav-icon">{item.icon}</div>
                  <span className="nav-label">{item.label}</span>
                  {item.badge && <span className={`nav-badge ${item.badgeColor || ""}`}>{item.badge}</span>}
                </div>
              ))}
            </nav>

            <div className="sidebar-divider" />

            <div className="nav-section">
              <div
                className="nav-item"
                onClick={logout}
                role="button" tabIndex={0}
                onKeyDown={e => e.key === "Enter" && logout()}
                style={{ color: "var(--rose)" }}
              >
                <div className="nav-icon" style={{ fontSize: 14 }}>⎋</div>
                <span className="nav-label">Sign out</span>
              </div>
            </div>

            <div className="sidebar-bottom">
              <div className="sidebar-profile">
                <div className="sidebar-avatar">{(profile?.name || expertName)[0].toUpperCase()}</div>
                <div style={{ minWidth: 0 }}>
                  <div className="sidebar-name" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{profile?.name || expertName}</div>
                  <div className="sidebar-role">{profile?.field || "Expert"}</div>
                </div>
              </div>
            </div>
          </aside>

          {/* ─── MAIN ─── */}
          <main className="ed-main">

            {/* ══════════ OVERVIEW ══════════ */}
            {selectedNav === NAV.DASHBOARD && (
              <div className="fade-in">
                <div className="page-header">
                  <h1 className="page-title">Good morning, {(profile?.name || expertName).split(" ")[0]} ☀️</h1>
                  <p className="page-sub">Here's your workspace overview for today.</p>
                </div>

                <div className="stats-grid">
                  {[
                    { label: "Total Revenue", value: fmtCurrency(totalEarnings), delta: `${payments.filter(p => p.status === "paid").length} paid transactions`, dir: "up", accent: "var(--gold)" },
                    { label: "This Month", value: fmtCurrency(thisMonthEarnings), delta: "Current billing cycle", dir: "neutral", accent: "var(--emerald)" },
                    { label: "Active Chats", value: conversations.length, delta: `${unreadCount} unread messages`, dir: unreadCount > 0 ? "up" : "neutral", accent: "var(--sky)" },
                    { label: "Session Rate", value: profile?.price ? fmtCurrency(Number(profile.price), profile.currency || "INR") : "—", delta: "Per session", dir: "neutral", accent: "var(--violet)" },
                  ].map((s, i) => (
                    <div key={i} className="stat-card" style={{ "--accent-c": s.accent }}>
                      <div className="stat-label">{s.label}</div>
                      <div className="stat-value" style={{ color: s.accent }}>{s.value}</div>
                      <div className={`stat-delta ${s.dir}`}>
                        {s.dir === "up" ? "▲" : s.dir === "down" ? "▼" : "—"} {s.delta}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="overview-grid">
                  <div className="overview-left">
                    {/* Earnings Chart */}
                    <div className="card card-p">
                      <div className="card-header">
                        <div>
                          <div className="card-title">Earnings Overview</div>
                          <div className="card-sub">Last 7 months</div>
                        </div>
                        <div style={{ textAlign: "right" }}>
                          <div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: 18, color: "var(--gold)" }}>{fmtCurrency(totalEarnings)}</div>
                          <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>All time</div>
                        </div>
                      </div>
                      <div className="earnings-chart">
                        {earningsData.map((d, i) => {
                          const max = Math.max(...earningsData.map(e => e.val), 1);
                          const pct = Math.max(5, (d.val / max) * 100);
                          return (
                            <div key={i} className="earnings-bar-wrap" title={`${d.label}: ${fmtCurrency(d.val)}`}>
                              <div className={`earnings-bar ${d.current ? "current" : ""}`} style={{ height: `${pct}%` }} />
                            </div>
                          );
                        })}
                      </div>
                      <div style={{ display: "flex", gap: 6 }}>
                        {earningsData.map((d, i) => (
                          <div key={i} style={{ flex: 1, textAlign: "center" }}>
                            <div className={`earnings-month ${d.current ? "current" : ""}`}>{d.label}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Recent Chats */}
                    <div className="card card-p">
                      <div className="card-header">
                        <div className="card-title">Recent Conversations</div>
                        <button className="btn btn-ghost btn-sm" onClick={() => handleNavClick(NAV.CONVERSATIONS)}>View all →</button>
                      </div>
                      {conversations.length === 0 ? (
                        <div className="empty-state">
                          <div className="empty-state-icon">◈</div>
                          <div className="empty-state-title">No conversations yet</div>
                          <div className="empty-state-desc">Clients will appear here when they reach out</div>
                        </div>
                      ) : conversations.slice(0, 5).map(c => {
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
                              {c.unread > 0 && <div className="unread-pill">{c.unread}</div>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="overview-right">
                    {/* Profile Card */}
                    <div className="card card-p">
                      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
                        <div className="avatar-btn" style={{ width: 48, height: 48, fontSize: 20, borderRadius: 12 }}>
                          {(profile?.name || expertName)[0].toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontWeight: 800, fontFamily: "var(--font-display)", fontSize: 14 }}>{profile?.name || expertName}</div>
                          <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>{profile?.field}</div>
                          <Stars rating={4.8} />
                        </div>
                      </div>
                      <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 14, lineHeight: 1.5 }}>{profile?.headline}</div>
                      <div className="progress-wrap" style={{ marginBottom: 14 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                          <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>Profile completion</span>
                          <span style={{ fontSize: 11, color: "var(--gold)", fontFamily: "var(--font-mono)" }}>78%</span>
                        </div>
                        <div className="progress-track"><div className="progress-fill" style={{ width: "78%" }} /></div>
                      </div>
                      <button className="btn btn-secondary btn-sm" style={{ width: "100%" }} onClick={() => handleNavClick(NAV.PROFILE)}>Edit Profile</button>
                    </div>

                    {/* Availability Calendar */}
                    <div className="card card-p">
                      <div className="card-header">
                        <div className="card-title">Availability</div>
                        <div className="chip green" style={{ fontSize: 10 }}>7 days</div>
                      </div>
                      <div className="cal-strip">
                        {calDays.map((d, i) => (
                          <div key={i} className={`cal-day ${d.isToday ? "today" : ""}`}>
                            <div className="cal-day-num" style={{ color: d.isToday ? "var(--gold)" : "var(--text-primary)", fontSize: 15 }}>{d.num}</div>
                            <div className="cal-day-name">{d.name}</div>
                            <div className="cal-dot" style={{ background: d.status === "available" ? "var(--emerald)" : d.isToday ? "var(--gold)" : "var(--rose)" }} />
                          </div>
                        ))}
                      </div>
                      <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--text-muted)" }}>
                          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--emerald)" }} /> Available
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--text-muted)" }}>
                          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--rose)" }} /> Busy
                        </div>
                      </div>
                    </div>

                    {/* Quick actions */}
                    <div className="card card-p">
                      <div className="card-title" style={{ marginBottom: 12 }}>Quick Actions</div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        <button className="btn btn-secondary" style={{ justifyContent: "flex-start", gap: 10 }} onClick={() => handleNavClick(NAV.AI)}>
                          <span style={{ color: "var(--violet)" }}>✦</span> Ask AI Assistant
                        </button>
                        <button className="btn btn-secondary" style={{ justifyContent: "flex-start", gap: 10 }} onClick={() => handleNavClick(NAV.CONVERSATIONS)}>
                          <span style={{ color: "var(--sky)" }}>◈</span> View All Chats {unreadCount > 0 && <span className="nav-badge">{unreadCount}</span>}
                        </button>
                        <button className="btn btn-secondary" style={{ justifyContent: "flex-start", gap: 10 }} onClick={() => handleNavClick(NAV.PAYMENTS)}>
                          <span style={{ color: "var(--gold)" }}>◉</span> Payments Ledger
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ══════════ CONVERSATIONS ══════════ */}
            {selectedNav === NAV.CONVERSATIONS && (
              <div className="fade-in">
                <div className="page-header">
                  <h1 className="page-title">Conversations</h1>
                  <p className="page-sub">{conversations.length} total · {unreadCount} unread</p>
                </div>
                <div className="chat-grid">
                  {/* List Panel */}
                  <div className="card chat-list-panel" style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
                    <div style={{ padding: "14px 14px 8px" }}>
                      <input
                        className="input-field input-search"
                        placeholder="Search conversations…"
                        value={convoSearch}
                        onChange={e => setConvoSearch(e.target.value)}
                        style={{ marginBottom: 0 }}
                      />
                    </div>
                    <div style={{ flex: 1, overflowY: "auto", padding: "6px 8px 8px" }}>
                      {filteredConvos.length === 0 ? (
                        <div className="empty-state">
                          <div className="empty-state-icon">◈</div>
                          <div className="empty-state-title">No conversations</div>
                        </div>
                      ) : filteredConvos.map(c => {
                        const other = c.otherEmail || c.room?.split("_").find(e => e !== expertEmail) || "User";
                        return (
                          <div
                            key={c.room}
                            className={`convo-item ${activeRoom === c.room ? "active" : ""}`}
                            onClick={() => openConversation(c)}
                          >
                            <div className="convo-avatar" style={{ color: activeRoom === c.room ? "var(--gold)" : undefined }}>
                              {other[0].toUpperCase()}
                            </div>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div className="convo-name">{other}</div>
                              <div className="convo-preview">{c.lastMessage || "Start conversation"}</div>
                            </div>
                            <div style={{ textAlign: "right", flexShrink: 0 }}>
                              <div className="convo-time">{formatTime(c.lastMessageTime)}</div>
                              {c.unread > 0 && <div className="unread-pill">{c.unread}</div>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Chat Window */}
                  <div className="card chat-window-panel" style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
                    {/* Chat header */}
                    <div style={{ padding: "13px 18px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 12 }}>
                      {activeRoom && (
                        <button className="btn btn-ghost btn-sm" onClick={() => { setActiveRoom(null); activeRoomRef.current = null; }}>← Back</button>
                      )}
                      {activeOther ? (
                        <>
                          <div className="convo-avatar">{activeOther[0].toUpperCase()}</div>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: 800, fontSize: 14 }}>{activeOther}</div>
                            <div style={{ fontSize: 11, color: "var(--emerald)", fontFamily: "var(--font-mono)" }}>● Live · Private Room</div>
                          </div>
                        </>
                      ) : (
                        <div style={{ color: "var(--text-muted)", fontSize: 13 }}>
                          Select a conversation to start chatting ←
                        </div>
                      )}
                    </div>

                    {/* Messages */}
                    <div className="messages-wrap">
                      {loadingMessages && (
                        <div style={{ textAlign: "center", color: "var(--gold)", fontSize: 13, padding: 10 }}>Loading messages…</div>
                      )}
                      {!loadingMessages && messages.length === 0 && activeRoom && (
                        <div className="empty-state">
                          <div className="empty-state-icon">◈</div>
                          <div className="empty-state-title">No messages yet</div>
                          <div className="empty-state-desc">Send a greeting to start the conversation</div>
                        </div>
                      )}
                      {messages.map((m, i) => {
                        const isMe = m.author === expertEmail;
                        return (
                          <div key={m._id || i} className={`msg-row ${isMe ? "sent" : "received"}`}>
                            {!isMe && <div className="msg-avatar">{(m.author || "U")[0].toUpperCase()}</div>}
                            <div>
                              <div className="msg-bubble">{m.message}</div>
                              <div className="msg-meta">
                                {isMe && <span style={{ color: "var(--gold)", fontSize: 10 }}>✓✓</span>}
                                {formatTime(m.createdAt)}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                      <div ref={messagesEndRef} />
                    </div>

                    {/* Compose */}
                    <div className="compose-bar">
                      <div className="quick-chips">
                        {["Thanks, noted!", "On a call, will reply soon.", "Could you share more details?", "Are you free for a quick call?"].map((q, i) => (
                          <button key={i} className="quick-chip" disabled={!activeRoom} onClick={() => setInputValue(p => p ? `${p} ${q}` : q)}>{q}</button>
                        ))}
                      </div>
                      <div className="compose-row">
                        <textarea
                          className="input-field chat-input"
                          style={{ flex: 1 }}
                          rows={2}
                          placeholder={activeRoom ? "Type a message… (Enter to send, Shift+Enter for newline)" : "Select a conversation first…"}
                          disabled={!activeRoom}
                          value={inputValue}
                          onChange={e => setInputValue(e.target.value)}
                          onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
                        />
                        <button className="btn btn-primary btn-send" onClick={sendMessage} disabled={!activeRoom || !inputValue.trim()}>
                          ➤
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ══════════ PAYMENTS ══════════ */}
            {selectedNav === NAV.PAYMENTS && (
              <div className="fade-in">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24, flexWrap: "wrap", gap: 12 }}>
                  <div className="page-header" style={{ marginBottom: 0 }}>
                    <h1 className="page-title">Payments Ledger</h1>
                    <p className="page-sub">{payments.length} transactions · {fmtCurrency(totalEarnings)} total earned</p>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <div className="chip gold">✓ {payments.filter(p=>p.status==="paid").length} paid</div>
                    <div className="chip rose">⏳ {payments.filter(p=>p.status==="pending"||p.status==="created").length} pending</div>
                  </div>
                </div>

                {/* Summary cards */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginBottom: 20 }}>
                  {[
                    { label: "Total Earned", val: fmtCurrency(totalEarnings), color: "var(--gold)" },
                    { label: "This Month", val: fmtCurrency(thisMonthEarnings), color: "var(--emerald)" },
                    { label: "Pending", val: fmtCurrency(payments.filter(p=>p.status!=="paid").reduce((a,b)=>a+Number(b.amount||0),0)), color: "var(--sky)" },
                  ].map((s,i)=>(
                    <div key={i} className="card card-p">
                      <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 8 }}>{s.label}</div>
                      <div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: 22, color: s.color }}>{s.val}</div>
                    </div>
                  ))}
                </div>

                <div className="card">
                  <div className="table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Client</th>
                          <th>Service</th>
                          <th>Amount</th>
                          <th>Date</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {payments.length === 0 ? (
                          <tr><td colSpan={5} style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>No payments yet</td></tr>
                        ) : payments.map(p => (
                          <tr key={p._id}>
                            <td>
                              <div style={{ fontWeight: 700, fontSize: 13 }}>{p.clientName}</div>
                              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{p.clientEmail}</div>
                            </td>
                            <td style={{ fontSize: 12, color: "var(--text-secondary)" }}>{p.notes?.purpose || "Consultation"}</td>
                            <td style={{ fontFamily: "var(--font-display)", fontWeight: 800, color: "var(--gold)" }}>{fmtCurrency(p.amount, p.currency)}</td>
                            <td style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>{formatTime(p.createdAt)}</td>
                            <td><span className={`pay-status ${p.status}`}>{p.status}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* ══════════ CLIENTS ══════════ */}
            {selectedNav === NAV.CLIENTS && (
              <div className="fade-in">
                <div className="page-header">
                  <h1 className="page-title">Client Management</h1>
                  <p className="page-sub">{Array.from(new Set(payments.map(p=>p.clientEmail).filter(Boolean))).length} unique clients</p>
                </div>

                <div className="card">
                  <div className="table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Client</th>
                          <th>Total Spend</th>
                          <th>Sessions</th>
                          <th>Last Transaction</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Array.from(new Set(payments.map(p => p.clientEmail || ""))).filter(Boolean).map(email => {
                          const clientPayments = payments.filter(p => p.clientEmail === email);
                          const total = clientPayments.reduce((a, b) => b.status === "paid" ? a + Number(b.amount||0) : a, 0);
                          const name = clientPayments[0]?.clientName || email.split("@")[0];
                          const convo = conversations.find(c => c.room?.includes(email.split("@")[0]) || c.otherEmail === email);
                          return (
                            <tr key={email}>
                              <td>
                                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                  <div className="convo-avatar" style={{ width: 32, height: 32, fontSize: 13 }}>{name[0].toUpperCase()}</div>
                                  <div>
                                    <div style={{ fontWeight: 700, fontSize: 13 }}>{name}</div>
                                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{email}</div>
                                  </div>
                                </div>
                              </td>
                              <td style={{ color: "var(--gold)", fontWeight: 700, fontFamily: "var(--font-display)" }}>{fmtCurrency(total)}</td>
                              <td style={{ color: "var(--text-secondary)" }}>{clientPayments.length}</td>
                              <td style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{formatTime(clientPayments[0]?.createdAt)}</td>
                              <td>
                                {convo ? (
                                  <button className="btn btn-secondary btn-sm" onClick={() => openConversation(convo)}>
                                    Chat →
                                  </button>
                                ) : (
                                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>No chat</span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                        {Array.from(new Set(payments.map(p=>p.clientEmail).filter(Boolean))).length === 0 && (
                          <tr><td colSpan={5} style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>No clients yet</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* ══════════ AI ══════════ */}
            {selectedNav === NAV.AI && (
              <div className="fade-in" style={{ maxWidth: 860 }}>
                <div className="page-header">
                  <h1 className="page-title">AI Assistant</h1>
                  <p className="page-sub">Powered by Gemini · Draft messages, analyze conversations, get expert tips</p>
                </div>
                <div className="chip purple" style={{ marginBottom: 20 }}>✦ Gemini API Connected</div>
                <div className="card card-p">
                  <AiPanel onAsk={askAI} response={aiResponse} loading={aiLoading} />
                </div>
              </div>
            )}

            {/* ══════════ PROFILE ══════════ */}
            {selectedNav === NAV.PROFILE && (
              <div className="fade-in" style={{ maxWidth: 780 }}>
                <div className="page-header">
                  <h1 className="page-title">Expert Profile</h1>
                  <p className="page-sub">How clients see your public profile</p>
                </div>

                <div className="profile-hero">
                  <div style={{ display: "flex", gap: 22, alignItems: "flex-start", flexWrap: "wrap" }}>
                    <div className="profile-avatar">{(profile?.name || "E")[0].toUpperCase()}</div>
                    <div style={{ flex: 1, minWidth: 200 }}>
                      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6, flexWrap: "wrap" }}>
                        <div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: "clamp(18px,3vw,22px)" }}>{profile?.name}</div>
                        <div className="chip green">✓ {profile?.status || "Approved"}</div>
                      </div>
                      <div style={{ color: "var(--text-secondary)", marginBottom: 4, fontSize: 14 }}>{profile?.headline}</div>
                      <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 14 }}>
                        {profile?.email} · {profile?.field}
                      </div>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {profile?.field && <div className="chip gold">{profile.field}</div>}
                        {profile?.price && <div className="chip sky">{fmtCurrency(Number(profile.price), profile.currency || "INR")} / session</div>}
                        <div className="chip purple">⭐ 4.8 rating</div>
                      </div>
                    </div>
                  </div>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  <div className="card card-p">
                    <div className="card-title" style={{ marginBottom: 12 }}>About / Bio</div>
                    <textarea className="input-field" rows={5} defaultValue={profile?.summary || ""} readOnly style={{ cursor: "default" }} />
                  </div>

                  <div className="card card-p">
                    <div className="card-title" style={{ marginBottom: 14 }}>Stats at a Glance</div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14 }}>
                      {[
                        { label: "Conversations", val: conversations.length, color: "var(--sky)" },
                        { label: "Total Earned", val: fmtCurrency(totalEarnings), color: "var(--gold)" },
                        { label: "Clients", val: Array.from(new Set(payments.map(p=>p.clientEmail).filter(Boolean))).length, color: "var(--emerald)" },
                      ].map((s,i) => (
                        <div key={i} style={{ textAlign: "center", padding: "16px 10px", background: "rgba(255,255,255,0.03)", borderRadius: 12, border: "1px solid var(--border)" }}>
                          <div style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: 22, color: s.color }}>{s.val}</div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: 4 }}>{s.label}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <button className="btn btn-danger btn-sm" style={{ alignSelf: "flex-start" }} onClick={logout}>
                    ⎋ Sign out of account
                  </button>
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