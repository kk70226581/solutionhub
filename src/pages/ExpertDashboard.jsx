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

const css = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@400;500&family=Cabinet+Grotesk:wght@400;500;700;800&display=swap');

  :root {
    --brand-1:#10b981; --brand-2:#14b8a6;
    --bg:#020617; --card:rgba(13,20,38,0.97);
    --border:rgba(148,163,184,0.12); --border-bright:rgba(255,255,255,0.1);
    --gold:#f59e0b; --gold-dim:rgba(245,158,11,0.10); --gold-glow:rgba(245,158,11,0.22);
    --emerald:#10b981; --rose:#fb7185; --sky:#38bdf8; --violet:#a78bfa;
    --text-primary:#f1f5f9; --text-secondary:#94a3b8; --text-muted:#475569;
    --r-sm:10px; --r-md:14px; --r-lg:18px; --r-xl:24px;
    --font-d:'Syne',sans-serif; --font-b:'Cabinet Grotesk',sans-serif; --font-m:'DM Mono',monospace;
    --sidebar-w:240px; --header-h:60px;
    --tr:0.2s cubic-bezier(0.4,0,0.2,1);
  }

  html,body { margin:0; padding:0; overflow-x:hidden; max-width:100vw; background:var(--bg); color:var(--text-primary); font-family:var(--font-b); -webkit-font-smoothing:antialiased; }
  *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
  ::-webkit-scrollbar { width:4px; height:4px; }
  ::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.08); border-radius:100px; }

  .ed-root { min-height:100vh; background:var(--bg); overflow-x:hidden; width:100%; max-width:100vw; }

  .ambient { position:fixed; inset:0; pointer-events:none; z-index:0; overflow:hidden; }
  .ab { position:absolute; border-radius:50%; filter:blur(110px); opacity:0.06; }
  .ab1 { width:500px; height:500px; background:var(--brand-1); top:-180px; left:-180px; }
  .ab2 { width:420px; height:420px; background:var(--gold); bottom:-120px; right:-120px; }
  .ab3 { width:350px; height:350px; background:var(--violet); top:45%; left:35%; }

  /* HEADER */
  .ed-header {
    position:sticky; top:0; z-index:300; height:var(--header-h);
    background:rgba(2,6,23,0.93); backdrop-filter:blur(20px) saturate(1.5);
    border-bottom:1px solid var(--border);
    display:flex; align-items:center; justify-content:space-between;
    padding:0 16px; gap:8px; width:100%; max-width:100vw;
  }
  .h-left { display:flex; align-items:center; gap:8px; flex-shrink:0; min-width:0; }
  .brand-mark { width:32px; height:32px; background:linear-gradient(135deg,var(--brand-1),var(--brand-2)); border-radius:9px; display:flex; align-items:center; justify-content:center; font-family:var(--font-d); font-weight:800; font-size:16px; color:#020617; flex-shrink:0; }
  .brand-text { font-family:var(--font-d); font-weight:800; font-size:15px; color:var(--text-primary); letter-spacing:-0.3px; white-space:nowrap; }
  .brand-sub { font-size:9px; font-family:var(--font-m); color:var(--gold); text-transform:uppercase; letter-spacing:.1em; }
  .h-center { display:flex; align-items:center; gap:7px; }
  .pill { display:inline-flex; align-items:center; gap:5px; padding:4px 10px; border-radius:100px; font-size:11px; font-family:var(--font-m); background:rgba(255,255,255,0.04); border:1px solid var(--border); color:var(--text-secondary); white-space:nowrap; }
  .pill.green { border-color:rgba(16,185,129,0.25); color:var(--emerald); }
  .pulse-dot { width:6px; height:6px; border-radius:50%; background:var(--emerald); animation:pulse 2s ease-in-out infinite; flex-shrink:0; }
  @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.75)} }
  .h-right { display:flex; align-items:center; gap:7px; flex-shrink:0; }
  .h-user { display:flex; flex-direction:column; align-items:flex-end; }
  .h-name { font-size:12px; font-weight:700; color:var(--text-primary); white-space:nowrap; }
  .h-email { font-size:10px; color:var(--text-muted); font-family:var(--font-m); white-space:nowrap; }
  .avatar-btn { width:32px; height:32px; border-radius:9px; background:linear-gradient(135deg,var(--brand-1),var(--brand-2)); border:none; cursor:pointer; font-family:var(--font-d); font-weight:800; font-size:13px; color:#020617; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
  .btn-logout { padding:5px 12px; background:transparent; border:1px solid var(--border); border-radius:8px; color:var(--text-secondary); font-size:11px; font-family:var(--font-m); cursor:pointer; white-space:nowrap; }
  .btn-logout:hover { border-color:var(--rose); color:var(--rose); }
  .menu-btn { display:none; background:transparent; border:1px solid var(--border); border-radius:8px; color:var(--text-primary); font-size:17px; cursor:pointer; width:34px; height:34px; align-items:center; justify-content:center; flex-shrink:0; }

  /* MOBILE TABS */
  .mobile-tabs { display:none; position:sticky; top:var(--header-h); z-index:200; background:rgba(2,6,23,0.95); backdrop-filter:blur(16px); border-bottom:1px solid var(--border); padding:7px 10px; gap:5px; overflow-x:auto; -webkit-overflow-scrolling:touch; scrollbar-width:none; width:100%; }
  .mobile-tabs::-webkit-scrollbar { display:none; }
  .mtab { display:inline-flex; align-items:center; gap:5px; padding:6px 11px; border-radius:8px; white-space:nowrap; font-family:var(--font-m); font-size:11px; background:rgba(255,255,255,0.04); border:1px solid var(--border); color:var(--text-secondary); cursor:pointer; flex-shrink:0; transition:all .15s; }
  .mtab.active { background:rgba(245,158,11,0.14); color:var(--gold); border-color:rgba(245,158,11,0.25); }

  /* LAYOUT */
  .ed-layout { display:grid; grid-template-columns:var(--sidebar-w) 1fr; min-height:calc(100vh - var(--header-h)); position:relative; z-index:1; width:100%; }

  /* SIDEBAR */
  .ed-sidebar { background:rgba(4,8,22,0.88); border-right:1px solid var(--border); display:flex; flex-direction:column; padding:12px 10px; position:sticky; top:var(--header-h); height:calc(100vh - var(--header-h)); overflow-y:auto; transition:transform .28s cubic-bezier(.4,0,.2,1); z-index:200; }
  .nav-lbl { font-size:9px; font-family:var(--font-m); text-transform:uppercase; letter-spacing:.12em; color:var(--text-muted); padding:4px 10px 5px; }
  .nav-item { display:flex; align-items:center; gap:9px; padding:8px 10px; border-radius:9px; cursor:pointer; transition:all .16s; font-size:13px; font-weight:500; color:var(--text-secondary); border:1px solid transparent; margin-bottom:2px; }
  .nav-item:hover { background:rgba(255,255,255,0.04); color:var(--text-primary); }
  .nav-item.active { background:rgba(245,158,11,0.1); border-color:rgba(245,158,11,0.2); color:var(--gold); }
  .nav-ico { width:28px; height:28px; display:flex; align-items:center; justify-content:center; border-radius:7px; font-size:13px; flex-shrink:0; background:rgba(255,255,255,0.04); }
  .nav-item.active .nav-ico { background:rgba(245,158,11,0.08); }
  .nav-badge { background:var(--rose); color:#fff; font-size:9px; font-family:var(--font-m); font-weight:700; padding:1px 5px; border-radius:100px; flex-shrink:0; }
  .nav-badge.gold { background:var(--gold); color:#020617; }
  .sb-div { height:1px; background:var(--border); margin:8px 0; }
  .sb-bottom { margin-top:auto; padding-top:8px; }
  .sb-profile { display:flex; gap:9px; align-items:center; padding:9px; border-radius:9px; background:rgba(255,255,255,0.03); border:1px solid var(--border); }
  .sb-av { width:30px; height:30px; border-radius:8px; background:var(--gold); display:flex; align-items:center; justify-content:center; font-weight:800; color:#020617; font-size:13px; flex-shrink:0; }
  .sb-name { font-weight:700; font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .sb-role { font-size:10px; color:var(--text-muted); }

  /* MAIN */
  .ed-main { overflow-y:auto; padding:22px 20px; height:calc(100vh - var(--header-h)); width:100%; min-width:0; overflow-x:hidden; }

  /* overlay */
  .overlay { display:none; position:fixed; inset:0; top:var(--header-h); background:rgba(0,0,0,0.6); z-index:180; backdrop-filter:blur(2px); }
  .overlay.open { display:block; }

  .fade-in { animation:fadeIn .22s ease-out; }
  @keyframes fadeIn { from{opacity:0;transform:translateY(7px)} to{opacity:1;transform:translateY(0)} }

  /* PAGE HEADER */
  .pg-title { font-family:var(--font-d); font-weight:800; font-size:clamp(17px,4vw,24px); color:var(--text-primary); }
  .pg-sub { font-size:12px; color:var(--text-secondary); margin-top:3px; }
  .pg-head { margin-bottom:18px; }

  /* CARD */
  .card { background:var(--card); border:1px solid var(--border); border-radius:var(--r-lg); width:100%; min-width:0; }
  .card:hover { border-color:var(--border-bright); }
  .cp { padding:16px; }
  .c-head { display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:13px; flex-wrap:wrap; gap:7px; }
  .c-title { font-family:var(--font-d); font-weight:700; font-size:13px; color:var(--text-primary); }
  .c-sub { font-size:10px; color:var(--text-muted); font-family:var(--font-m); margin-top:1px; }

  /* STATS GRID - 2 col default, 1 col mobile */
  .stats-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; margin-bottom:18px; }
  .stat-card { background:var(--card); border:1px solid var(--border); border-radius:var(--r-lg); padding:14px 15px; position:relative; overflow:hidden; transition:all .2s; min-width:0; }
  .stat-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:var(--sc,var(--gold)); opacity:.7; }
  .stat-label { font-size:9px; font-family:var(--font-m); text-transform:uppercase; letter-spacing:.08em; color:var(--text-muted); margin-bottom:7px; }
  .stat-value { font-family:var(--font-d); font-size:clamp(16px,3.5vw,22px); font-weight:800; color:var(--text-primary); line-height:1; word-break:break-all; overflow-wrap:anywhere; }
  .stat-delta { font-size:10px; font-family:var(--font-m); margin-top:5px; display:flex; align-items:center; gap:3px; flex-wrap:wrap; color:var(--text-muted); }
  .up { color:var(--emerald)!important; } .down { color:var(--rose)!important; } .neutral { color:var(--text-muted)!important; }

  /* OVERVIEW GRID */
  .ov-grid { display:grid; grid-template-columns:1fr 300px; gap:14px; }
  .ov-left { display:flex; flex-direction:column; gap:14px; min-width:0; }
  .ov-right { display:flex; flex-direction:column; gap:14px; min-width:0; }

  /* EARNINGS */
  .e-chart { display:flex; align-items:flex-end; gap:4px; height:68px; margin-bottom:6px; }
  .e-bar-w { flex:1; display:flex; flex-direction:column; align-items:center; gap:3px; height:100%; justify-content:flex-end; min-width:0; }
  .e-bar { width:100%; border-radius:4px 4px 0 0; background:rgba(245,158,11,0.2); min-height:4px; }
  .e-bar.cur { background:linear-gradient(180deg,var(--gold),rgba(245,158,11,.45)); }
  .e-month { font-size:8px; font-family:var(--font-m); color:var(--text-muted); text-align:center; }
  .e-month.cur { color:var(--gold); }

  /* CONVO */
  .convo-item { display:flex; gap:9px; align-items:center; padding:8px 9px; border-radius:9px; cursor:pointer; transition:background .12s; border:1px solid transparent; }
  .convo-item:hover { background:rgba(255,255,255,0.04); }
  .convo-item.active { background:rgba(245,158,11,0.07); border-color:rgba(245,158,11,0.15); }
  .c-av { width:36px; height:36px; border-radius:10px; background:linear-gradient(135deg,#1e2d40,#0d1b2a); border:1px solid var(--border-bright); display:flex; align-items:center; justify-content:center; font-family:var(--font-d); font-weight:700; font-size:13px; flex-shrink:0; color:var(--gold); }
  .c-name { font-weight:700; font-size:13px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .c-prev { font-size:11px; color:var(--text-secondary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; margin-top:1px; }
  .c-time { font-size:10px; color:var(--text-muted); font-family:var(--font-m); white-space:nowrap; flex-shrink:0; }
  .unread-pill { background:var(--gold); color:#020617; font-size:9px; font-family:var(--font-m); font-weight:700; padding:1px 5px; border-radius:100px; flex-shrink:0; margin-top:2px; }

  /* BUTTONS */
  .btn { display:inline-flex; align-items:center; justify-content:center; gap:6px; padding:7px 14px; border-radius:var(--r-sm); font-size:12.5px; font-weight:600; font-family:var(--font-b); cursor:pointer; border:none; transition:all .15s; white-space:nowrap; }
  .btn-primary { background:var(--gold); color:#020617; box-shadow:0 0 18px var(--gold-glow); }
  .btn-primary:hover { background:#fbbf24; }
  .btn-secondary { background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text-secondary); }
  .btn-secondary:hover { background:rgba(255,255,255,0.08); color:var(--text-primary); }
  .btn-ghost { background:transparent; border:1px solid var(--border); color:var(--text-muted); }
  .btn-ghost:hover { color:var(--text-secondary); }
  .btn-danger { background:rgba(251,113,133,0.1); border:1px solid rgba(251,113,133,0.2); color:var(--rose); }
  .btn-sm { padding:4px 10px; font-size:11px; }
  .btn:disabled { opacity:.35; cursor:not-allowed; }

  /* INPUT */
  .inp { width:100%; background:rgba(255,255,255,0.04); border:1px solid var(--border); border-radius:var(--r-sm); padding:9px 12px; color:var(--text-primary); font-family:var(--font-b); font-size:13px; outline:none; transition:border-color .15s; resize:vertical; min-width:0; }
  .inp::placeholder { color:var(--text-muted); }
  .inp:focus { border-color:rgba(245,158,11,0.4); background:rgba(255,255,255,0.05); }
  .inp-search { padding-left:33px; background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E"); background-repeat:no-repeat; background-position:10px center; }

  /* CHIPS */
  .chip { display:inline-flex; align-items:center; gap:4px; padding:3px 9px; border-radius:100px; font-size:10px; font-family:var(--font-m); background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text-secondary); }
  .chip.gold { background:var(--gold-dim); border-color:rgba(245,158,11,0.2); color:var(--gold); }
  .chip.green { background:rgba(16,185,129,0.1); border-color:rgba(16,185,129,0.25); color:var(--emerald); }
  .chip.purple { background:rgba(167,139,250,0.1); border-color:rgba(167,139,250,0.25); color:var(--violet); }
  .chip.rose { background:rgba(251,113,133,0.1); border-color:rgba(251,113,133,0.2); color:var(--rose); }
  .chip.sky { background:rgba(56,189,248,0.1); border-color:rgba(56,189,248,0.2); color:var(--sky); }

  /* CHAT */
  .chat-grid { display:grid; grid-template-columns:270px 1fr; gap:12px; height:calc(100vh - var(--header-h) - 130px); min-height:360px; }
  .chat-list { display:flex; flex-direction:column; overflow:hidden; }
  .chat-win { display:flex; flex-direction:column; overflow:hidden; }
  .msgs-wrap { flex:1; overflow-y:auto; padding:14px; display:flex; flex-direction:column; gap:11px; }
  .mobile-hide { }
  .msg-row { display:flex; gap:8px; align-items:flex-end; max-width:76%; }
  .msg-row.sent { flex-direction:row-reverse; margin-left:auto; }
  .msg-av { width:27px; height:27px; border-radius:7px; background:linear-gradient(135deg,#1e2d40,#0d1b2a); border:1px solid var(--border-bright); display:flex; align-items:center; justify-content:center; font-weight:700; font-size:10px; color:var(--gold); flex-shrink:0; }
  .msg-bub { padding:8px 12px; border-radius:12px; font-size:13px; line-height:1.5; max-width:100%; word-break:break-word; }
  .received .msg-bub { background:rgba(255,255,255,0.05); border:1px solid var(--border); border-bottom-left-radius:4px; }
  .sent .msg-bub { background:linear-gradient(135deg,rgba(45,32,8,.9),rgba(30,21,5,.9)); border:1px solid rgba(245,158,11,0.15); border-bottom-right-radius:4px; color:#f5e8c0; }
  .msg-meta { font-size:10px; color:var(--text-muted); font-family:var(--font-m); margin-top:3px; display:flex; align-items:center; gap:3px; }
  .sent .msg-meta { justify-content:flex-end; }

  /* COMPOSE */
  .compose { padding:10px 13px; border-top:1px solid var(--border); flex-shrink:0; }
  .q-chips { display:flex; gap:5px; flex-wrap:wrap; margin-bottom:7px; }
  .q-chip { padding:5px 9px; border-radius:100px; background:rgba(255,255,255,0.04); border:1px solid var(--border); color:var(--text-secondary); font-size:11px; cursor:pointer; transition:all .12s; }
  .q-chip:hover { border-color:rgba(245,158,11,0.3); color:var(--gold); }
  .q-chip:disabled { opacity:.3; cursor:default; }
  .c-row { display:flex; gap:7px; align-items:flex-end; }
  .chat-inp { border-radius:10px; padding:9px 12px; font-size:13px; min-height:40px; resize:none; }
  .btn-send { padding:9px 15px; border-radius:10px; min-width:48px; align-self:flex-end; }

  /* TABLE */
  .tbl-wrap { width:100%; overflow-x:auto; -webkit-overflow-scrolling:touch; }
  .data-tbl { width:100%; border-collapse:collapse; min-width:400px; }
  .data-tbl th { text-align:left; font-size:9px; font-family:var(--font-m); text-transform:uppercase; letter-spacing:.09em; color:var(--text-muted); padding:0 10px 10px; border-bottom:1px solid var(--border); white-space:nowrap; }
  .data-tbl td { padding:10px; font-size:12px; border-bottom:1px solid rgba(255,255,255,0.03); vertical-align:middle; }
  .data-tbl tr:last-child td { border-bottom:none; }
  .data-tbl tr:hover td { background:rgba(255,255,255,0.02); }

  /* MOBILE CARD LIST (replaces tables on mobile) */
  .mob-list { display:none; flex-direction:column; gap:9px; }
  .mob-card { background:var(--card); border:1px solid var(--border); border-radius:var(--r-md); padding:13px; width:100%; min-width:0; }
  .mob-row { display:flex; align-items:flex-start; justify-content:space-between; gap:8px; }
  .mob-label { font-size:9px; font-family:var(--font-m); color:var(--text-muted); text-transform:uppercase; letter-spacing:.07em; margin-bottom:2px; }
  .mob-val { font-size:12px; color:var(--text-primary); font-weight:600; word-break:break-all; overflow-wrap:anywhere; }

  /* PAY STATUS */
  .ps { padding:2px 8px; border-radius:100px; font-size:9px; font-family:var(--font-m); font-weight:600; text-transform:uppercase; display:inline-block; }
  .ps.paid { background:rgba(16,185,129,0.12); color:var(--emerald); border:1px solid rgba(16,185,129,0.25); }
  .ps.pending,.ps.created { background:rgba(245,158,11,0.09); color:var(--gold); border:1px solid rgba(245,158,11,0.18); }
  .ps.failed { background:rgba(251,113,133,0.1); color:var(--rose); border:1px solid rgba(251,113,133,0.2); }

  /* CAL */
  .cal-strip { display:flex; gap:5px; overflow-x:auto; padding-bottom:3px; }
  .cal-day { flex-shrink:0; width:42px; height:56px; border-radius:9px; background:rgba(255,255,255,0.03); border:1px solid var(--border); display:flex; flex-direction:column; align-items:center; justify-content:center; gap:2px; }
  .cal-day.today { border-color:rgba(245,158,11,0.4); background:var(--gold-dim); }
  .cal-num { font-size:14px; font-weight:700; font-family:var(--font-m); line-height:1; }
  .cal-name { font-size:8px; color:var(--text-muted); text-transform:uppercase; font-family:var(--font-m); }
  .cal-dot { width:5px; height:5px; border-radius:50%; }

  /* STARS */
  .stars { display:flex; gap:2px; }
  .star { font-size:11px; }

  /* PROGRESS */
  .prog-track { height:4px; background:rgba(255,255,255,0.06); border-radius:100px; overflow:hidden; }
  .prog-fill { height:100%; border-radius:100px; background:linear-gradient(90deg,var(--gold),#e09020); }

  /* EMPTY */
  .empty { display:flex; flex-direction:column; align-items:center; justify-content:center; gap:7px; padding:28px 14px; color:var(--text-muted); text-align:center; }
  .empty-ico { font-size:26px; opacity:.35; }
  .empty-t { font-size:13px; font-weight:600; color:var(--text-secondary); }

  /* TOASTS */
  .toast-stack { position:fixed; bottom:16px; right:14px; z-index:9999; display:flex; flex-direction:column; gap:7px; pointer-events:none; max-width:calc(100vw - 28px); }
  .toast { padding:10px 13px; border-radius:10px; font-size:12px; display:flex; align-items:center; gap:8px; min-width:180px; backdrop-filter:blur(20px); animation:toastIn .22s cubic-bezier(.34,1.56,.64,1); border:1px solid var(--border-bright); color:#fff; word-break:break-word; }
  @keyframes toastIn { from{opacity:0;transform:translateX(12px) scale(.94)} to{opacity:1;transform:translateX(0) scale(1)} }
  .toast.success { background:rgba(16,185,129,0.18); border-color:rgba(16,185,129,0.35); }
  .toast.error { background:rgba(251,113,133,0.18); border-color:rgba(251,113,133,0.35); }
  .toast.info { background:rgba(56,189,248,0.15); border-color:rgba(56,189,248,0.3); }

  /* AI */
  .ai-sugg { display:grid; grid-template-columns:repeat(3,1fr); gap:7px; margin-bottom:14px; }
  .ai-sugg-btn { padding:9px 10px; border-radius:9px; background:rgba(167,139,250,0.07); border:1px solid rgba(167,139,250,0.15); color:var(--text-secondary); font-size:11.5px; line-height:1.4; text-align:left; cursor:pointer; transition:all .15s; font-family:var(--font-b); }
  .ai-sugg-btn:hover { background:rgba(167,139,250,0.12); color:var(--text-primary); }
  .ai-bubble { padding:13px; background:linear-gradient(135deg,rgba(167,139,250,0.07),rgba(56,189,248,0.04)); border:1px solid rgba(167,139,250,0.18); border-radius:10px; font-size:13px; line-height:1.75; white-space:pre-wrap; color:var(--text-primary); }

  /* PROFILE */
  .p-hero { background:linear-gradient(135deg,rgba(245,158,11,0.05),rgba(8,11,18,0)); border:1px solid var(--border); border-radius:var(--r-xl); padding:20px; margin-bottom:14px; width:100%; min-width:0; }
  .p-av { width:68px; height:68px; border-radius:16px; background:linear-gradient(135deg,var(--gold),#c0850a); display:flex; align-items:center; justify-content:center; font-family:var(--font-d); font-weight:800; font-size:26px; color:#020617; flex-shrink:0; }

  /* SUMMARY ROW */
  .sum-row { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-bottom:16px; }
  .sum-card { background:var(--card); border:1px solid var(--border); border-radius:var(--r-md); padding:13px; min-width:0; }
  .sum-label { font-size:9px; font-family:var(--font-m); color:var(--text-muted); text-transform:uppercase; margin-bottom:6px; }
  .sum-val { font-family:var(--font-d); font-weight:800; font-size:clamp(14px,3vw,19px); word-break:break-all; overflow-wrap:anywhere; }

  /* TYPING */
  .typing { display:flex; gap:4px; padding:8px 12px; background:rgba(255,255,255,0.04); border-radius:11px; width:fit-content; }
  .t-dot { width:5px; height:5px; border-radius:50%; background:var(--text-muted); animation:tp 1.4s ease-in-out infinite; }
  .t-dot:nth-child(2){animation-delay:.2s} .t-dot:nth-child(3){animation-delay:.4s}
  @keyframes tp{0%,80%,100%{transform:scale(.7);opacity:.5}40%{transform:scale(1);opacity:1}}

  /* QUICK ACTIONS */
  .qa-list { display:flex; flex-direction:column; gap:7px; }

  /* ============================
     RESPONSIVE BREAKPOINTS
  ============================ */

  /* Tablet: collapse right col */
  @media (max-width:1080px) {
    .ov-grid { grid-template-columns:1fr; }
    .ov-right { display:grid; grid-template-columns:repeat(2,1fr); gap:13px; }
    .stats-grid { grid-template-columns:repeat(2,1fr); }
  }

  /* Tablet: sidebar icon only */
  @media (max-width:900px) {
    :root { --sidebar-w:60px; }
    .nav-lbl, .nav-item span:not(.nav-ico), .nav-badge, .sb-bottom { display:none; }
    .nav-item { justify-content:center; padding:8px; }
  }

  /* Mobile: drawer sidebar + mobile tabs */
  @media (max-width:768px) {
    :root { --sidebar-w:0px; --header-h:56px; }
    .ed-layout { grid-template-columns:1fr; }
    .ed-sidebar { display:none !important; }
    .menu-btn { display:none !important; }
    .overlay, .overlay.open { display:none !important; }
    .h-center { display:none; }
    .h-user { display:none; }
    .btn-logout { display:none; }
    .mobile-tabs { display:flex; top:var(--header-h); }
    /* main fills full width, auto height for natural scroll */
    .ed-main { padding:13px 11px; height:auto; min-height:calc(100vh - var(--header-h) - 44px); overflow-x:hidden; }
    /* stats: 2 col on medium mobile */
    .stats-grid { grid-template-columns:repeat(2,1fr); gap:9px; }
    /* overview stacked */
    .ov-grid { grid-template-columns:1fr; gap:12px; }
    .ov-right { grid-template-columns:1fr; gap:12px; }
    /* chat stacked */
    .chat-grid { grid-template-columns:1fr; height:auto; display:flex; flex-direction:column; gap:10px; }
    .chat-list { max-height:35vh; min-height:160px; }
    .chat-win { min-height:300px; display:flex; flex-direction:column; }
    .msgs-wrap { flex:1; min-height:200px; }
    .msg-row { max-width:90%; }
    /* payments/clients: hide table show cards */
    .desktop-tbl { display:none !important; }
    .mob-list { display:flex; }
    /* summary row stack */
    .sum-row { grid-template-columns:1fr; gap:8px; }
    /* ai suggestions */
    .ai-sugg { grid-template-columns:repeat(2,1fr); gap:6px; }
    /* profile hero */
    .p-hero { padding:15px; }
    .p-hero-inner { flex-direction:column !important; align-items:flex-start !important; }
    .mobile-hide { display:none !important; }
    .ed-header { padding:0 10px; }
    .brand-sub { display:none; }
    .pg-head { margin-bottom:14px; }
    .card { border-radius:14px; }
    .btn { min-height:36px; }
    .msgs-wrap { padding:12px 10px; }
    .compose { padding:9px 10px; }
  }

  /* Small mobile */
  @media (max-width:480px) {
    .stats-grid { grid-template-columns:1fr; gap:8px; }
    .sum-row { grid-template-columns:1fr; gap:8px; }
    .ai-sugg { grid-template-columns:1fr; gap:6px; }
    .ov-right { grid-template-columns:1fr; }
    .ed-main { padding:10px 9px; }
    .cp { padding:13px 12px; }
    .p-hero { padding:13px; }
    .brand-text { display:none; }
    .e-chart { height:56px; }
    .msg-row { max-width:95%; }
    .chat-list { max-height:28vh; }
    .stats-grid .stat-value { font-size:18px; }
    .mtab { padding:6px 10px; }
    .ed-header { gap:6px; }
    .avatar-btn { width:30px; height:30px; border-radius:8px; font-size:12px; }
    .pg-sub { font-size:11px; }
    .mob-row { flex-direction:column; align-items:flex-start; }
    .mob-card .btn { width:100%; }
    /* profile stats 3 col -> 1 col */
    .p-stats-grid { grid-template-columns:1fr !important; }
  }

  @media (max-width:360px) {
    .ed-main { padding:8px 7px; }
    .cp { padding:11px 10px; }
    .mtab { padding:5px 8px; font-size:10px; }
  }
`;

/* utils */
const formatTime = (ts) => {
  if (!ts) return "";
  try {
    const d = new Date(ts), now = new Date(), diff = now - d;
    if (diff < 60000) return "Just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    if (diff < 604800000) return d.toLocaleDateString("en-IN", { weekday: "short" });
    return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short" });
  } catch { return ""; }
};

const fmtCur = (n, currency = "INR") => {
  if (n == null || n === "") return "—";
  const v = Number(n);
  if (Number.isNaN(v)) return "—";
  try { return new Intl.NumberFormat("en-IN", { style: "currency", currency, maximumFractionDigits: 0 }).format(v); }
  catch { return `${currency} ${v}`; }
};

const Stars = ({ rating = 4.5 }) => (
  <div className="stars">
    {[1,2,3,4,5].map(i => (
      <span key={i} className="star" style={{ color: i <= Math.floor(rating) ? "var(--gold)" : "var(--text-muted)" }}>★</span>
    ))}
  </div>
);

/* AI Panel */
const AiPanel = ({ onAsk, response, loading }) => {
  const [prompt, setPrompt] = useState("");
  const suggestions = ["Summarize my last 5 conversations","Draft a professional follow-up","Handle an unresponsive client","Improve client retention","Write my profile intro","Questions to ask new clients"];
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:13 }}>
      <div className="ai-sugg">
        {suggestions.map((s,i) => <button key={i} className="ai-sugg-btn" onClick={() => setPrompt(s)}>{s}</button>)}
      </div>
      <textarea className="inp" rows={4} placeholder="Ask anything: draft messages, summarize chats, get tips…" value={prompt} onChange={e => setPrompt(e.target.value)} onKeyDown={e => { if (e.key==="Enter"&&e.ctrlKey&&prompt.trim()) onAsk(prompt); }} style={{ marginBottom:8 }}/>
      <div style={{ display:"flex", gap:7, alignItems:"center", flexWrap:"wrap" }}>
        <button className="btn btn-primary" onClick={() => { if(prompt.trim()) onAsk(prompt); }} disabled={loading||!prompt.trim()}>{loading?"⟳ Thinking…":"✦ Ask AI"}</button>
        <button className="btn btn-ghost btn-sm" onClick={() => setPrompt("")}>Clear</button>
        {prompt.trim() && <span style={{ fontSize:10, color:"var(--text-muted)", fontFamily:"var(--font-m)" }}>Ctrl+Enter</span>}
      </div>
      {(response||loading) && (
        <div>
          <div style={{ fontSize:9, fontFamily:"var(--font-m)", color:"var(--text-muted)", marginBottom:7, textTransform:"uppercase", letterSpacing:".1em" }}>✦ AI Response</div>
          <div className="ai-bubble">{loading ? <div style={{ display:"flex", alignItems:"center", gap:10, color:"var(--text-muted)" }}><div className="typing"><div className="t-dot"/><div className="t-dot"/><div className="t-dot"/></div>Generating…</div> : response}</div>
        </div>
      )}
    </div>
  );
};

/* MAIN */
const ExpertDashboard = () => {
  const navigate = useNavigate();
  const token = localStorage.getItem("token");
  const storedRole = localStorage.getItem("role");
  const expertEmail = localStorage.getItem("email");
  const expertName = localStorage.getItem("name") || "Expert";

  useEffect(() => {
    if (!token || !expertEmail || storedRole !== "expert") navigate("/login", { replace:true });
  }, [token, expertEmail, storedRole, navigate]);

  const NAV = { DASHBOARD:"dashboard", CONVERSATIONS:"conversations", CLIENTS:"clients", PAYMENTS:"payments", AI:"ai", PROFILE:"profile" };

  const [sel, setSel] = useState(NAV.DASHBOARD);
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
  const [loadingMsgs, setLoadingMsgs] = useState(false);
  const [convoSearch, setConvoSearch] = useState("");
  const [aiResp, setAiResp] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [toasts, setToasts] = useState([]);
  const socketRef = useRef(null);
  const msgsEndRef = useRef(null);

  const showToast = useCallback((text, type="info", ms=3000) => {
    const id = Date.now();
    setToasts(p => [...p, { id, text, type }]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), ms);
  }, []);

  useEffect(() => { document.body.style.overflow = sidebarOpen ? "hidden":""; return () => { document.body.style.overflow=""; }; }, [sidebarOpen]);

  useEffect(() => {
    if (!token) return;
    const load = async () => {
      try {
        const h = { Authorization:`Bearer ${token}` };
        const [pR,cR,pmR] = await Promise.all([
          fetch(`${API}/api/profile?email=${expertEmail}`,{headers:h}),
          fetch(`${API}/api/conversations?email=${expertEmail}`,{headers:h}),
          fetch(`${API}/api/my-payments`,{headers:h}),
        ]);
        const [pD,cD,pmD] = await Promise.all([pR.json(),cR.json(),pmR.json()]);
        if (!pD.error) setProfile(pD);
        if (Array.isArray(cD)) setConversations(cD);
        if (Array.isArray(pmD)) setPayments(pmD);
      } catch { showToast("Error loading data","error"); }
      finally { setLoadingApp(false); }
    };
    load();
  }, [expertEmail, token, showToast]);

  useEffect(() => {
    if (!API||!token) return;
    const s = io(API,{ auth:{token}, transports:["websocket"] });
    socketRef.current = s;
    s.on("connect",()=>s.emit("authenticate",{token}));
    s.on("online_users",(map)=>setOnlineCount(map?Object.keys(map).length:0));
    s.on("receive_message",(msg)=>{
      if (!msg?.room) return;
      if (msg.room===activeRoomRef.current) {
        setMessages(p=>[...p,msg]);
        setTimeout(()=>msgsEndRef.current?.scrollIntoView({behavior:"smooth"}),80);
      }
      setConversations(p=>{
        const ex=p.find(c=>c.room===msg.room);
        if (ex) return p.map(c=>c.room===msg.room?{...c,lastMessage:msg.message,lastMessageTime:msg.createdAt,unread:(c.unread||0)+(msg.room!==activeRoomRef.current?1:0)}:c);
        return [{room:msg.room,lastMessage:msg.message,lastMessageTime:msg.createdAt,otherEmail:msg.author,unread:1},...p];
      });
    });
    return ()=>{ try{s.disconnect();}catch{} };
  }, [API, token]);

  const openConvo = useCallback(async (c) => {
    if (!c?.room) return;
    const other = c.otherEmail||c.room.split("_").find(e=>e!==expertEmail)||"User";
    setActiveRoom(c.room); activeRoomRef.current=c.room;
    setActiveOther(other); setMessages([]); setLoadingMsgs(true);
    setSel(NAV.CONVERSATIONS); setSidebarOpen(false);
    try {
      const r = await fetch(`${API}/api/messages?room=${encodeURIComponent(c.room)}`,{headers:{Authorization:`Bearer ${token}`}});
      if (r.ok) { const h=await r.json(); setMessages(h); setTimeout(()=>msgsEndRef.current?.scrollIntoView({behavior:"instant"}),50); }
    } catch { showToast("Failed to load messages","error"); }
    finally { setLoadingMsgs(false); }
    setTimeout(()=>{ try{socketRef.current?.emit("join_private",c.room);}catch{} },45);
    setConversations(p=>p.map(x=>x.room===c.room?{...x,unread:0}:x));
  }, [expertEmail, token, showToast, NAV.CONVERSATIONS]);

  useEffect(()=>{ msgsEndRef.current?.scrollIntoView({behavior:"smooth"}); },[messages]);

  const sendMsg = useCallback(async ()=>{
    const room=activeRoomRef.current||activeRoom;
    if (!room||!inputValue.trim()) return;
    const text=inputValue.trim(); setInputValue("");
    const opt={_id:Date.now().toString(),room,author:expertEmail,message:text,createdAt:new Date().toISOString()};
    setMessages(p=>[...p,opt]);
    setTimeout(()=>msgsEndRef.current?.scrollIntoView({behavior:"smooth"}),50);
    if (socketRef.current?.connected) socketRef.current.emit("send_private_message",{room,author:expertEmail,authorRole:"expert",message:text});
    try{fetch(`${API}/api/messages`,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${token}`},body:JSON.stringify({room,author:expertEmail,message:text})}).catch(()=>{});}catch{}
  },[inputValue,expertEmail,activeRoom,token]);

  const askAI = useCallback(async (prompt)=>{
    setAiLoading(true); setAiResp("");
    try {
      const r=await fetch(`${API}/api/ai/ask`,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${token}`},body:JSON.stringify({prompt})});
      const d=await r.json(); setAiResp(d?.answer||"No response received.");
    } catch { setAiResp("AI service error."); }
    setAiLoading(false);
  },[token]);

  const logout=()=>{ ["token","email","name","role"].forEach(k=>localStorage.removeItem(k)); navigate("/login"); };
  const goTo=(id)=>{ setSel(id); setSidebarOpen(false); if(id!==NAV.CONVERSATIONS){setActiveRoom(null);activeRoomRef.current=null;} };

  const unread = useMemo(()=>conversations.reduce((a,c)=>a+(c.unread||0),0),[conversations]);

  const earningsData = useMemo(()=>{
    const months=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const cur=new Date().getMonth();
    const chart=[];
    for(let i=6;i>=0;i--){const d=new Date();d.setMonth(cur-i);chart.push({label:months[d.getMonth()],val:0,cur:i===0,mNum:d.getMonth(),yr:d.getFullYear()});}
    payments.forEach(p=>{
      const amt=Number(p?.amount||0);
      if(p?.status==="paid"&&!Number.isNaN(amt)&&p?.createdAt){const d=new Date(p.createdAt);const m=chart.find(c=>c.mNum===d.getMonth()&&c.yr===d.getFullYear());if(m)m.val+=amt;}
    });
    return chart;
  },[payments]);

  const totalEarnings=useMemo(()=>payments.reduce((a,b)=>{const v=Number(b?.amount||0);return b?.status==="paid"&&!Number.isNaN(v)?a+v:a;},0),[payments]);
  const thisMonth=earningsData[earningsData.length-1]?.val||0;
  const pendingAmt=payments.filter(p=>p.status!=="paid").reduce((a,b)=>a+Number(b.amount||0),0);

  const calDays=useMemo(()=>{
    const dns=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    return Array.from({length:7},(_,i)=>{const d=new Date();d.setDate(d.getDate()+i);return{num:d.getDate(),name:dns[d.getDay()],isToday:i===0,status:i%3===0?"available":"busy"};});
  },[]);

  const filteredConvos=useMemo(()=>{
    if(!convoSearch.trim()) return conversations;
    const q=convoSearch.toLowerCase();
    return conversations.filter(c=>(c.otherEmail||c.room||"").toLowerCase().includes(q)||(c.lastMessage||"").toLowerCase().includes(q));
  },[conversations,convoSearch]);

  const uniqueClients=useMemo(()=>Array.from(new Set(payments.map(p=>p.clientEmail||"").filter(Boolean))),[payments]);

  const navItems=[
    {id:NAV.DASHBOARD,label:"Overview",icon:"⬡"},
    {id:NAV.CONVERSATIONS,label:"Chats",icon:"◈",badge:unread>0?`${unread}`:null},
    {id:NAV.CLIENTS,label:"Clients",icon:"◉"},
    {id:NAV.PAYMENTS,label:"Payments",icon:"◇"},
    {id:NAV.AI,label:"AI",icon:"✦",badgeColor:"gold"},
    {id:NAV.PROFILE,label:"Profile",icon:"◎"},
  ];

  useEffect(()=>{
    const fn=(e)=>{if(e.key==="Escape")setSidebarOpen(false);};
    window.addEventListener("keydown",fn);
    return()=>window.removeEventListener("keydown",fn);
  },[]);

  const displayName=profile?.name||expertName;

  if(loadingApp) return (
    <div style={{background:"var(--bg)",height:"100vh",display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column",gap:12,fontFamily:"var(--font-d)",color:"var(--gold)"}}>
      <div style={{fontSize:30}}>⬡</div>
      <div style={{fontSize:14,fontWeight:700}}>Loading workspace…</div>
    </div>
  );

  return (
    <>
      <style>{css}</style>
      <div className="ed-root">

        <div className="ambient" aria-hidden>
          <div className="ab ab1"/><div className="ab ab2"/><div className="ab ab3"/>
        </div>

        <div className="toast-stack" aria-live="polite">
          {toasts.map(t=>(
            <div key={t.id} className={`toast ${t.type}`}>
              <span>{t.type==="success"?"✓":t.type==="error"?"✕":"i"}</span><span>{t.text}</span>
            </div>
          ))}
        </div>

        <div className={`overlay ${sidebarOpen?"open":""}`} onClick={()=>setSidebarOpen(false)} aria-hidden/>

        {/* HEADER */}
        <header className="ed-header">
          <div className="h-left">
            <button className="menu-btn" onClick={()=>setSidebarOpen(s=>!s)} aria-label="Toggle menu">{sidebarOpen?"✕":"☰"}</button>
            <div style={{display:"flex",alignItems:"center",gap:8,cursor:"pointer"}} onClick={()=>goTo(NAV.DASHBOARD)}>
              <div className="brand-mark">S</div>
              <div>
                <div className="brand-text">SolutionHub</div>
                <div className="brand-sub">Expert Console</div>
              </div>
            </div>
          </div>
          <div className="h-center">
            <div className="pill"><div className="pulse-dot"/>{onlineCount} online</div>
            <div className="pill green">✓ Approved</div>
          </div>
          <div className="h-right">
            <div className="h-user">
              <div className="h-name">{displayName}</div>
              <div className="h-email">{expertEmail}</div>
            </div>
            <div className="avatar-btn" title={displayName}>{displayName[0].toUpperCase()}</div>
            <button className="btn-logout" onClick={logout}>Sign out</button>
          </div>
        </header>

        {/* MOBILE TABS */}
        <nav className="mobile-tabs" aria-label="Mobile navigation">
          {navItems.map(item=>(
            <button key={item.id} className={`mtab ${sel===item.id?"active":""}`} onClick={()=>goTo(item.id)}>
              <span>{item.icon}</span><span>{item.label}</span>
              {item.badge&&<span style={{background:"var(--rose)",color:"#fff",borderRadius:100,padding:"1px 4px",fontSize:8,fontFamily:"var(--font-m)"}}>{item.badge}</span>}
            </button>
          ))}
        </nav>

        <div className="ed-layout">

          {/* SIDEBAR */}
          <aside className={`ed-sidebar ${sidebarOpen?"open":""}`}>
            <nav>
              <div className="nav-lbl">Main</div>
              {navItems.slice(0,4).map(item=>(
                <div key={item.id} className={`nav-item ${sel===item.id?"active":""}`} onClick={()=>goTo(item.id)} role="button" tabIndex={0}>
                  <div className="nav-ico">{item.icon}</div>
                  <span style={{flex:1}}>{item.label}</span>
                  {item.badge&&<span className={`nav-badge ${item.badgeColor||""}`}>{item.badge}</span>}
                </div>
              ))}
              <div className="sb-div"/>
              <div className="nav-lbl">Tools</div>
              {navItems.slice(4).map(item=>(
                <div key={item.id} className={`nav-item ${sel===item.id?"active":""}`} onClick={()=>goTo(item.id)} role="button" tabIndex={0}>
                  <div className="nav-ico">{item.icon}</div>
                  <span style={{flex:1}}>{item.label}</span>
                </div>
              ))}
              <div className="sb-div"/>
              <div className="nav-item" onClick={logout} role="button" tabIndex={0} style={{color:"var(--rose)"}}>
                <div className="nav-ico">⎋</div>
                <span>Sign out</span>
              </div>
            </nav>
            <div className="sb-bottom">
              <div className="sb-profile">
                <div className="sb-av">{displayName[0].toUpperCase()}</div>
                <div style={{minWidth:0}}>
                  <div className="sb-name">{displayName}</div>
                  <div className="sb-role">{profile?.field||"Expert"}</div>
                </div>
              </div>
            </div>
          </aside>

          {/* MAIN */}
          <main className="ed-main">

            {/* OVERVIEW */}
            {sel===NAV.DASHBOARD&&(
              <div className="fade-in">
                <div className="pg-head">
                  <div className="pg-title">Good morning, {displayName.split(" ")[0]} ☀️</div>
                  <div className="pg-sub">Here's your workspace overview</div>
                </div>

                <div className="stats-grid">
                  {[
                    {label:"Total Revenue",val:fmtCur(totalEarnings),delta:`${payments.filter(p=>p.status==="paid").length} paid tx`,dir:"up",sc:"var(--gold)"},
                    {label:"This Month",val:fmtCur(thisMonth),delta:"Current cycle",dir:"neutral",sc:"var(--emerald)"},
                    {label:"Active Chats",val:conversations.length,delta:`${unread} unread`,dir:unread>0?"up":"neutral",sc:"var(--sky)"},
                    {label:"Session Rate",val:profile?.price?fmtCur(Number(profile.price),profile.currency||"INR"):"—",delta:"Per session",dir:"neutral",sc:"var(--violet)"},
                  ].map((s,i)=>(
                    <div key={i} className="stat-card" style={{"--sc":s.sc}}>
                      <div className="stat-label">{s.label}</div>
                      <div className="stat-value" style={{color:s.sc}}>{s.val}</div>
                      <div className={`stat-delta ${s.dir}`}>{s.dir==="up"?"▲":"—"} {s.delta}</div>
                    </div>
                  ))}
                </div>

                <div className="ov-grid">
                  <div className="ov-left">
                    {/* Earnings */}
                    <div className="card cp">
                      <div className="c-head">
                        <div><div className="c-title">Earnings Overview</div><div className="c-sub">Last 7 months</div></div>
                        <div style={{textAlign:"right"}}>
                          <div style={{fontFamily:"var(--font-d)",fontWeight:800,fontSize:"clamp(14px,3vw,18px)",color:"var(--gold)"}}>{fmtCur(totalEarnings)}</div>
                          <div style={{fontSize:9,color:"var(--text-muted)",fontFamily:"var(--font-m)"}}>All time</div>
                        </div>
                      </div>
                      <div className="e-chart">
                        {earningsData.map((d,i)=>{
                          const max=Math.max(...earningsData.map(e=>e.val),1);
                          return <div key={i} className="e-bar-w" title={`${d.label}: ${fmtCur(d.val)}`}><div className={`e-bar ${d.cur?"cur":""}`} style={{height:`${Math.max(5,(d.val/max)*100)}%`}}/></div>;
                        })}
                      </div>
                      <div style={{display:"flex",gap:4}}>
                        {earningsData.map((d,i)=><div key={i} style={{flex:1,textAlign:"center"}}><div className={`e-month ${d.cur?"cur":""}`}>{d.label}</div></div>)}
                      </div>
                    </div>

                    {/* Recent chats */}
                    <div className="card cp">
                      <div className="c-head">
                        <div className="c-title">Recent Conversations</div>
                        <button className="btn btn-ghost btn-sm" onClick={()=>goTo(NAV.CONVERSATIONS)}>View all →</button>
                      </div>
                      {conversations.length===0
                        ?<div className="empty"><div className="empty-ico">◈</div><div className="empty-t">No conversations yet</div></div>
                        :conversations.slice(0,5).map(c=>{
                          const other=c.otherEmail||c.room?.split("_").find(e=>e!==expertEmail)||"User";
                          return(
                            <div key={c.room} className="convo-item" onClick={()=>openConvo(c)}>
                              <div className="c-av">{other[0].toUpperCase()}</div>
                              <div style={{flex:1,minWidth:0}}>
                                <div className="c-name">{other}</div>
                                <div className="c-prev">{c.lastMessage||"—"}</div>
                              </div>
                              <div style={{textAlign:"right",flexShrink:0}}>
                                <div className="c-time">{formatTime(c.lastMessageTime)}</div>
                                {c.unread>0&&<div className="unread-pill">{c.unread}</div>}
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  </div>

                  <div className="ov-right">
                    {/* Profile card */}
                    <div className="card cp">
                      <div style={{display:"flex",gap:10,alignItems:"center",marginBottom:10}}>
                        <div className="avatar-btn" style={{width:44,height:44,fontSize:17,borderRadius:11,flexShrink:0}}>{displayName[0].toUpperCase()}</div>
                        <div style={{minWidth:0}}>
                          <div style={{fontWeight:800,fontFamily:"var(--font-d)",fontSize:13,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{displayName}</div>
                          <div style={{fontSize:11,color:"var(--text-secondary)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{profile?.field}</div>
                          <Stars rating={4.8}/>
                        </div>
                      </div>
                      {profile?.headline&&<div style={{fontSize:11,color:"var(--text-secondary)",marginBottom:11,lineHeight:1.5,wordBreak:"break-word"}}>{profile.headline}</div>}
                      <div style={{marginBottom:11}}>
                        <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                          <span style={{fontSize:9,color:"var(--text-muted)",fontFamily:"var(--font-m)"}}>Profile completion</span>
                          <span style={{fontSize:9,color:"var(--gold)",fontFamily:"var(--font-m)"}}>78%</span>
                        </div>
                        <div className="prog-track"><div className="prog-fill" style={{width:"78%"}}/></div>
                      </div>
                      <button className="btn btn-secondary btn-sm" style={{width:"100%"}} onClick={()=>goTo(NAV.PROFILE)}>Edit Profile</button>
                    </div>

                    {/* Availability */}
                    <div className="card cp">
                      <div className="c-head">
                        <div className="c-title">Availability</div>
                        <div className="chip green" style={{fontSize:9}}>7 days</div>
                      </div>
                      <div className="cal-strip">
                        {calDays.map((d,i)=>(
                          <div key={i} className={`cal-day ${d.isToday?"today":""}`}>
                            <div className="cal-num" style={{color:d.isToday?"var(--gold)":"var(--text-primary)"}}>{d.num}</div>
                            <div className="cal-name">{d.name}</div>
                            <div className="cal-dot" style={{background:d.isToday?"var(--gold)":d.status==="available"?"var(--emerald)":"var(--rose)"}}/>
                          </div>
                        ))}
                      </div>
                      <div style={{display:"flex",gap:10,marginTop:9}}>
                        {[["var(--emerald)","Available"],["var(--rose)","Busy"]].map(([c,l],i)=>(
                          <div key={i} style={{display:"flex",alignItems:"center",gap:4,fontSize:10,color:"var(--text-muted)"}}>
                            <div style={{width:5,height:5,borderRadius:"50%",background:c,flexShrink:0}}/>{l}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Quick actions */}
                    <div className="card cp">
                      <div className="c-title" style={{marginBottom:10}}>Quick Actions</div>
                      <div className="qa-list">
                        {[
                          {icon:"✦",c:"var(--violet)",label:"Ask AI Assistant",nav:NAV.AI},
                          {icon:"◈",c:"var(--sky)",label:`Chats${unread>0?` (${unread})`:""}`,nav:NAV.CONVERSATIONS},
                          {icon:"◇",c:"var(--gold)",label:"Payments Ledger",nav:NAV.PAYMENTS},
                        ].map((a,i)=>(
                          <button key={i} className="btn btn-secondary" style={{justifyContent:"flex-start",gap:8,width:"100%"}} onClick={()=>goTo(a.nav)}>
                            <span style={{color:a.c}}>{a.icon}</span>{a.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* CONVERSATIONS */}
            {sel===NAV.CONVERSATIONS&&(
              <div className="fade-in">
                <div className="pg-head">
                  <div className="pg-title">Conversations</div>
                  <div className="pg-sub">{conversations.length} total · {unread} unread</div>
                </div>
                <div className="chat-grid">
                  <div className={`card chat-list ${activeRoom ? "mobile-hide" : ""}`}>
                    <div style={{padding:"12px 12px 7px"}}>
                      <input className="inp inp-search" placeholder="Search…" value={convoSearch} onChange={e=>setConvoSearch(e.target.value)}/>
                    </div>
                    <div style={{flex:1,overflowY:"auto",padding:"4px 8px 8px"}}>
                      {filteredConvos.length===0
                        ?<div className="empty"><div className="empty-ico">◈</div><div className="empty-t">No conversations</div></div>
                        :filteredConvos.map(c=>{
                          const other=c.otherEmail||c.room?.split("_").find(e=>e!==expertEmail)||"User";
                          return(
                            <div key={c.room} className={`convo-item ${activeRoom===c.room?"active":""}`} onClick={()=>openConvo(c)}>
                              <div className="c-av" style={{color:activeRoom===c.room?"var(--gold)":undefined}}>{other[0].toUpperCase()}</div>
                              <div style={{flex:1,minWidth:0}}>
                                <div className="c-name">{other}</div>
                                <div className="c-prev">{c.lastMessage||"Start conversation"}</div>
                              </div>
                              <div style={{textAlign:"right",flexShrink:0}}>
                                <div className="c-time">{formatTime(c.lastMessageTime)}</div>
                                {c.unread>0&&<div className="unread-pill">{c.unread}</div>}
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  </div>

                  <div className={`card chat-win ${!activeRoom ? "mobile-hide" : ""}`}>
                    <div style={{padding:"11px 14px",borderBottom:"1px solid var(--border)",display:"flex",alignItems:"center",gap:9,flexShrink:0}}>
                      {activeRoom&&<button className="btn btn-ghost btn-sm" onClick={()=>{setActiveRoom(null);activeRoomRef.current=null;}}>← Back</button>}
                      {activeOther
                        ?<><div className="c-av">{activeOther[0].toUpperCase()}</div><div style={{minWidth:0}}><div style={{fontWeight:800,fontSize:13,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{activeOther}</div><div style={{fontSize:10,color:"var(--emerald)",fontFamily:"var(--font-m)"}}>● Live · Private</div></div></>
                        :<div style={{fontSize:12,color:"var(--text-muted)"}}>Select a conversation ←</div>}
                    </div>
                    <div className="msgs-wrap">
                      {loadingMsgs&&<div style={{textAlign:"center",color:"var(--gold)",fontSize:12,padding:10}}>Loading…</div>}
                      {!loadingMsgs&&messages.length===0&&activeRoom&&<div className="empty"><div className="empty-ico">◈</div><div className="empty-t">No messages yet</div></div>}
                      {messages.map((m,i)=>{
                        const isMe=m.author===expertEmail;
                        return(
                          <div key={m._id||i} className={`msg-row ${isMe?"sent":"received"}`}>
                            {!isMe&&<div className="msg-av">{(m.author||"U")[0].toUpperCase()}</div>}
                            <div>
                              <div className="msg-bub">{m.message}</div>
                              <div className="msg-meta">{isMe&&<span style={{color:"var(--gold)",fontSize:9}}>✓✓</span>}{formatTime(m.createdAt)}</div>
                            </div>
                          </div>
                        );
                      })}
                      <div ref={msgsEndRef}/>
                    </div>
                    <div className="compose">
                      <div className="q-chips">
                        {["Thanks, noted!","Will reply soon","More details?","Quick call?"].map((q,i)=>(
                          <button key={i} className="q-chip" disabled={!activeRoom} onClick={()=>setInputValue(p=>p?`${p} ${q}`:q)}>{q}</button>
                        ))}
                      </div>
                      <div className="c-row">
                        <textarea className="inp chat-inp" style={{flex:1}} rows={2} placeholder={activeRoom?"Type a message… (Enter to send)":"Select a conversation first…"} disabled={!activeRoom} value={inputValue} onChange={e=>setInputValue(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendMsg();}}}/>
                        <button className="btn btn-primary btn-send" onClick={sendMsg} disabled={!activeRoom||!inputValue.trim()}>➤</button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* PAYMENTS */}
            {sel===NAV.PAYMENTS&&(
              <div className="fade-in">
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:16,flexWrap:"wrap",gap:9}}>
                  <div className="pg-head" style={{marginBottom:0}}>
                    <div className="pg-title">Payments Ledger</div>
                    <div className="pg-sub">{payments.length} transactions</div>
                  </div>
                  <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                    <div className="chip gold">✓ {payments.filter(p=>p.status==="paid").length} paid</div>
                    <div className="chip rose">⏳ {payments.filter(p=>p.status==="pending"||p.status==="created").length} pending</div>
                  </div>
                </div>

                <div className="sum-row">
                  {[
                    {l:"Total Earned",v:fmtCur(totalEarnings),c:"var(--gold)"},
                    {l:"This Month",v:fmtCur(thisMonth),c:"var(--emerald)"},
                    {l:"Pending",v:fmtCur(pendingAmt),c:"var(--sky)"},
                  ].map((s,i)=>(
                    <div key={i} className="sum-card">
                      <div className="sum-label">{s.l}</div>
                      <div className="sum-val" style={{color:s.c}}>{s.v}</div>
                    </div>
                  ))}
                </div>

                {/* Desktop table */}
                <div className="card desktop-tbl">
                  <div className="tbl-wrap">
                    <table className="data-tbl">
                      <thead><tr><th>Client</th><th>Service</th><th>Amount</th><th>Date</th><th>Status</th></tr></thead>
                      <tbody>
                        {payments.length===0
                          ?<tr><td colSpan={5} style={{textAlign:"center",padding:28,color:"var(--text-muted)"}}>No payments yet</td></tr>
                          :payments.map(p=>(
                            <tr key={p._id}>
                              <td>
                                <div style={{fontWeight:700,fontSize:12}}>{p.clientName}</div>
                                <div style={{fontSize:10,color:"var(--text-muted)",fontFamily:"var(--font-m)"}}>{p.clientEmail}</div>
                              </td>
                              <td style={{fontSize:11,color:"var(--text-secondary)"}}>{p.notes?.purpose||"Consultation"}</td>
                              <td style={{fontFamily:"var(--font-d)",fontWeight:800,color:"var(--gold)"}}>{fmtCur(p.amount,p.currency)}</td>
                              <td style={{fontFamily:"var(--font-m)",fontSize:11,color:"var(--text-muted)"}}>{formatTime(p.createdAt)}</td>
                              <td><span className={`ps ${p.status}`}>{p.status}</span></td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Mobile cards */}
                <div className="mob-list">
                  {payments.length===0
                    ?<div className="empty"><div className="empty-ico">◇</div><div className="empty-t">No payments yet</div></div>
                    :payments.map(p=>(
                      <div key={p._id} className="mob-card">
                        <div className="mob-row" style={{marginBottom:10}}>
                          <div style={{minWidth:0}}>
                            <div style={{fontWeight:700,fontSize:13,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.clientName||"Client"}</div>
                            <div style={{fontSize:10,color:"var(--text-muted)",fontFamily:"var(--font-m)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.clientEmail}</div>
                          </div>
                          <span className={`ps ${p.status}`} style={{flexShrink:0}}>{p.status}</span>
                        </div>
                        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                          <div><div className="mob-label">Amount</div><div className="mob-val" style={{color:"var(--gold)",fontFamily:"var(--font-d)",fontWeight:800}}>{fmtCur(p.amount,p.currency)}</div></div>
                          <div><div className="mob-label">Date</div><div className="mob-val" style={{fontSize:11,color:"var(--text-secondary)"}}>{formatTime(p.createdAt)}</div></div>
                          <div style={{gridColumn:"1/-1"}}><div className="mob-label">Service</div><div className="mob-val" style={{fontSize:11,color:"var(--text-secondary)"}}>{p.notes?.purpose||"Consultation"}</div></div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* CLIENTS */}
            {sel===NAV.CLIENTS&&(
              <div className="fade-in">
                <div className="pg-head">
                  <div className="pg-title">Client Management</div>
                  <div className="pg-sub">{uniqueClients.length} unique clients</div>
                </div>

                {/* Desktop table */}
                <div className="card desktop-tbl">
                  <div className="tbl-wrap">
                    <table className="data-tbl">
                      <thead><tr><th>Client</th><th>Total Spend</th><th>Sessions</th><th>Last Tx</th><th>Action</th></tr></thead>
                      <tbody>
                        {uniqueClients.length===0
                          ?<tr><td colSpan={5} style={{textAlign:"center",padding:36,color:"var(--text-muted)"}}>No clients yet</td></tr>
                          :uniqueClients.map(email=>{
                            const cps=payments.filter(p=>p.clientEmail===email);
                            const total=cps.reduce((a,b)=>b.status==="paid"?a+Number(b.amount||0):a,0);
                            const name=cps[0]?.clientName||email.split("@")[0];
                            const convo=conversations.find(c=>c.room?.includes(email.split("@")[0])||c.otherEmail===email);
                            return(
                              <tr key={email}>
                                <td>
                                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                                    <div className="c-av" style={{width:28,height:28,fontSize:11}}>{name[0].toUpperCase()}</div>
                                    <div>
                                      <div style={{fontWeight:700,fontSize:12}}>{name}</div>
                                      <div style={{fontSize:10,color:"var(--text-muted)",fontFamily:"var(--font-m)"}}>{email}</div>
                                    </div>
                                  </div>
                                </td>
                                <td style={{fontFamily:"var(--font-d)",fontWeight:800,color:"var(--gold)"}}>{fmtCur(total)}</td>
                                <td style={{color:"var(--text-secondary)"}}>{cps.length}</td>
                                <td style={{fontSize:11,color:"var(--text-muted)",fontFamily:"var(--font-m)"}}>{formatTime(cps[0]?.createdAt)}</td>
                                <td>{convo?<button className="btn btn-secondary btn-sm" onClick={()=>openConvo(convo)}>Chat →</button>:<span style={{fontSize:11,color:"var(--text-muted)"}}>—</span>}</td>
                              </tr>
                            );
                          })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Mobile cards */}
                <div className="mob-list">
                  {uniqueClients.length===0
                    ?<div className="empty"><div className="empty-ico">◉</div><div className="empty-t">No clients yet</div></div>
                    :uniqueClients.map(email=>{
                      const cps=payments.filter(p=>p.clientEmail===email);
                      const total=cps.reduce((a,b)=>b.status==="paid"?a+Number(b.amount||0):a,0);
                      const name=cps[0]?.clientName||email.split("@")[0];
                      const convo=conversations.find(c=>c.room?.includes(email.split("@")[0])||c.otherEmail===email);
                      return(
                        <div key={email} className="mob-card">
                          <div className="mob-row" style={{marginBottom:10}}>
                            <div style={{display:"flex",alignItems:"center",gap:9,minWidth:0}}>
                              <div className="c-av" style={{width:34,height:34,fontSize:12,flexShrink:0}}>{name[0].toUpperCase()}</div>
                              <div style={{minWidth:0}}>
                                <div style={{fontWeight:700,fontSize:13,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{name}</div>
                                <div style={{fontSize:10,color:"var(--text-muted)",fontFamily:"var(--font-m)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{email}</div>
                              </div>
                            </div>
                            {convo&&<button className="btn btn-secondary btn-sm" style={{flexShrink:0}} onClick={()=>openConvo(convo)}>Chat →</button>}
                          </div>
                          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                            <div><div className="mob-label">Total Spend</div><div className="mob-val" style={{color:"var(--gold)",fontFamily:"var(--font-d)",fontWeight:800}}>{fmtCur(total)}</div></div>
                            <div><div className="mob-label">Sessions</div><div className="mob-val">{cps.length}</div></div>
                            <div style={{gridColumn:"1/-1"}}><div className="mob-label">Last Transaction</div><div className="mob-val" style={{fontSize:11,color:"var(--text-secondary)"}}>{formatTime(cps[0]?.createdAt)||"—"}</div></div>
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}

            {/* AI */}
            {sel===NAV.AI&&(
              <div className="fade-in" style={{maxWidth:820,width:"100%"}}>
                <div className="pg-head">
                  <div className="pg-title">AI Assistant</div>
                  <div className="pg-sub">Draft messages, analyze conversations, get expert tips</div>
                </div>
                <div className="chip purple" style={{marginBottom:14}}>✦ Gemini API Connected</div>
                <div className="card cp"><AiPanel onAsk={askAI} response={aiResp} loading={aiLoading}/></div>
              </div>
            )}

            {/* PROFILE */}
            {sel===NAV.PROFILE&&(
              <div className="fade-in" style={{maxWidth:740,width:"100%"}}>
                <div className="pg-head">
                  <div className="pg-title">Expert Profile</div>
                  <div className="pg-sub">How clients see you</div>
                </div>

                <div className="p-hero">
                  <div className="p-hero-inner" style={{display:"flex",gap:16,alignItems:"flex-start",flexWrap:"wrap"}}>
                    <div className="p-av">{(profile?.name||"E")[0].toUpperCase()}</div>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:"flex",gap:7,alignItems:"center",marginBottom:5,flexWrap:"wrap"}}>
                        <div style={{fontFamily:"var(--font-d)",fontWeight:800,fontSize:"clamp(15px,3vw,20px)",wordBreak:"break-word"}}>{profile?.name}</div>
                        <div className="chip green">✓ {profile?.status||"Approved"}</div>
                      </div>
                      <div style={{color:"var(--text-secondary)",marginBottom:4,fontSize:13,wordBreak:"break-word"}}>{profile?.headline}</div>
                      <div style={{fontSize:11,color:"var(--text-muted)",fontFamily:"var(--font-m)",marginBottom:11,wordBreak:"break-all"}}>{profile?.email} · {profile?.field}</div>
                      <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                        {profile?.field&&<div className="chip gold">{profile.field}</div>}
                        {profile?.price&&<div className="chip sky">{fmtCur(Number(profile.price),profile.currency||"INR")} / session</div>}
                        <div className="chip purple">⭐ 4.8</div>
                      </div>
                    </div>
                  </div>
                </div>

                <div style={{display:"flex",flexDirection:"column",gap:12}}>
                  <div className="card cp">
                    <div className="c-title" style={{marginBottom:10}}>About / Bio</div>
                    <textarea className="inp" rows={5} defaultValue={profile?.summary||""} readOnly style={{cursor:"default"}}/>
                  </div>

                  <div className="card cp">
                    <div className="c-title" style={{marginBottom:12}}>Stats at a Glance</div>
                    <div className="p-stats-grid" style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
                      {[
                        {l:"Conversations",v:conversations.length,c:"var(--sky)"},
                        {l:"Total Earned",v:fmtCur(totalEarnings),c:"var(--gold)"},
                        {l:"Clients",v:uniqueClients.length,c:"var(--emerald)"},
                      ].map((s,i)=>(
                        <div key={i} style={{textAlign:"center",padding:"13px 8px",background:"rgba(255,255,255,0.03)",borderRadius:11,border:"1px solid var(--border)",minWidth:0}}>
                          <div style={{fontFamily:"var(--font-d)",fontWeight:800,fontSize:"clamp(14px,3vw,19px)",color:s.c,wordBreak:"break-all"}}>{s.v}</div>
                          <div style={{fontSize:9,color:"var(--text-muted)",fontFamily:"var(--font-m)",marginTop:3}}>{s.l}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <button className="btn btn-danger btn-sm" style={{alignSelf:"flex-start"}} onClick={logout}>⎋ Sign out</button>
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
