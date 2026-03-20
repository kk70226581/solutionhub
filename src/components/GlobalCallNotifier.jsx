import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import io from 'socket.io-client';
import { Phone, PhoneOff } from 'lucide-react';
import '../styles/GlobalCallNotifier.css';
import {
  getStoredIncomingCall,
  setStoredIncomingCall,
} from '../utils/incomingCallStorage';

const API = import.meta.env.VITE_API_BASE || 'https://solutionhub66.onrender.com';

export default function GlobalCallNotifier() {
  const navigate = useNavigate();
  const location = useLocation();
  const [incomingCall, setIncomingCall] = useState(() => getStoredIncomingCall());
  const conversationsRef = useRef([]);
  const socketRef = useRef(null);

  const token = typeof window !== 'undefined' ? localStorage.getItem('token') : '';
  const email = typeof window !== 'undefined' ? localStorage.getItem('email') : '';
  const role = typeof window !== 'undefined' ? String(localStorage.getItem('role') || '').toLowerCase() : '';

  const setCall = useCallback((call) => {
    setIncomingCall(call);
    setStoredIncomingCall(call);
  }, []);

  useEffect(() => {
    if (!token || !email || !['client', 'expert'].includes(role)) return undefined;

    let cancelled = false;
    const joinKnownRooms = () => {
      if (!socketRef.current) return;
      conversationsRef.current.forEach((conversation) => {
        if (conversation?.room) {
          socketRef.current.emit('join-room', { room: conversation.room });
        }
      });
    };

    const loadConversations = async () => {
      try {
        const res = await fetch(`${API}/api/conversations?email=${encodeURIComponent(email)}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json().catch(() => []);
        if (!cancelled) {
          conversationsRef.current = Array.isArray(data) ? data : [];
          joinKnownRooms();
        }
      } catch {
        if (!cancelled) conversationsRef.current = [];
      }
    };

    loadConversations();
    return () => { cancelled = true; };
  }, [token, email, role, location.pathname]);

  useEffect(() => {
    if (!token || !email || !['client', 'expert'].includes(role)) return undefined;

    const socket = io(API, { auth: { token }, transports: ['websocket'] });
    socketRef.current = socket;

    const joinKnownRooms = () => {
      conversationsRef.current.forEach((conversation) => {
        if (conversation?.room) {
          socket.emit('join-room', { room: conversation.room });
        }
      });
    };

    socket.on('connect', () => socket.emit('authenticate', { token }));
    socket.on('auth_success', joinKnownRooms);
    socket.on('offer', ({ room, offer, from }) => {
      if (!room || !offer || String(from || '').toLowerCase() === String(email || '').toLowerCase()) return;
      const match = conversationsRef.current.find((conversation) => conversation.room === room);
      setCall({
        room,
        offer,
        from: from || 'Caller',
        otherEmail: match?.otherEmail || from || '',
        at: Date.now(),
      });
    });
    socket.on('call-ended', ({ room }) => {
      setIncomingCall((prev) => {
        const next = prev?.room === room ? null : prev;
        setStoredIncomingCall(next);
        return next;
      });
    });

    return () => {
      socketRef.current = null;
      try {
        socket.disconnect();
      } catch {
        // ignore disconnect failures
      }
    };
  }, [token, email, role, setCall]);

  const dismissCall = useCallback(() => {
    setCall(null);
  }, [setCall]);

  const openCall = useCallback(() => {
    if (!incomingCall) return;
    if (role === 'expert') {
      navigate('/expert-dashboard', { state: { openIncomingCall: true } });
      return;
    }

    const targetEmail = incomingCall.otherEmail || incomingCall.from || '';
    navigate(`/chat?email=${encodeURIComponent(targetEmail)}`, {
      state: { expertEmail: targetEmail, openIncomingCall: true },
    });
  }, [incomingCall, navigate, role]);

  if (!incomingCall || !token || !email || !['client', 'expert'].includes(role)) return null;

  return (
    <div className="gcn-popup" role="dialog" aria-live="assertive" aria-label="Incoming call">
      <div className="gcn-kicker">Incoming Call</div>
      <div className="gcn-title">{incomingCall.from} is calling</div>
      <div className="gcn-subtitle">Open the private room to answer the call.</div>
      <div className="gcn-actions">
        <button type="button" className="gcn-btn gcn-btn-primary" onClick={openCall}>
          <Phone size={15} />
          Open
        </button>
        <button type="button" className="gcn-btn gcn-btn-ghost" onClick={dismissCall}>
          <PhoneOff size={15} />
          Dismiss
        </button>
      </div>
    </div>
  );
}
