// src/pages/ClientChat.jsx
import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import io from 'socket.io-client';
import '../styles/ClientChat.css';

const ClientChat = () => {
  const navigate = useNavigate();
  const location = useLocation();

  // ===== URL & AUTH STATE =====
  const searchParams = new URLSearchParams(location.search);
  const expertEmailFromQuery = searchParams.get('email');

  // if you navigated with state from Experts.jsx:
  const locationState = location.state || {};
  const expertEmail = locationState.expertEmail || expertEmailFromQuery;

  const clientEmail =
    typeof window !== 'undefined' ? localStorage.getItem('email') : null;
  const clientName =
    (typeof window !== 'undefined' &&
      (localStorage.getItem('name') ||
        localStorage.getItem('username') ||
        (clientEmail ? clientEmail.split('@')[0] : 'User'))) ||
    'User';
  const token =
    typeof window !== 'undefined' ? localStorage.getItem('token') : null;

  // ===== STATE =====
  const [expert, setExpert] = useState({
    name: 'Expert',
    field: 'General expert',
    experience: 0,
    email: '---',
    avatar: '',
  });

  const [roomId, setRoomId] = useState(null);
  const [socketInstance, setSocketInstance] = useState(null);
  const [messages, setMessages] = useState([]); // {author, message, createdAt, _id?}
  const [loadingMessages, setLoadingMessages] = useState(true);
  const [inputValue, setInputValue] = useState('');
  const [typingVisible, setTypingVisible] = useState(false);
  const [toast, setToast] = useState({ visible: false, text: '', error: false });

  const displayedMessageIdsRef = useRef(new Set());
  const typingTimeoutRef = useRef(null);
  const isTypingRef = useRef(false);
  const chatMessagesRef = useRef(null);

  // ===== AUTH GUARD =====
  useEffect(() => {
    if (!token || !clientEmail) {
      window.alert('Please login to chat with an expert');
      navigate('/login', { replace: true });
    }
  }, [token, clientEmail, navigate]);

  // ===== UTILITIES =====
  const escapeHtml = text => {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  };

  const formatTime = ts => {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleTimeString('en-IN', {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const scrollToBottom = () => {
    const container = chatMessagesRef.current;
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  };

  const showToast = (msg, isError = false) => {
    setToast({ visible: true, text: msg, error: isError });
    setTimeout(() => {
      setToast(prev => ({ ...prev, visible: false }));
    }, 2600);
  };

  // ===== LOAD EXPERT =====
  const loadExpert = useCallback(async () => {
    if (!expertEmail) {
      window.alert('No expert selected');
      navigate('/experts', { replace: true });
      return;
    }
    try {
      const res = await fetch(
        `/api/profile?email=${encodeURIComponent(expertEmail)}`,
      );
      if (!res.ok) throw new Error('profile_fetch_failed');
      const data = await res.json();

      setExpert({
        name: data.name || 'Expert',
        field: data.field || 'General expert',
        experience: data.experience || 0,
        email: data.email || '---',
        avatar: data.avatar || '',
      });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Error loading expert', err);
      window.alert('Failed to load expert details');
      navigate('/experts', { replace: true });
    }
  }, [expertEmail, navigate]);

  // ===== LOAD CHAT HISTORY =====
  const loadChatHistory = useCallback(async rid => {
    setLoadingMessages(true);
    try {
      const res = await fetch(
        `/api/messages?room=${encodeURIComponent(rid)}`,
      );
      if (!res.ok) throw new Error('history_fetch_failed');
      const msgs = await res.json();
      const setIds = new Set();
      (msgs || []).forEach(m => {
        const id =
          (m._id || '') + '|' + (m.createdAt || '') + '|' + (m.message || '');
        if (id) setIds.add(id);
      });
      displayedMessageIdsRef.current = setIds;
      setMessages(msgs || []);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Error loading history', err);
      setMessages([
        {
          author: 'system',
          message:
            'Could not load previous messages. You can still start a new chat below.',
          createdAt: new Date().toISOString(),
          _id: 'system-load-failed',
          isError: true,
        },
      ]);
    } finally {
      setLoadingMessages(false);
      setTimeout(scrollToBottom, 50);
    }
  }, []);

  // ===== SOCKET SETUP =====
  useEffect(() => {
    if (!expertEmail || !clientEmail) return;

    const rid = [clientEmail, expertEmail].sort().join('_');
    setRoomId(rid);

    const s = io(); // same-origin socket.io server

    s.on('connect', () => {
      s.emit('join_private', rid);
      s.emit('user_online', {
        email: clientEmail,
        name: clientName,
        role: 'client',
      });
    });

    s.on('receive_message', data => {
      // ignore echo of own message
      if (data.author === clientEmail) return;

      const id =
        (data._id || '') +
        '|' +
        (data.createdAt || '') +
        '|' +
        (data.message || '');
      if (id && displayedMessageIdsRef.current.has(id)) return;
      if (id) displayedMessageIdsRef.current.add(id);

      setMessages(prev => [...prev, data]);
      setTimeout(scrollToBottom, 20);
    });

    s.on('user_typing', data => {
      if (data.room === rid && data.author !== clientEmail) {
        setTypingVisible(true);
      }
    });

    s.on('user_stopped_typing', data => {
      if (data.room === rid) {
        setTypingVisible(false);
      }
    });

    s.on('connect_error', err => {
      // eslint-disable-next-line no-console
      console.error('Socket error', err);
    });

    s.on('disconnect', () => {
      // eslint-disable-next-line no-console
      console.log('Socket disconnected');
    });

    setSocketInstance(s);
    loadChatHistory(rid);

    return () => {
      s.disconnect();
    };
  }, [expertEmail, clientEmail, clientName, loadChatHistory]);

  // ===== SEND MESSAGE =====
  const handleSend = () => {
    if (!socketInstance || !roomId) return;
    const trimmed = inputValue.trim();
    if (!trimmed) return;

    const localMsg = {
      author: clientEmail,
      message: trimmed,
      createdAt: new Date().toISOString(),
    };

    // Add locally
    setMessages(prev => [...prev, localMsg]);
    setTimeout(scrollToBottom, 20);

    const payload = {
      room: roomId,
      author: clientEmail,
      authorRole: 'client',
      message: trimmed,
    };

    socketInstance.emit('send_private_message', payload);
    socketInstance.emit('stop_typing', { room: roomId });

    setInputValue('');
  };

  const handleKeyPress = e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSend();
    }
  };

  // ===== TYPING =====
  const handleTyping = () => {
    if (!socketInstance || !roomId) return;
    if (!isTypingRef.current) {
      isTypingRef.current = true;
      socketInstance.emit('typing', {
        room: roomId,
        name: clientName,
        author: clientEmail,
      });
    }
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    typingTimeoutRef.current = setTimeout(() => {
      isTypingRef.current = false;
      socketInstance.emit('stop_typing', { room: roomId });
    }, 900);
  };

  // ===== EFFECT: LOAD EXPERT ON MOUNT =====
  useEffect(() => {
    loadExpert();
  }, [loadExpert]);

  // ===== RENDER =====
  const avatarInitial =
    (expert.name || 'E').trim()[0]?.toUpperCase() || 'E';
  const expertAvatarSrc = expert.avatar
    ? expert.avatar.includes('uploads')
      ? `/${expert.avatar}`
      : `/uploads/photos/${expert.avatar}`
    : null;

  return (
    <div className="client-chat-page">
      {/* Toast */}
      {toast.visible && (
        <div className={`toast ${toast.error ? 'error' : ''}`}>
          {toast.text}
        </div>
      )}

      {/* HEADER */}
      <header>
        <div className="shell header-inner">
          <div
            className="brand-row"
            onClick={() => navigate('/experts')}
          >
            <div className="brand-logo">S</div>
            <div>
              <div className="brand-text">
                Solution<span>Hub</span>
              </div>
              <div className="chat-sub">
                Live 1‑to‑1 with verified experts
              </div>
            </div>
          </div>

          <div className="header-meta">
            <div className="pill online-dot">
              <span className="dot" />
              <span>Secure private room</span>
            </div>
          </div>

          <div className="header-actions">
            <div className="user-tag">
              <div className="user-avatar-small">
                {clientName[0]?.toUpperCase() || 'U'}
              </div>
              <span>{clientName}</span>
            </div>
            <button
              className="back-btn"
              onClick={() => navigate('/experts')}
            >
              <i className="fa-solid fa-arrow-left" />
              Back
            </button>
          </div>
        </div>
      </header>

      {/* MAIN */}
      <main>
        <div className="shell">
          <div className="chat-layout">
            {/* Expert sidebar */}
            <aside className="expert-card">
              <div className="expert-avatar-wrap">
                {expertAvatarSrc ? (
                  <img
                    src={expertAvatarSrc}
                    alt={expert.name || 'Expert'}
                    className="expert-avatar"
                    onError={e => {
                      e.target.style.display = 'none';
                      const sib = e.target.nextElementSibling;
                      if (sib) sib.style.display = 'flex';
                    }}
                  />
                ) : null}
                <div
                  className="avatar-fallback"
                  style={{
                    display: expertAvatarSrc ? 'none' : 'flex',
                  }}
                >
                  {avatarInitial}
                </div>
              </div>

              <div className="expert-name">{expert.name}</div>
              <div className="expert-field">
                {expert.field || 'Expert'}
              </div>

              <div className="expert-info">
                <div className="info-row">
                  <i className="fa-solid fa-briefcase" />
                  <span>
                    <span>{expert.experience}</span>+ years
                    experience
                  </span>
                </div>
                <div className="info-row">
                  <i className="fa-solid fa-envelope" />
                  <span style={{ fontSize: 11 }}>
                    {expert.email}
                  </span>
                </div>
                <div className="info-row">
                  <i
                    className="fa-solid fa-circle-check"
                    style={{ color: 'var(--success)' }}
                  />
                  <span>Verified SolutionHub expert</span>
                </div>
              </div>

              <div className="launch-box">
                <strong>Launch offer</strong>
                <span>
                  Free or discounted sessions while the
                  network is in early access.
                </span>
              </div>
            </aside>

            {/* Chat section */}
            <section className="chat-section">
              <div className="chat-header">
                <div>
                  <div className="chat-title">
                    <i className="fa-solid fa-comments" />
                    <span>Live chat</span>
                  </div>
                  <div className="chat-sub">
                    Ask, clarify, share screenshots (by
                    link), and get direct guidance.
                  </div>
                </div>
                <div className="chat-status">
                  <div className="status-dot" />
                  <span>Connected</span>
                </div>
              </div>

              <div className="chat-box">
                <div
                  className="chat-messages"
                  ref={chatMessagesRef}
                >
                  {loadingMessages ? (
                    <div className="loading-messages">
                      <i className="fa-solid fa-spinner fa-spin" />
                      Loading previous messages…
                    </div>
                  ) : messages.length === 0 ? (
                    <div className="empty-state">
                      <i className="fa-solid fa-comments" />
                      <h4 style={{ marginBottom: 4 }}>
                        Start the conversation
                      </h4>
                      <p>
                        Send your first message to this
                        expert.
                      </p>
                    </div>
                  ) : (
                    <>
                      {messages.map((msg, idx) => {
                        if (msg.author === 'system') {
                          return (
                            <div
                              key={msg._id || idx}
                              className="empty-state"
                            >
                              <i className="fa-solid fa-triangle-exclamation" />
                              <h4
                                style={{
                                  marginBottom: 4,
                                }}
                              >
                                Could not load messages
                              </h4>
                              <p>
                                You can still start a new
                                chat below.
                              </p>
                            </div>
                          );
                        }

                        const isMe =
                          msg.author === clientEmail;
                        const senderName = isMe
                          ? 'You'
                          : expert.name || 'Expert';

                        return (
                          <div
                            key={msg._id || idx}
                            className={
                              'message ' + (isMe ? 'me' : 'other')
                            }
                          >
                            <div className="message-sender">
                              {senderName}
                            </div>
                            <div
                              dangerouslySetInnerHTML={{
                                __html: escapeHtml(
                                  msg.message || '',
                                ),
                              }}
                            />
                            <div className="message-time">
                              {formatTime(msg.createdAt)}
                            </div>
                          </div>
                        );
                      })}
                      {typingVisible && (
                        <div
                          id="typingIndicator"
                          className="typing-indicator"
                        >
                          <div className="typing-dot" />
                          <div className="typing-dot" />
                          <div className="typing-dot" />
                        </div>
                      )}
                    </>
                  )}
                </div>

                <div className="chat-input-area">
                  <input
                    type="text"
                    placeholder="Type your message and press Enter…"
                    value={inputValue}
                    onChange={e =>
                      setInputValue(e.target.value)
                    }
                    onKeyDown={handleKeyPress}
                    onInput={handleTyping}
                  />
                  <button
                    className="send-btn"
                    onClick={handleSend}
                    disabled={!inputValue.trim()}
                  >
                    <i className="fa-solid fa-paper-plane" />
                    Send
                  </button>
                </div>
              </div>
            </section>
          </div>
        </div>
      </main>

      {/* FOOTER */}
      <footer>
        <div className="footer-row">
          <span>
            © 2026 SolutionHub. Human experts + smart tools, for
            real‑world problems.
          </span>
          <span>
            <i
              className="fa-solid fa-shield-halved"
              style={{
                marginRight: 4,
                color: 'var(--success)',
              }}
            />
            Private, encrypted room between you and your expert.
          </span>
        </div>
      </footer>
    </div>
  );
};

export default ClientChat;
