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
import "../styles/ExpertDashboard.css";

// ✅ Base API / socket origin, e.g. VITE_API_BASE=https://solutionhub66.onrender.com
const API = import.meta.env.VITE_API_BASE;

const ExpertDashboard = () => {
  const navigate = useNavigate();

  const token =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;
  const expertEmail =
    typeof window !== "undefined" ? localStorage.getItem("email") : null;
  const expertName =
    typeof window !== "undefined"
      ? localStorage.getItem("name") ||
        (expertEmail && expertEmail.split("@")[0])
      : "Expert";

  useEffect(() => {
    if (!token || !expertEmail) {
      alert("Please login as an expert to access the dashboard");
      navigate("/login", { replace: true });
    }
  }, [token, expertEmail, navigate]);

  const [conversations, setConversations] = useState([]);
  const [activeRoom, setActiveRoom] = useState(null);
  const [activeOther, setActiveOther] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState("");
  const [loadingConvos, setLoadingConvos] = useState(true);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [typingVisible, setTypingVisible] = useState(false);
  const [search, setSearch] = useState("");
  const [toast, setToast] = useState({
    visible: false,
    text: "",
    type: "info",
  });
  const [onlineUsers, setOnlineUsers] = useState(0);
  const [stats, setStats] = useState({ totalConvos: 0, unread: 0, today: 0 });
  const [quickReplies] = useState([
    "Thanks for reaching out! How can I help?",
    "Let me check that for you...",
    "That's a great question! Let me explain...",
    "I'll get back to you shortly with details.",
    "Perfect! Let me confirm that for you.",
  ]);

  const socketRef = useRef(null);
  const displayedMessageIdsRef = useRef(new Set());
  const typingTimeoutRef = useRef(null);
  const isTypingRef = useRef(false);
  const messagesContainerRef = useRef(null);
  const conversationsEndRef = useRef(null);

  const showToast = (text, type = "info") => {
    setToast({ visible: true, text, type });
    setTimeout(
      () => setToast({ visible: false, text: "", type: "info" }),
      3200
    );
  };

  const scrollToBottom = useCallback(() => {
    const c = messagesContainerRef.current;
    if (c) {
      c.scrollTo({ top: c.scrollHeight, behavior: "smooth" });
    }
  }, []);

  const scrollConvosToBottom = useCallback(() => {
    const c = conversationsEndRef.current;
    if (c) {
      c.scrollIntoView({ behavior: "smooth" });
    }
  }, []);

  const formatTime = (ts) => {
    if (!ts) return "";
    try {
      const d = new Date(ts);
      const now = new Date();
      const diff = now - d;
      if (diff < 60 * 1000) return "Just now";
      if (diff < 60 * 60 * 1000) return `${Math.floor(diff / 60000)}m ago`;
      if (diff < 24 * 60 * 60 * 1000) return `${Math.floor(diff / 3600000)}h ago`;
      return d.toLocaleTimeString("en-IN", {
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return "";
    }
  };

  // ✅ conversations via `${API}/api/...`
  const loadConversations = useCallback(async () => {
    if (!expertEmail || !API) return;
    setLoadingConvos(true);
    try {
      const res = await fetch(
        `${API}/api/conversations?email=${encodeURIComponent(expertEmail)}`,
        {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        }
      );
      if (!res.ok) throw new Error("Could not fetch conversations");
      const data = await res.json();
      const convos = Array.isArray(data) ? data : [];

      const todayStr = new Date().toDateString();
      const statsData = {
        totalConvos: convos.length,
        unread: convos.filter((c) => c.unread > 0).length,
        today: convos.filter(
          (c) =>
            c.lastMessageTime &&
            new Date(c.lastMessageTime).toDateString() === todayStr
        ).length,
      };
      setStats(statsData);
      setConversations(convos);
      scrollConvosToBottom();
    } catch (err) {
      console.error("Convos load error", err);
      showToast("Failed to load conversations", "error");
    } finally {
      setLoadingConvos(false);
    }
  }, [expertEmail, token, scrollConvosToBottom]);

  // ✅ socket.io to backend origin
  useEffect(() => {
    if (!expertEmail || !API) return;

    const s = io(API, {
      auth: { token },
      transports: ["websocket"],
    });
    socketRef.current = s;

    const handleOnlineCount = (count) => {
      setOnlineUsers(count || 0);
    };

    const handleChatHistory = (history) => {
      const arr = Array.isArray(history) ? history : [];
      const setIds = new Set();
      arr.forEach((m) => {
        const id =
          (m._id || "") + "|" + (m.createdAt || "") + "|" + (m.message || "");
        if (id) setIds.add(id);
      });
      displayedMessageIdsRef.current = setIds;
      setMessages(arr);
      setLoadingMessages(false);
      setTimeout(scrollToBottom, 80);
    };

    const handleReceiveMessage = (msg) => {
      // IGNORE your own messages here – you already added them optimistically
      if (msg.author === expertEmail) return;

      const id =
        (msg._id || "") + "|" + (msg.createdAt || "") + "|" + (msg.message || "");
      if (id && displayedMessageIdsRef.current.has(id)) return;
      if (id) displayedMessageIdsRef.current.add(id);

      setMessages((prev) => [...prev, msg]);
      setTimeout(scrollToBottom, 50);
    };

    const handleNewNotification = ({ room, message, unreadCount }) => {
      setConversations((prev) => {
        const existing = prev.find((c) => c.room === room);
        const others = prev.filter((c) => c.room !== room);
        const newEntry = {
          ...(existing || {}),
          room,
          lastMessage: message?.message,
          lastMessageTime: message?.createdAt,
          unread: unreadCount ?? (existing?.unread || 0) + 1,
          otherEmail:
            existing?.otherEmail ||
            room.split("_").find((e) => e !== expertEmail),
        };
        return [newEntry, ...others];
      });
    };

    const handleTypingEvent = (data) => {
      if (data?.room === activeRoom && data.author !== expertEmail) {
        setTypingVisible(true);
        if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
        typingTimeoutRef.current = setTimeout(() => {
          setTypingVisible(false);
        }, 1500);
      }
    };

    const handleStopTypingEvent = (data) => {
      if (data?.room === activeRoom) setTypingVisible(false);
    };

    s.on("connect", () => {
      s.emit("user_online", {
        email: expertEmail,
        name: expertName,
        role: "expert",
      });
    });

    s.on("online_users_count", handleOnlineCount);
    s.on("chat_history", handleChatHistory);
    s.on("receive_message", handleReceiveMessage);
    s.on("new_message_notification", handleNewNotification);
    s.on("user_typing", handleTypingEvent);
    s.on("user_stopped_typing", handleStopTypingEvent);

    return () => {
      s.off("online_users_count", handleOnlineCount);
      s.off("chat_history", handleChatHistory);
      s.off("receive_message", handleReceiveMessage);
      s.off("new_message_notification", handleNewNotification);
      s.off("user_typing", handleTypingEvent);
      s.off("user_stopped_typing", handleStopTypingEvent);
      try {
        s.disconnect();
      } catch (e) {}
    };
  }, [expertEmail, expertName, activeRoom, scrollToBottom, token]);

  useEffect(() => {
    loadConversations();
  }, [loadConversations]);

  const openConversation = (convo) => {
    if (!convo?.room) return;
    setActiveRoom(convo.room);
    setActiveOther(
      convo.otherEmail ||
        convo.room.split("_").find((e) => e !== expertEmail) ||
        "User"
    );
    setMessages([]);
    setLoadingMessages(true);
    setTypingVisible(false);

    if (socketRef.current?.connected) {
      socketRef.current.emit("join_private", convo.room);
    } else {
      setLoadingMessages(false);
    }
  };

  // ✅ fallback POST uses `${API}/api/messages`
  const sendMessage = () => {
    if (!activeRoom || !inputValue.trim()) return;
    const text = inputValue.trim();

    const local = {
      author: expertEmail,
      authorRole: "expert",
      room: activeRoom,
      message: text,
      createdAt: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, local]);
    setInputValue("");
    setTimeout(scrollToBottom, 40);

    const payload = {
      room: activeRoom,
      author: expertEmail,
      authorRole: "expert",
      message: text,
    };

    if (socketRef.current?.connected) {
      socketRef.current.emit("send_private_message", payload);
      socketRef.current.emit("stop_typing", { room: activeRoom });
      isTypingRef.current = false;
    } else if (API) {
      fetch(`${API}/api/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(payload),
      }).catch((e) => console.error("message post fallback failed", e));
    }
  };

  const handleTyping = () => {
    if (!socketRef.current || !activeRoom) return;
    if (!isTypingRef.current) {
      isTypingRef.current = true;
      socketRef.current.emit("typing", {
        room: activeRoom,
        name: expertName,
        author: expertEmail,
      });
    }
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      isTypingRef.current = false;
      if (socketRef.current) {
        socketRef.current.emit("stop_typing", { room: activeRoom });
      }
    }, 1000);
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const handleQuickReply = (reply) => {
    if (!activeRoom) return;
    setInputValue((prev) => (prev ? `${prev} ${reply}` : reply));
  };

  const markAllRead = () => {
    setConversations((prev) => prev.map((c) => ({ ...c, unread: 0 })));
    if (socketRef.current) {
      socketRef.current.emit("mark_all_read", { expertEmail });
    }
    showToast("All conversations marked as read", "success");
  };

  const filteredConversations = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return conversations;
    return conversations.filter((c) => {
      const other = (c.otherEmail || "").toLowerCase();
      const lastMsg = (c.lastMessage || "").toLowerCase();
      return other.includes(term) || lastMsg.includes(term);
    });
  }, [conversations, search]);

  return (
    <div className="expert-dashboard-v2">
      {/* Toast */}
      {toast.visible && (
        <div className={`enhanced-toast ${toast.type} show`}>
          <div className="toast-inner">
            <div className="toast-icon">
              {toast.type === "error"
                ? "⚠️"
                : toast.type === "success"
                ? "✅"
                : "ℹ️"}
            </div>
            <div>{toast.text}</div>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="enhanced-header">
        <div className="shell header-shell">
          <div className="brand-enhanced" onClick={() => navigate("/experts")}>
            <div className="brand-glow">S</div>
            <div className="brand-stack">
              <div className="brand-main">
                Solution<span>Hub</span>
              </div>
              <div className="brand-subtitle">
                Expert Control Center — Live Support
              </div>
            </div>
          </div>

          <div className="header-stats">
            <div className="stat-badge">
              <span className="badge-dot" />
              <span>Live • {onlineUsers} online</span>
            </div>
            <div className="status-indicator">
              <span className={`status-dot ${activeRoom ? "active" : ""}`} />
              <span>{activeRoom ? "Active chat" : "Idle"}</span>
            </div>
            <button
              className="logout-premium"
              onClick={() => {
                localStorage.removeItem("token");
                localStorage.removeItem("email");
                localStorage.removeItem("name");
                navigate("/login");
              }}
            >
              <span>Logout</span>
              <i className="fa-solid fa-power-off" />
            </button>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="dashboard-main">
        <div className="shell main-shell">
          <div className="enhanced-chat-layout">
            {/* Left: Conversations */}
            <aside className="conversations-panel glass-effect">
              <div className="panel-header">
                <div className="header-row">
                  <div className="header-title">
                    <i className="fa-solid fa-comments" />
                    Conversations
                  </div>
                  <div className="header-actions">
                    <button
                      className="action-btn refresh"
                      onClick={loadConversations}
                      title="Refresh"
                    >
                      <i className="fa-solid fa-rotate" />
                    </button>
                    <button
                      className="action-btn mark-read"
                      onClick={markAllRead}
                      title="Mark all read"
                    >
                      <i className="fa-solid fa-check-double" />
                    </button>
                  </div>
                </div>

                <div className="stats-row">
                  <div className="stat-item">
                    <span className="stat-number">{stats.totalConvos}</span>
                    <span className="stat-label">Total</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-number unread">{stats.unread}</span>
                    <span className="stat-label">Unread</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-number">{stats.today}</span>
                    <span className="stat-label">Today</span>
                  </div>
                </div>

                <input
                  className="search-enhanced"
                  placeholder="Search by email or message…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>

              <div className="conversations-scroll">
                {loadingConvos ? (
                  <div className="loading-state">
                    <div className="spinner-pulse" />
                    <span>Loading conversations…</span>
                  </div>
                ) : filteredConversations.length === 0 ? (
                  <div className="empty-enhanced">
                    <div className="empty-icon">💬</div>
                    <div className="empty-title">No conversations yet</div>
                    <div className="empty-subtitle">
                      Your recent chats will appear here
                    </div>
                  </div>
                ) : (
                  <>
                    {filteredConversations.map((c) => {
                      const other =
                        c.otherEmail ||
                        c.room.split("_").find((e) => e !== expertEmail);
                      const unread = c.unread || 0;
                      const isRecent =
                        c.lastMessageTime &&
                        new Date(c.lastMessageTime) >
                          new Date(Date.now() - 24 * 60 * 60 * 1000);
                      const active = c.room === activeRoom;

                      return (
                        <div
                          key={c.room}
                          className={`conversation-item ${
                            active ? "active" : ""
                          } ${unread > 0 ? "unread" : ""} ${
                            isRecent ? "recent" : ""
                          }`}
                          onClick={() => openConversation(c)}
                        >
                          <div className="convo-avatar">
                            <div className="avatar-ring">
                              {(other || "U")[0]?.toUpperCase()}
                              {unread > 0 && (
                                <div className="unread-badge">
                                  {unread > 99 ? "99+" : unread}
                                </div>
                              )}
                            </div>
                          </div>
                          <div className="convo-details">
                            <div className="convo-header">
                              <span className="convo-name">{other}</span>
                              <span className="convo-time">
                                {formatTime(c.lastMessageTime)}
                              </span>
                            </div>
                            <div
                              className="convo-preview"
                              title={c.lastMessage}
                            >
                              {c.lastMessage || "Start conversation…"}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    <div ref={conversationsEndRef} />
                  </>
                )}
              </div>
            </aside>

            {/* Right: Chat */}
            <section className="chat-main glass-effect">
              <div className="chat-header-enhanced">
                <div className="chat-info">
                  {activeOther ? (
                    <div className="chat-participant">
                      <div className="participant-avatar">
                        {activeOther[0]?.toUpperCase()}
                      </div>
                      <div>
                        <div className="participant-name">{activeOther}</div>
                        <div className="participant-status">
                          <span className="status-dot active" />
                          <span>Private room • Messages stored</span>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="chat-title">Select a conversation</div>
                      <div className="chat-subtitle">
                        Choose a user from the left list to start chatting
                      </div>
                    </>
                  )}
                </div>
              </div>

              <div className="chat-container">
                <div
                  className="messages-container"
                  ref={messagesContainerRef}
                >
                  {loadingMessages ? (
                    <div className="loading-chat">
                      <div className="spinner-dots">
                        <div className="dot" />
                        <div className="dot" />
                        <div className="dot" />
                      </div>
                      Loading messages…
                    </div>
                  ) : messages.length === 0 ? (
                    <div className="empty-chat">
                      <div className="empty-chat-icon">💬</div>
                      <div className="empty-chat-text">
                        {activeRoom
                          ? "No messages yet — say hello 👋"
                          : "Select a conversation to see messages"}
                      </div>
                    </div>
                  ) : (
                    <>
                      {messages.map((m, i) => {
                        const isMe = m.author === expertEmail;
                        const key =
                          m._id || `${m.createdAt || ""}:${i}`;
                        return (
                          <div
                            key={key}
                            className={`message-bubble ${
                              isMe ? "sent" : "received"
                            }`}
                          >
                            {!isMe && (
                              <div className="message-avatar">
                                {m.author?.[0]?.toUpperCase() || "U"}
                              </div>
                            )}
                            <div className="message-content">
                              <div
                                className="message-text"
                                dangerouslySetInnerHTML={{
                                  __html: m.message || "",
                                }}
                              />
                              <div className="message-meta">
                                <span className="message-time">
                                  {formatTime(m.createdAt)}
                                </span>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                      {typingVisible && (
                        <div className="typing-animation">
                          <div className="typing-avatar">
                            {activeOther?.[0]?.toUpperCase() || "U"}
                          </div>
                          <div className="typing-bubbles">
                            <div className="bubble" />
                            <div className="bubble" />
                            <div className="bubble" />
                          </div>
                          <span className="typing-text">
                            {activeOther} is typing…
                          </span>
                        </div>
                      )}
                    </>
                  )}
                </div>

                <div className="input-section">
                  <div className="quick-replies">
                    {quickReplies.map((reply, idx) => (
                      <button
                        key={idx}
                        className="quick-btn"
                        onClick={() => handleQuickReply(reply)}
                        disabled={!activeRoom}
                      >
                        {reply.slice(0, 22)}…
                      </button>
                    ))}
                  </div>

                  <div className="input-row">
                    <textarea
                      className="message-input"
                      disabled={!activeRoom}
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder={
                        activeRoom
                          ? "Type your reply and press Enter to send… (Shift+Enter for new line)"
                          : "Select a conversation to start typing…"
                      }
                      onKeyDown={handleKeyDown}
                      onInput={handleTyping}
                      rows={1}
                    />
                    <button
                      className="send-button"
                      disabled={!inputValue.trim() || !activeRoom}
                      onClick={sendMessage}
                    >
                      <i className="fa-solid fa-paper-plane" />
                    </button>
                  </div>
                </div>
              </div>
            </section>
          </div>
        </div>
      </main>

      <footer className="enhanced-footer">
        <div className="shell footer-shell">
          <div className="footer-left">
            <div className="footer-brand">
              © 2026 SolutionHub • Expert Dashboard
            </div>
            <div className="footer-features">
              🔒 Private 1:1 Rooms • 💾 Messages Stored • ⚡ Real-time Chat •
              📱 Responsive
            </div>
          </div>
          <div className="footer-right">
            <div className="status-indicator-small">
              <span className="status-dot-small" />
              <span>Expert: {expertName}</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default ExpertDashboard;
