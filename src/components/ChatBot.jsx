// src/components/ChatBot.jsx
import React, { useState, useRef, useEffect } from "react";
import { X, Send, Sparkles, ArrowRight } from "lucide-react";

/**
 * Fully-hardened ChatBot component
 * - always posts to /api/ai/ask (no accidental /ai/ask)
 * - supports VITE_API_BASE or REACT_APP_API_BASE env variable
 * - includes Authorization: Bearer <token> if token present in localStorage
 * - has AbortController timeout (15s)
 * - reads JSON or plain text response and surfaces helpful errors
 */

const ChatBot = ({ open, onClose, onEscalate, user }) => {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Hi, I'm Solvenut AI. Tell me about your decision, project, or career fork. I can help you think, then route you to the right expert.",
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesRef = useRef(null);

  // env handling: prefer VITE_API_BASE (Vite), fallback to CRA REACT_APP_API_BASE
  const rawEnvApi =
    typeof import.meta !== "undefined" && import.meta.env?.VITE_API_BASE
      ? import.meta.env.VITE_API_BASE
      : process?.env?.REACT_APP_API_BASE || "";

  const apiBase = rawEnvApi && rawEnvApi.trim() ? rawEnvApi.replace(/\/+$/, "") : "";

  // Build the final absolute URL for the AI endpoint
  const buildAiUrl = () => {
    // ALWAYS call /api/ai/ask (backend defines app.post('/api/ai/ask'...))
    if (apiBase) return `${apiBase}/api/ai/ask`;
    return `/api/ai/ask`;
  };

  useEffect(() => {
    if (messagesRef.current) {
      messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  const addMessage = (msg) => setMessages((prev) => [...prev, msg]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const text = input.trim();
    addMessage({ role: "user", content: text });
    setInput("");
    setIsLoading(true);

    const url = buildAiUrl();
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

    // 15s timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    try {
      console.debug("ChatBot -> POST", url, { prompt: text, user });

      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          prompt: text,
          user: { name: user?.name, email: user?.email },
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        // Try parse JSON error, else fallback to text
        let body = "";
        try {
          const json = await res.json();
          body = json?.error || json?.message || JSON.stringify(json);
        } catch (e) {
          try {
            body = await res.text();
          } catch (e2) {
            body = "(no body)";
          }
        }

        console.error("AI error response:", res.status, res.statusText, body);

        addMessage({
          role: "assistant",
          content:
            `AI returned error ${res.status} ${res.statusText}. ${body}\n\n` +
            `Checks: ensure backend route /api/ai/ask exists, your server is reachable, and if deployed make sure GEMINI_API_KEY is set (if using Google Generative).`,
        });

        return;
      }

      // Parse JSON but be tolerant of plain text
      let data;
      try {
        data = await res.json();
      } catch (e) {
        const txt = await res.text().catch(() => "");
        data = { answer: txt };
      }

      // Backend expected to return { answer: "..." }
      const answer =
        data?.answer ||
        data?.reply ||
        data?.result ||
        (typeof data === "string" ? data : null) ||
        "AI response missing. Please check server logs.";

      addMessage({ role: "assistant", content: answer });
    } catch (err) {
      clearTimeout(timeoutId);
      console.error("AI/network error:", err);

      const userMessage =
        err.name === "AbortError"
          ? "Request timed out after 15s. The AI service took too long to respond."
          : err.message
          ? `Network or CORS error: ${err.message}`
          : "Unknown network error occurred.";

      addMessage({
        role: "assistant",
        content:
          `${userMessage}\n\nQuick checks:\n` +
          `• Is your frontend env VITE_API_BASE or REACT_APP_API_BASE pointing to the backend?\n` +
          `• Is the backend running and reachable at that address?\n` +
          `• Does the backend expose POST /api/ai/ask (not /ai/ask)?\n` +
          `• If CORS errors appear in console, enable CORS on server (you already do app.use(cors())).`,
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  if (!open) return null;

  return (
    <div className="chatbot-overlay" onClick={onClose}>
      <div className="chatbot-modal" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="chatbot-header">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <Sparkles size={22} />
            <div>
              <div className="chatbot-title">Solvenut AI</div>
              <div className="chatbot-subtitle">Fast thinking help • Human escalation</div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="chatbot-escalate-btn"
              type="button"
              onClick={() => {
                if (isLoading) return;
                onEscalate();
              }}
              disabled={isLoading}
            >
              <ArrowRight size={16} />
              Expert
            </button>

            <button
              className="chatbot-close-btn"
              type="button"
              onClick={() => {
                if (isLoading) return;
                onClose();
              }}
              aria-label="Close chat"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="chatbot-messages" ref={messagesRef}>
          {messages.map((m, idx) => (
            <div key={idx} className={`chatbot-message ${m.role === "user" ? "user" : "assistant"}`}>
              <div className="chatbot-message-content">{m.content}</div>
            </div>
          ))}

          {isLoading && (
            <div className="chatbot-message assistant">
              <div className="chatbot-message-content">
                <div className="chatbot-typing-dots">
                  <span />
                  <span />
                  <span />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <div className="chatbot-input-container">
          <textarea
            className="chatbot-input"
            placeholder="Describe your decision, project, or question…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={2}
            disabled={isLoading}
          />
          <button
            className="chatbot-send-btn"
            type="button"
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            aria-label="Send message"
          >
            <Send size={18} />
          </button>
        </div>
      </div>
    </div>
  );
};

export default ChatBot;