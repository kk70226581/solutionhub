// src/components/ChatBot.jsx
import React, { useState, useRef, useEffect } from "react";
import { X, Send, Sparkles, ArrowRight } from "lucide-react";

/**
 * ChatBot component using Solvenut AI Expert endpoints
 * - Uses /api/ai/start to begin a consultation with initial message
 * - Uses /api/ai/message for follow-up messages with streaming
 * - Supports VITE_API_BASE or REACT_APP_API_BASE env variable
 * - Includes Authorization: Bearer <token> if token present in localStorage
 * - Has AbortController timeout (30s for streaming)
 */

// Simple markdown to JSX converter
function renderMarkdown(text) {
  return (
    <>
      {text.split("\n").map((line, idx) => {
        // Bold text
        line = line.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
        line = line.replace(/__(.*?)__/g, "<strong>$1</strong>");

        // Italic text
        line = line.replace(/\*(.*?)\*/g, "<em>$1</em>");
        line = line.replace(/_(.*?)_/g, "<em>$1</em>");

        // List items
        if (line.trim().match(/^[\d]+\.|^[-*]/)) {
          return (
            <div key={idx} style={{ marginLeft: "1.5rem", marginBottom: "0.5rem" }}>
              <div dangerouslySetInnerHTML={{ __html: line }} />
            </div>
          );
        }

        // Headers
        if (line.startsWith("###")) {
          return (
            <h4 key={idx} style={{ fontWeight: "600", marginTop: "0.5rem", marginBottom: "0.25rem" }}>
              {line.replace(/^#+\s/, "")}
            </h4>
          );
        }
        if (line.startsWith("##")) {
          return (
            <h3 key={idx} style={{ fontWeight: "600", marginTop: "0.75rem", marginBottom: "0.5rem" }}>
              {line.replace(/^#+\s/, "")}
            </h3>
          );
        }
        if (line.startsWith("#")) {
          return (
            <h2 key={idx} style={{ fontWeight: "700", marginTop: "1rem", marginBottom: "0.75rem" }}>
              {line.replace(/^#+\s/, "")}
            </h2>
          );
        }

        // Regular paragraph
        if (line.trim()) {
          return (
            <p key={idx} style={{ marginBottom: "0.5rem" }}>
              <span dangerouslySetInnerHTML={{ __html: line }} />
            </p>
          );
        }

        // Empty line - add spacing
        return <div key={idx} style={{ marginBottom: "0.5rem" }} />;
      })}
    </>
  );
}

const ChatBot = ({ open, onClose, onEscalate }) => {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Hi, I'm Solvenut AI Expert. Tell me about your decision, project, or career fork. I can help you think, then route you to the right expert.",
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [conversationId, setConversationId] = useState(null);
  const messagesRef = useRef(null);

  // env handling: prefer VITE_API_BASE (Vite), fallback to CRA REACT_APP_API_BASE
  const rawEnvApi =
    typeof import.meta !== "undefined" && import.meta.env?.VITE_API_BASE
      ? import.meta.env.VITE_API_BASE
      : globalThis?.process?.env?.REACT_APP_API_BASE || "";

  const apiBase = rawEnvApi && rawEnvApi.trim() ? rawEnvApi.replace(/\/+$/, "") : "";

  // Build API URLs
  const buildAiStartUrl = () => (apiBase ? `${apiBase}/api/ai/start` : `/api/ai/start`);
  const buildAiMessageUrl = () => (apiBase ? `${apiBase}/api/ai/message` : `/api/ai/message`);

  useEffect(() => {
    if (messagesRef.current) {
      messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  const addMessage = (msg) => setMessages((prev) => [...prev, msg]);

  const getAuthHeaders = () => {
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const text = input.trim();
    addMessage({ role: "user", content: text });
    setInput("");
    setIsLoading(true);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

    try {
      // If no conversation yet, start one with the first message
      if (!conversationId) {
        console.debug("ChatBot -> Starting AI consultation with:", { domain: "career", problem: text });

        const startRes = await fetch(buildAiStartUrl(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            ...getAuthHeaders(),
          },
          body: JSON.stringify({
            domain: "career", // Default domain - could be made configurable
            problem: text,
          }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!startRes.ok) {
          let body = "";
          try {
            const json = await startRes.json();
            body = json?.error || json?.message || JSON.stringify(json);
          } catch {
            body = await startRes.text().catch(() => "(no body)");
          }

          console.error("AI start error:", startRes.status, body);
          addMessage({
            role: "assistant",
            content: `Error starting consultation: ${body}. Please try again.`,
          });
          return;
        }

        const startData = await startRes.json().catch(() => ({}));
        const newConvId = startData?.conversation?._id;

        if (!newConvId) {
          addMessage({
            role: "assistant",
            content: "Error: Could not create AI conversation. Please try again.",
          });
          return;
        }

        setConversationId(newConvId);

        // Add assistant response from first exchange
        if (startData?.firstExchange?.assistantMessage?.content) {
          addMessage({
            role: "assistant",
            content: startData.firstExchange.assistantMessage.content,
          });
        }
      } else {
        // Send follow-up message
        console.debug("ChatBot -> Sending follow-up message to conversation:", conversationId);

        const messageRes = await fetch(buildAiMessageUrl(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "text/event-stream",
            ...getAuthHeaders(),
          },
          body: JSON.stringify({
            conversationId,
            message: text,
            stream: true,
          }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!messageRes.ok || !messageRes.body) {
          let body = "";
          try {
            const json = await messageRes.json();
            body = json?.error || json?.message || JSON.stringify(json);
          } catch {
            body = await messageRes.text().catch(() => "(no body)");
          }

          console.error("AI message error:", messageRes.status, body);
          addMessage({
            role: "assistant",
            content: `Error sending message: ${body}. Please try again.`,
          });
          return;
        }

        // Stream response
        const reader = messageRes.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let assistantContent = "";
        const assistantId = `assistant-${Date.now()}`;
        let messageAdded = false;
        let doneReceived = false;

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const events = buffer.split("\n\n");
          buffer = events.pop() || "";

          for (const rawEvent of events) {
            if (!rawEvent.trim()) continue; // Skip empty events

            const lines = rawEvent.split("\n");
            let event = null;
            let payload = null;

            for (const line of lines) {
              if (line.startsWith("event:")) {
                event = line.replace("event:", "").trim();
              }
              if (line.startsWith("data:")) {
                try {
                  payload = JSON.parse(line.replace("data:", "").trim());
                } catch (e) {
                  console.error("Failed to parse SSE data:", e);
                }
              }
            }

            if (event && payload) {
              console.debug("ChatBot SSE event:", event, "payload:", JSON.stringify(payload).slice(0, 100));
              
              if (event === "token" && payload.token) {
                assistantContent += payload.token;

                // Add message on first token, then update
                if (!messageAdded) {
                  addMessage({ role: "assistant", content: assistantContent, id: assistantId });
                  messageAdded = true;
                } else {
                  setMessages((prev) =>
                    prev.map((m) =>
                      m.id === assistantId ? { ...m, content: assistantContent } : m
                    )
                  );
                }
              }

              if (event === "done") {
                doneReceived = true;
                console.debug("ChatBot: received done event");
              }
            }
          }
        }

        // Handle case where no tokens received or incomplete streaming
        if (!messageAdded) {
          console.warn("ChatBot: No tokens received, adding fallback. Content length:", assistantContent.length);
          addMessage({ role: "assistant", content: assistantContent || "No response received." });
        } else if (!doneReceived) {
          console.warn("ChatBot: Stream ended without done event");
          // Content already added via tokens, just finalize it
        }

      }
    } catch (err) {
      clearTimeout(timeoutId);
      console.error("AI error:", err);

      const errorMsg =
        err.name === "AbortError"
          ? "Request timed out. The AI service took too long to respond."
          : err.message || "Unknown error occurred.";

      addMessage({
        role: "assistant",
        content: `Error: ${errorMsg}. Please check your connection and try again.`,
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
              <div className="chatbot-title">Solvenut AI Expert</div>
              <div className="chatbot-subtitle">Fast thinking help • Human escalation</div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="chatbot-escalate-btn"
              type="button"
              aria-label="Escalate to a human expert"
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
              <div className="chatbot-message-content">
                {m.role === "assistant" ? renderMarkdown(m.content) : m.content}
              </div>
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
            placeholder="Ask a follow-up or add more context…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={2}
            aria-label="Chat message"
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
