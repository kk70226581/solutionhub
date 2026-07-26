// src/components/PsychologyAssistant.jsx
import React, { useEffect, useRef, useState } from "react";
import { MessageSquare, RotateCcw, Send, X, ArrowRight, User } from "lucide-react";
import "../styles/PsychologyAssistant.css";

const systemPrompt = `You are Dr. Empathy, a compassionate AI psychology assistant with a warm, supportive personality. Your role is to:

1. LISTEN with genuine empathy and understanding
2. VALIDATE the user's feelings and experiences
3. GUIDE them toward clarity and self-understanding
4. SUGGEST practical, actionable coping strategies
5. Know when to escalate to real experts

Communication Style:
- Be warm, human, and genuinely caring
- Use their name when they share it
- Ask follow-up questions to understand better
- Normalize their feelings and experiences
- Use a conversational, non-judgmental tone
- Avoid clinical jargon unless necessary

Key Guidelines:
- If they mention severe mental health crisis, self-harm, or emergency → suggest they seek professional help immediately
- After 2-3 exchanges, ask: "Would you like to chat with a real licensed expert who can provide more specialized help?"
- If they say yes to expert escalation, end conversation professionally and encourage expert booking
- Remember: You're helpful, but you're an AI - real experts are better for ongoing care`;

const welcomeMessage = {
  role: "assistant",
  content: `Hi there! 👋 I'm Dr. Empathy, your supportive AI companion. 

I'm here to listen and help you work through whatever's on your mind—whether it's stress, relationships, personal challenges, or just needing someone to talk to.

What's bothering you today? I'm all ears and ready to help however I can.`,
};

const PsychologyAssistant = ({ open, onClose }) => {
  const [messages, setMessages] = useState([welcomeMessage]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showExpertCTA, setShowExpertCTA] = useState(false);
  const [conversationDepth, setConversationDepth] = useState(0);
  const messagesRef = useRef(null);
  const apiBase = import.meta.env.VITE_API_BASE || "/";

  useEffect(() => {
    if (messagesRef.current) {
      messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  const addMessage = (msg) => setMessages((prev) => [...prev, msg]);

  const handleSend = async (nextPrompt = input) => {
    if (!nextPrompt.trim() || isLoading) return;

    const text = nextPrompt.trim();
    addMessage({ role: "user", content: text });
    setInput("");
    setIsLoading(true);
    setConversationDepth(prev => prev + 1);

    // Show expert escalation CTA after 2-3 user messages
    if (conversationDepth >= 2 && !showExpertCTA) {
      setShowExpertCTA(true);
    }

    const url = `${apiBase.replace(/\/+$/, "")}/api/psychology-assist`;
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 15000);

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ 
          message: text,
          systemPrompt: systemPrompt,
          conversationHistory: messages.map(m => ({
            role: m.role,
            content: m.content
          }))
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        let body = "";
        try {
          const json = await res.json();
          body = json?.error || json?.message || JSON.stringify(json);
        } catch {
          body = await res.text().catch(() => "");
        }

        addMessage({
          role: "assistant",
          content: `I'm having trouble connecting right now (${res.status}). ${body || "Let me try again in a moment."}\n\nIf this keeps happening, you can connect with a real expert who can help you better. Would you like to book a consultation?`,
        });
        return;
      }

      let data;
      try {
        data = await res.json();
      } catch {
        const txt = await res.text().catch(() => "");
        data = { response: txt };
      }

      const response =
        data?.response ||
        data?.answer ||
        data?.message ||
        (typeof data === "string" ? data : null) ||
        "I'm listening and here to help. Could you tell me more about what you're experiencing?";

      addMessage({ role: "assistant", content: response });

      // Check if response indicates emergency situation
      if (data?.needsEmergencyResponse) {
        addMessage({
          role: "assistant",
          content: "If you're in immediate danger or having thoughts of self-harm, please contact emergency services or a crisis hotline. You matter, and help is available 24/7.",
        });
      }
    } catch (err) {
      const userMessage =
        err.name === "AbortError"
          ? "That took a bit longer than expected. Let me listen again—please go ahead."
          : err.message
          ? `I had a moment of difficulty: ${err.message}`
          : "I'm having trouble connecting. Please try again.";

      addMessage({
        role: "assistant",
        content: `${userMessage}\n\nOr if you'd prefer, connect with a real licensed expert who can give you personalized support.`,
      });
    } finally {
      window.clearTimeout(timeoutId);
      setIsLoading(false);
    }
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      handleSend();
    }
  };

  const handleExpertEscalation = () => {
    addMessage({
      role: "assistant",
      content: `I'm so glad we talked today. What you're going through deserves the attention of a real licensed expert who can provide specialized guidance tailored to your situation.

I've connected you to our expert directory where you can find and book qualified professionals. Take your time, and remember—reaching out for help is a sign of strength. 💙`,
    });
    setTimeout(() => {
      // Could navigate to experts page or open expert selection
      window.location.href = "/experts";
    }, 2000);
  };

  const resetConversation = () => {
    setMessages([welcomeMessage]);
    setInput("");
    setConversationDepth(0);
    setShowExpertCTA(false);
  };

  if (!open) return null;

  return (
    <div className="psychology-assistant-overlay" onClick={onClose}>
      <div className="psychology-assistant-modal" onClick={(event) => event.stopPropagation()}>
        <div className="psychology-assistant-header">
          <div className="psychology-assistant-heading">
            <div className="psychology-assistant-avatar">
              <MessageSquare size={24} />
            </div>
            <div>
              <div className="psychology-assistant-title">Dr. Empathy</div>
              <div className="psychology-assistant-subtitle">Your supportive AI companion</div>
            </div>
          </div>

          <div className="psychology-assistant-header-actions">
            <button
              className="psychology-assistant-icon-btn"
              type="button"
              onClick={resetConversation}
              disabled={isLoading || messages.length === 1}
              aria-label="Start new conversation"
              title="New conversation"
            >
              <RotateCcw size={18} />
            </button>
            <button
              className="psychology-assistant-close-btn"
              type="button"
              onClick={() => {
                if (!isLoading) onClose();
              }}
              aria-label="Close assistant"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="psychology-assistant-messages" ref={messagesRef} aria-live="polite">
          {messages.map((message, index) => (
            <div
              key={`${message.role}-${index}`}
              className={`psychology-assistant-message ${message.role === "user" ? "user" : "assistant"}`}
            >
              {message.role === "assistant" && (
                <div className="psychology-assistant-avatar-small">
                  <MessageSquare size={16} />
                </div>
              )}
              {message.role === "user" && (
                <div className="psychology-assistant-avatar-small user-avatar">
                  <User size={16} />
                </div>
              )}
              <div className="psychology-assistant-message-content">
                {message.content}
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="psychology-assistant-message assistant">
              <div className="psychology-assistant-avatar-small">
                <MessageSquare size={16} />
              </div>
              <div className="psychology-assistant-message-content">
                <div className="psychology-assistant-typing-dots" aria-label="Dr. Empathy is thinking">
                  <span />
                  <span />
                  <span />
                </div>
              </div>
            </div>
          )}
        </div>

        {showExpertCTA && !isLoading && (
          <div className="psychology-assistant-expert-cta">
            <div className="expert-cta-content">
              <h4>Would you like expert guidance?</h4>
              <p>A real licensed professional can provide specialized support tailored to your situation.</p>
            </div>
            <button
              type="button"
              className="expert-cta-btn"
              onClick={handleExpertEscalation}
              disabled={isLoading}
            >
              <span>Connect with Expert</span>
              <ArrowRight size={16} />
            </button>
          </div>
        )}

        <div className="psychology-assistant-input-container">
          <textarea
            className="psychology-assistant-input"
            placeholder="Share what's on your mind. I'm listening..."
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            rows={1}
          />
          <button
            className="psychology-assistant-send-btn"
            type="button"
            onClick={() => handleSend()}
            disabled={isLoading || !input.trim()}
            aria-label="Send message"
            title="Send"
          >
            <Send size={18} />
          </button>
        </div>
      </div>
    </div>
  );
};

export default PsychologyAssistant;
