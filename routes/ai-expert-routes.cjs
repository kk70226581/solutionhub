const VALID_DOMAINS = new Set([
  "career",
  "business",
  "finance",
  "programming",
  "devops",
  "academics",
  "medical guidance",
  "personal growth",
]);

const DOMAIN_TO_EXPERT_FIELD = {
  career: "career",
  business: "business",
  finance: "finance",
  programming: "programming",
  devops: "devops",
  academics: "academics",
  "medical guidance": "medical",
  "personal growth": "career",
};

let aiServicePromise = null;

const getAiService = () => {
  if (!aiServicePromise) {
    aiServicePromise = import("../services/aiExpertService.js");
  }
  return aiServicePromise;
};

const sanitizeText = (value, max = 6000) => String(value || "").trim().slice(0, max);
const escapeRegExp = (value) => String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const sendSse = (res, event, data) => {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
};

const registerAIExpertRoutes = (app, deps) => {
  const {
    authMiddleware,
    createRateLimiter,
    AIConversation,
    AIMessage,
    AIUserFeedback,
    Expert,
    normalizeEmail,
  } = deps;

  const aiRateLimiter = createRateLimiter({
    windowMs: Number(process.env.AI_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
    max: Number(process.env.AI_RATE_LIMIT_MAX || 50),
    keyPrefix: "ai-expert",
  });

  const loadConversation = async (conversationId, userEmail) => {
    const conversation = await AIConversation.findOne({
      _id: conversationId,
      userEmail,
    });
    return conversation;
  };

  const getConversationMessages = async (conversationId) => {
    const messages = await AIMessage.find({ conversationId }).sort({ createdAt: 1 }).limit(40).lean();
    return messages.map((message) => ({
      role: message.role,
      content: message.content,
    }));
  };

  app.post("/api/ai/start", authMiddleware, aiRateLimiter, async (req, res) => {
    try {
      const { normalizeDomain } = await getAiService();
      const userEmail = normalizeEmail(req.user?.email);
      const requestedDomain = normalizeDomain(req.body?.domain);
      const domain = VALID_DOMAINS.has(requestedDomain) ? requestedDomain : "career";
      const problem = sanitizeText(req.body?.problem || req.body?.message || "", 6000);

      if (!userEmail) {
        return res.status(401).json({ error: "Authenticated user email required" });
      }

      const conversation = await AIConversation.create({
        userId: req.user?.id || req.user?._id || userEmail,
        userEmail,
        domain,
        title: problem ? problem.slice(0, 80) : `${domain} consultation`,
      });

      let firstExchange = null;
      if (problem) {
        const userMessage = await AIMessage.create({
          conversationId: conversation._id,
          userEmail,
          role: "user",
          domain,
          content: problem,
        });

        const history = [{ role: "user", content: problem }];
        const aiResult = await getAiService()
          .then((service) => service.askAIExpert({ domain, messages: history, userMessage: problem }))
          .catch((err) => {
            console.error("AI Expert start error:", err);
            return {
              text: "I could not reach the AI Expert service right now. You can continue trying, or connect with a verified human expert for this topic.",
              confidenceScore: 35,
              recommendEscalation: true,
              escalationReason: "service_unavailable",
              tokenUsage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
              raw: { error: err?.message || String(err) },
            };
          });

        const assistantMessage = await AIMessage.create({
          conversationId: conversation._id,
          userEmail,
          role: "assistant",
          domain,
          content: aiResult.text,
          confidenceScore: aiResult.confidenceScore,
          recommendEscalation: aiResult.recommendEscalation,
          escalationReason: aiResult.escalationReason,
          tokenUsage: aiResult.tokenUsage,
          rawProviderResponse: aiResult.raw,
        });

        conversation.confidenceScore = aiResult.confidenceScore;
        conversation.escalationStatus = aiResult.recommendEscalation ? "suggested" : "none";
        conversation.escalationReason = aiResult.escalationReason || "";
        conversation.tokenUsage = aiResult.tokenUsage;
        await conversation.save();

        firstExchange = { userMessage, assistantMessage, ai: aiResult };
      }

      return res.json({
        success: true,
        conversation,
        firstExchange,
      });
    } catch (err) {
      console.error("AI start route error:", err);
      return res.status(500).json({ error: "Failed to start AI Expert consultation" });
    }
  });

  app.post("/api/ai/message", authMiddleware, aiRateLimiter, async (req, res) => {
    const wantsStream =
      req.body?.stream === true ||
      String(req.headers.accept || "").includes("text/event-stream");

    try {
      const userEmail = normalizeEmail(req.user?.email);
      const conversationId = sanitizeText(req.body?.conversationId, 100);
      const content = sanitizeText(req.body?.message || req.body?.content, 6000);

      if (!conversationId || !content) {
        return res.status(400).json({ error: "conversationId and message are required" });
      }

      const conversation = await loadConversation(conversationId, userEmail);
      if (!conversation) {
        return res.status(404).json({ error: "Conversation not found" });
      }

      await AIMessage.create({
        conversationId: conversation._id,
        userEmail,
        role: "user",
        domain: conversation.domain,
        content,
      });

      const history = await getConversationMessages(conversation._id);

      if (wantsStream) {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          "X-Accel-Buffering": "no",
        });
        sendSse(res, "ready", { conversationId: String(conversation._id) });

        try {
          const { streamAIExpert } = await getAiService();
          const aiResult = await streamAIExpert({
            domain: conversation.domain,
            messages: history,
            userMessage: content,
            onToken: (token) => sendSse(res, "token", { token }),
          });

          const assistantMessage = await AIMessage.create({
            conversationId: conversation._id,
            userEmail,
            role: "assistant",
            domain: conversation.domain,
            content: aiResult.text || "I need a little more context before I can answer confidently.",
            confidenceScore: aiResult.confidenceScore,
            recommendEscalation: aiResult.recommendEscalation,
            escalationReason: aiResult.escalationReason,
            tokenUsage: aiResult.tokenUsage,
          });

          conversation.confidenceScore = aiResult.confidenceScore;
          conversation.escalationStatus = aiResult.recommendEscalation ? "suggested" : conversation.escalationStatus;
          conversation.escalationReason = aiResult.escalationReason || conversation.escalationReason;
          conversation.tokenUsage = {
            inputTokens: Number(conversation.tokenUsage?.inputTokens || 0) + Number(aiResult.tokenUsage?.inputTokens || 0),
            outputTokens: Number(conversation.tokenUsage?.outputTokens || 0) + Number(aiResult.tokenUsage?.outputTokens || 0),
            totalTokens: Number(conversation.tokenUsage?.totalTokens || 0) + Number(aiResult.tokenUsage?.totalTokens || 0),
          };
          await conversation.save();

          sendSse(res, "done", {
            messageId: assistantMessage._id,
            text: aiResult.text,
            confidenceScore: aiResult.confidenceScore,
            recommendEscalation: aiResult.recommendEscalation,
            escalationReason: aiResult.escalationReason,
            tokenUsage: aiResult.tokenUsage,
          });
          return res.end();
        } catch (err) {
          console.error("AI stream route error:", err);
          const fallback = "The AI Expert service is unavailable right now. You can continue with AI in a moment, or connect with a verified human expert.";
          const assistantMessage = await AIMessage.create({
            conversationId: conversation._id,
            userEmail,
            role: "assistant",
            domain: conversation.domain,
            content: fallback,
            confidenceScore: 35,
            recommendEscalation: true,
            escalationReason: "service_unavailable",
            rawProviderResponse: { error: err?.message || String(err) },
          });
          conversation.confidenceScore = 35;
          conversation.escalationStatus = "suggested";
          conversation.escalationReason = "service_unavailable";
          await conversation.save();
          sendSse(res, "token", { token: fallback });
          sendSse(res, "done", {
            messageId: assistantMessage._id,
            text: fallback,
            confidenceScore: 35,
            recommendEscalation: true,
            escalationReason: "service_unavailable",
          });
          return res.end();
        }
      }

      const { askAIExpert } = await getAiService();
      const aiResult = await askAIExpert({
        domain: conversation.domain,
        messages: history,
        userMessage: content,
      });

      const assistantMessage = await AIMessage.create({
        conversationId: conversation._id,
        userEmail,
        role: "assistant",
        domain: conversation.domain,
        content: aiResult.text,
        confidenceScore: aiResult.confidenceScore,
        recommendEscalation: aiResult.recommendEscalation,
        escalationReason: aiResult.escalationReason,
        tokenUsage: aiResult.tokenUsage,
        rawProviderResponse: aiResult.raw,
      });

      conversation.confidenceScore = aiResult.confidenceScore;
      conversation.escalationStatus = aiResult.recommendEscalation ? "suggested" : conversation.escalationStatus;
      conversation.escalationReason = aiResult.escalationReason || conversation.escalationReason;
      await conversation.save();

      return res.json({
        success: true,
        message: assistantMessage,
        confidenceScore: aiResult.confidenceScore,
        recommendEscalation: aiResult.recommendEscalation,
        escalationReason: aiResult.escalationReason,
        tokenUsage: aiResult.tokenUsage,
      });
    } catch (err) {
      console.error("AI message route error:", err);
      return res.status(500).json({ error: "Failed to send AI Expert message" });
    }
  });

  app.post("/api/ai/feedback", authMiddleware, aiRateLimiter, async (req, res) => {
    try {
      const userEmail = normalizeEmail(req.user?.email);
      const conversationId = sanitizeText(req.body?.conversationId, 100);
      const feedback = sanitizeText(req.body?.feedback, 30);
      const allowed = new Set(["helped", "partial", "not_helped"]);

      if (!conversationId || !allowed.has(feedback)) {
        return res.status(400).json({ error: "Valid conversationId and feedback are required" });
      }

      const conversation = await loadConversation(conversationId, userEmail);
      if (!conversation) {
        return res.status(404).json({ error: "Conversation not found" });
      }

      const saved = await AIUserFeedback.create({
        conversationId: conversation._id,
        messageId: req.body?.messageId || undefined,
        userEmail,
        feedback,
        note: sanitizeText(req.body?.note, 1000),
        domain: conversation.domain,
      });

      conversation.lastFeedback = feedback;
      if (feedback === "not_helped") {
        conversation.escalationStatus = "suggested";
        conversation.escalationReason = "ai_recommendation";
      }
      await conversation.save();

      return res.json({
        success: true,
        feedback: saved,
        recommendEscalation: feedback === "not_helped" || Number(conversation.confidenceScore || 0) < 70,
        escalationReason: conversation.escalationReason,
      });
    } catch (err) {
      console.error("AI feedback route error:", err);
      return res.status(500).json({ error: "Failed to save feedback" });
    }
  });

  app.post("/api/ai/escalate", authMiddleware, aiRateLimiter, async (req, res) => {
    try {
      const userEmail = normalizeEmail(req.user?.email);
      const conversationId = sanitizeText(req.body?.conversationId, 100);

      const conversation = await loadConversation(conversationId, userEmail);
      if (!conversation) {
        return res.status(404).json({ error: "Conversation not found" });
      }

      const field = DOMAIN_TO_EXPERT_FIELD[conversation.domain] || conversation.domain;
      let experts = await Expert.find({
        status: "approved",
        field: new RegExp(escapeRegExp(field), "i"),
      })
        .select("-password")
        .sort({ experience: -1, createdAt: -1 })
        .limit(12)
        .lean();

      let matchStrategy = "domain";
      if (!experts.length) {
        experts = await Expert.find({ status: "approved" })
          .select("-password")
          .sort({ experience: -1, createdAt: -1 })
          .limit(12)
          .lean();
        matchStrategy = "general";
      }

      conversation.status = "escalated";
      conversation.escalationStatus = "requested";
      conversation.escalationReason = conversation.escalationReason || "human_requested";
      await conversation.save();

      return res.json({
        success: true,
        domain: conversation.domain,
        expertField: field,
        experts,
        matchStrategy,
        escalationReason: conversation.escalationReason,
        redirectUrl: `/experts?domain=${encodeURIComponent(field)}&source=ai&conversationId=${encodeURIComponent(conversation._id)}`,
      });
    } catch (err) {
      console.error("AI escalate route error:", err);
      return res.status(500).json({ error: "Failed to escalate to human expert" });
    }
  });

  app.get("/api/ai/conversation/:id", authMiddleware, aiRateLimiter, async (req, res) => {
    try {
      const userEmail = normalizeEmail(req.user?.email);
      const conversation = await loadConversation(req.params.id, userEmail);
      if (!conversation) {
        return res.status(404).json({ error: "Conversation not found" });
      }

      const [messages, feedback] = await Promise.all([
        AIMessage.find({ conversationId: conversation._id }).sort({ createdAt: 1 }).lean(),
        AIUserFeedback.find({ conversationId: conversation._id }).sort({ createdAt: -1 }).lean(),
      ]);

      return res.json({
        success: true,
        conversation,
        messages,
        feedback,
      });
    } catch (err) {
      console.error("AI conversation fetch error:", err);
      return res.status(500).json({ error: "Failed to fetch AI conversation" });
    }
  });
};

module.exports = {
  registerAIExpertRoutes,
};
