const { getRelevantGuide, formatGuide } = require("../utils/app-guide.cjs");

const registerPublicRoutes = (app, deps) => {
  const {
    fetch,
    port,
    isRedisReady,
    cacheExpertsTtlSec,
    cacheHomeTtlSec,
    User,
    Expert,
    Message,
    Payment,
    Rating,
    authMiddleware,
    getCacheJson,
    setCacheJson,
    normalizeEmail,
    timeAgo,
    initials,
    getRatingStats,
    getRatingStatsBatch,
  } = deps;

  const buildDocsSpec = () => {
    const serverUrl =
      process.env.PUBLIC_API_URL ||
      process.env.RENDER_EXTERNAL_URL ||
      `http://localhost:${port}`;

    return {
      openapi: "3.0.3",
      info: {
        title: "SolutionHub API",
        version: "1.0.0",
        description: "Core public and auth endpoints",
      },
      servers: [{ url: serverUrl }],
      paths: {
        "/api/health-public": {
          get: { summary: "Public health check", responses: { 200: { description: "OK" } } },
        },
        "/api/password-policy": {
          get: { summary: "Password policy", responses: { 200: { description: "Policy returned" } } },
        },
        "/api/register": {
          post: { summary: "Register client account", responses: { 200: { description: "Created" }, 400: { description: "Validation error" } } },
        },
        "/api/pro-signup": {
          post: { summary: "Register expert account", responses: { 200: { description: "Created" }, 400: { description: "Validation error" } } },
        },
        "/api/login": {
          post: { summary: "Login for client/expert", responses: { 200: { description: "Login success" }, 401: { description: "Invalid credentials" } } },
        },
        "/api/forgot-password": {
          post: { summary: "Request password reset", responses: { 200: { description: "Request accepted" } } },
        },
        "/api/reset-password": {
          post: { summary: "Reset password with token", responses: { 200: { description: "Reset success" }, 400: { description: "Invalid token/password" } } },
        },
        "/api/experts": {
          get: { summary: "Public experts list", responses: { 200: { description: "Experts returned" } } },
        },
        "/api/public-home-data": {
          get: { summary: "Public homepage data", responses: { 200: { description: "Homepage metrics returned" } } },
        },
      },
    };
  };

  const buildConversationPreview = (message) => {
    const attachmentName = message.attachmentName || message.imageName || "";
    switch (message.messageType) {
      case "image":
        return attachmentName ? `[Image] ${attachmentName}` : "[Image]";
      case "audio":
        return attachmentName ? `[Audio] ${attachmentName}` : "[Audio]";
      case "pdf":
        return attachmentName ? `[PDF] ${attachmentName}` : "[PDF]";
      case "file":
        return attachmentName ? `[File] ${attachmentName}` : "[File]";
      default:
        return message.message || "";
    }
  };

  const callGemini = async (prompt) => {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      return {
        ok: false,
        reason: "NO_KEY",
        message: "GEMINI_API_KEY not set",
      };
    }

    const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";
    const url = `https://generativelanguage.googleapis.com/v1/models/${encodeURIComponent(model)}:generateContent?key=${key}`;

    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
        }),
      });

      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        return {
          ok: false,
          reason: "HTTP_ERROR",
          status: resp.status,
          body: data,
        };
      }

      const answer =
        data?.candidates?.[0]?.content?.parts?.[0]?.text ||
        data?.candidates?.[0]?.content?.[0]?.text ||
        data?.candidates?.[0]?.content ||
        "";

      return { ok: true, answer: answer || "" };
    } catch (err) {
      return {
        ok: false,
        reason: "EXCEPTION",
        message: String(err?.message || err),
      };
    }
  };

  app.get("/api/health-public", (req, res) => {
    res.json({
      success: true,
      status: "ok",
      service: "solutionhub-api",
      cache: isRedisReady() ? "redis" : "none",
      timestamp: new Date().toISOString(),
    });
  });

  app.get("/api/docs/openapi.json", (req, res) => {
    res.json(buildDocsSpec());
  });

  app.get("/api/docs", (req, res) => {
    res.type("html").send(`<!doctype html>
<html><head><meta charset="utf-8"/><title>SolutionHub API Docs</title>
<style>body{font-family:Arial,sans-serif;padding:24px;background:#0b1020;color:#e5e7eb}a{color:#38bdf8}code{background:#111827;padding:2px 6px;border-radius:6px}</style>
</head><body>
<h1>SolutionHub API Docs</h1>
<p>OpenAPI JSON: <a href="/api/docs/openapi.json">/api/docs/openapi.json</a></p>
<p>Import this JSON in Postman/Insomnia or Swagger Editor.</p>
</body></html>`);
  });

  app.get("/api/profile", async (req, res) => {
    try {
      const email = normalizeEmail(req.query.email);
      if (!email) {
        return res.status(400).json({ error: "Email required" });
      }

      const user = await User.findOne({ email }).select("-password");
      if (user?.role !== "expert" && user) {
        return res.json(user);
      }

      const expert = await Expert.findOne({ email }).select("-password");
      if (!expert) {
        return res.status(404).json({ error: "User not found" });
      }

      const stats = await getRatingStats(Rating, email);
      return res.json({
        ...expert.toObject(),
        avgRating: stats.avgRating,
        ratingsCount: stats.ratingsCount,
      });
    } catch (err) {
      console.error("Profile error:", err);
      return res.status(500).json({ error: "Failed to fetch profile" });
    }
  });

  app.get("/api/messages", async (req, res) => {
    try {
      const room = String(req.query.room || "").trim();
      if (!room) {
        return res.status(400).json({ error: "Room ID required" });
      }

      const messages = await Message.find({ room }).sort({ createdAt: 1 }).limit(100);
      return res.json(messages);
    } catch (err) {
      console.error("Error fetching messages:", err);
      return res.status(500).json({ error: "Failed to fetch messages" });
    }
  });

  app.get("/api/conversations", async (req, res) => {
    try {
      const email = normalizeEmail(req.query.email);
      if (!email) {
        return res.status(400).json({ error: "Email required" });
      }

      const messages = await Message.find({
        room: { $regex: email },
      }).sort({ createdAt: -1 });

      const roomMap = {};
      for (const message of messages) {
        if (roomMap[message.room]) {
          continue;
        }

        roomMap[message.room] = {
          room: message.room,
          lastMessage: buildConversationPreview(message),
          lastMessageTime: message.createdAt,
          otherEmail: String(message.room || "")
            .split("_")
            .find((entry) => entry !== email),
        };
      }

      return res.json(Object.values(roomMap));
    } catch (err) {
      console.error("Error fetching conversations:", err);
      return res.status(500).json({ error: "Failed to fetch conversations" });
    }
  });

  app.get("/api/experts", async (req, res) => {
    try {
      const status = String(req.query.status || "approved");
      const field = String(req.query.field || "");
      const cacheKey = `experts:${JSON.stringify({ status, field })}`;
      const cached = await getCacheJson(cacheKey);
      if (cached) {
        return res.json(cached);
      }

      const filter = {};
      if (status !== "all") {
        filter.status = status;
      }
      if (field && field !== "all") {
        filter.field = new RegExp(field, "i");
      }

      const experts = await Expert.find(filter).select("-password").sort({ experience: -1, createdAt: -1 });
      const ratingStats = await getRatingStatsBatch(
        Rating,
        experts.map((expert) => expert.email)
      );

      const payload = experts.map((expert) => {
        const info = ratingStats.get(normalizeEmail(expert.email)) || {
          avgRating: 0,
          ratingsCount: 0,
        };

        return {
          ...expert.toObject(),
          avgRating: info.avgRating,
          ratingsCount: info.ratingsCount,
        };
      });

      await setCacheJson(cacheKey, payload, cacheExpertsTtlSec);
      return res.json(payload);
    } catch (err) {
      console.error("EXPERTS ERROR:", err);
      return res.status(500).json({ error: "Failed to fetch experts" });
    }
  });

  app.get("/api/public-home-data", async (req, res) => {
    try {
      const cacheKey = "home:public-data";
      const cached = await getCacheJson(cacheKey);
      if (cached) {
        return res.json(cached);
      }

      const palette = ["#22d3ee", "#34d399", "#fbbf24", "#a78bfa"];
      const [approvedExperts, paidSessions, totalMessages, avgRatingAgg, expertsRaw, recentPayments] =
        await Promise.all([
          Expert.countDocuments({ status: "approved" }),
          Payment.countDocuments({ status: "paid", verified: true }),
          Message.countDocuments({}),
          Rating.aggregate([{ $group: { _id: null, avgScore: { $avg: "$score" } } }]),
          Expert.find({ status: "approved" })
            .select("name field experience email")
            .sort({ experience: -1, createdAt: -1 })
            .lean(),
          Payment.find({ status: "paid", verified: true })
            .sort({ createdAt: -1 })
            .limit(5)
            .select("clientName clientEmail expertField createdAt")
            .lean(),
        ]);

      const expertEmails = expertsRaw.map((expert) => normalizeEmail(expert.email)).filter(Boolean);
      const [ratingsByExpert, sessionsByExpert] = await Promise.all([
        Rating.aggregate([
          { $match: { expertEmail: { $in: expertEmails } } },
          { $group: { _id: "$expertEmail", avgRating: { $avg: "$score" }, ratingsCount: { $sum: 1 } } },
        ]),
        Payment.aggregate([
          { $match: { status: "paid", verified: true, expertEmail: { $in: expertEmails } } },
          { $group: { _id: "$expertEmail", sessions: { $sum: 1 } } },
        ]),
      ]);

      const ratingMap = new Map(
        ratingsByExpert.map((entry) => [
          normalizeEmail(entry._id),
          {
            avg: Number(entry.avgRating || 0),
            count: Number(entry.ratingsCount || 0),
          },
        ])
      );
      const sessionsMap = new Map(
        sessionsByExpert.map((entry) => [normalizeEmail(entry._id), Number(entry.sessions || 0)])
      );

      const experts = expertsRaw
        .map((expert, index) => {
          const email = normalizeEmail(expert.email);
          const ratingInfo = ratingMap.get(email) || { avg: 0, count: 0 };
          const sessions = sessionsMap.get(email) || 0;
          const expYears = Number(expert.experience || 0);

          return {
            name: expert.name || "Expert",
            domain: String(expert.field || "General Consulting"),
            exp: `${expYears}+ yrs`,
            sessions,
            tag:
              ratingInfo.avg >= 4.7
                ? "Top rated"
                : sessions >= 20
                  ? "Active expert"
                  : "Verified expert",
            color: palette[index % palette.length],
            initial: initials(expert.name),
            score: ratingInfo.avg,
          };
        })
        .sort((left, right) => right.score - left.score || right.sessions - left.sessions)
        .slice(0, 4)
        .map(({ score, ...expert }) => expert);

      const activityIcons = ["target", "briefcase", "chart", "check", "rocket"];
      const activity = recentPayments.map((payment, index) => {
        const who = payment.clientName || (payment.clientEmail ? payment.clientEmail.split("@")[0] : "Client");
        const field = String(payment.expertField || "expert");

        return {
          icon: activityIcons[index % activityIcons.length],
          text: `${who} booked a ${field} session`,
          time: timeAgo(payment.createdAt),
        };
      });

      const avgScore = Number(avgRatingAgg?.[0]?.avgScore || 0);
      const payload = {
        stats: {
          approvedExperts,
          sessionsCompleted: paidSessions,
          decisionsMade: totalMessages,
          clientSatisfaction: avgScore > 0 ? Math.round((avgScore / 5) * 100) : 97,
        },
        experts,
        activity,
      };

      await setCacheJson(cacheKey, payload, cacheHomeTtlSec);
      return res.json(payload);
    } catch (err) {
      console.error("PUBLIC HOME DATA ERROR:", err);
      return res.status(500).json({ error: "Failed to fetch home data" });
    }
  });

  app.post("/api/ratings", authMiddleware, async (req, res) => {
    try {
      if (req.user?.role !== "client") {
        return res.status(403).json({ error: "Only clients can submit ratings" });
      }

      const clientEmail = normalizeEmail(req.user.email);
      const expertEmail = normalizeEmail(req.body.expertEmail);
      const score = Number(req.body.score);
      const review = String(req.body.review || "").trim().slice(0, 500);
      const room = String(req.body.room || "");

      if (!expertEmail || !Number.isFinite(score) || score < 1 || score > 5) {
        return res.status(400).json({ error: "Valid expertEmail and score (1-5) are required" });
      }

      const expert = await Expert.findOne({ email: expertEmail }).select("email");
      if (!expert) {
        return res.status(404).json({ error: "Expert not found" });
      }

      const rating = await Rating.findOneAndUpdate(
        { expertEmail, clientEmail },
        { $set: { score, review, room } },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );

      return res.json({ success: true, rating });
    } catch (err) {
      console.error("Rating save error:", err);
      return res.status(500).json({ error: "Failed to save rating" });
    }
  });

  app.get("/api/ratings/my", authMiddleware, async (req, res) => {
    try {
      const clientEmail = normalizeEmail(req.user.email);
      const expertEmail = normalizeEmail(req.query.expertEmail);
      if (!expertEmail) {
        return res.status(400).json({ error: "expertEmail is required" });
      }

      const rating = await Rating.findOne({ clientEmail, expertEmail }).lean();
      return res.json({ success: true, rating: rating || null });
    } catch (err) {
      console.error("Rating fetch error:", err);
      return res.status(500).json({ error: "Failed to fetch rating" });
    }
  });

  app.get("/api/ai/debug", (req, res) => {
    res.json({
      hasKey: Boolean(process.env.GEMINI_API_KEY),
      model: process.env.GEMINI_MODEL || "gemini-2.5-flash",
      base: "v1",
    });
  });

  app.post("/api/ai/ask", async (req, res) => {
    try {
      const prompt =
        (req.body && (req.body.prompt || req.body.input || req.body.text)) || "";
      if (!String(prompt).trim()) {
        return res.status(400).json({ error: "Prompt required" });
      }

      const result = await callGemini(prompt);
      if (result.ok && result.answer) {
        return res.json({ answer: result.answer });
      }

      console.warn("Gemini failure:", result);
      return res.json({
        answer:
          "Our AI service is temporarily overloaded or unavailable, but your question reached the server. Please try again later or talk to a human expert.",
        meta: result,
      });
    } catch (err) {
      console.error("AI route error:", err);
      return res.json({
        answer:
          "Something went wrong inside the AI route, but your request reached the server. You can still talk to a human expert.",
      });
    }
  });

  /**
   * Help/Guide endpoint - helps users understand how to use the app
   * POST /api/help - Returns guide based on user's question
   */
  app.post("/api/help", async (req, res) => {
    try {
      const userQuestion =
        (req.body && (req.body.question || req.body.prompt || req.body.text)) || "";

      // If no question, return main features overview
      if (!String(userQuestion).trim()) {
        const helpText = formatGuide(null);
        return res.json({ answer: helpText });
      }

      // Find relevant guide section based on user's question
      const { getRelevantGuide } = require("../utils/app-guide.cjs");
      const relevantGuide = getRelevantGuide(userQuestion);
      const formattedHelp = formatGuide(relevantGuide);

      return res.json({ answer: formattedHelp });
    } catch (err) {
      console.error("Help route error:", err);
      return res.json({
        answer:
          "Help service encountered an issue. Please try again or contact support@solvenut.com",
      });
    }
  });
};

module.exports = {
  registerPublicRoutes,
};
