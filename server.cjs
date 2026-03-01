// server.cjs
require("dotenv").config();

const express = require("express");
const http = require("http");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
// NOTE: Node 18+ has global fetch. If you run older Node, install node-fetch and uncomment:
// const fetch = require("node-fetch");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const { Server } = require("socket.io");
const Razorpay = require("razorpay");
const crypto = require("crypto");

/* ============================================================
   BASIC SETUP
   ============================================================ */
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "solutionhub_secret";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "your-super-secret-admin-key-2025-CHANGE-THIS";

/* ============================================================
   ENV DEBUG
   ============================================================ */
console.log("🔍 ENV CHECK:");
console.log("RAZORPAY_KEY_ID:", process.env.RAZORPAY_KEY_ID ? process.env.RAZORPAY_KEY_ID.substring(0, 15) + "..." : "❌ MISSING");
console.log("RAZORPAY_KEY_SECRET:", process.env.RAZORPAY_KEY_SECRET ? "✅ LOADED" : "❌ MISSING");
console.log("MONGO_URI:", process.env.MONGO_URI ? "✅ LOADED" : "❌ MISSING");
console.log("JWT_SECRET:", process.env.JWT_SECRET ? "✅ LOADED" : "❌ MISSING");
console.log("GEMINI_API_KEY:", process.env.GEMINI_API_KEY ? "✅ LOADED" : "❌ MISSING");
console.log("GEMINI_MODEL (optional):", process.env.GEMINI_MODEL || "(default: gemini-1.5-flash)");

/* ============================================================
   RAZORPAY SETUP
   ============================================================ */
let razorpay = null;
try {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    throw new Error("Razorpay keys missing in .env");
  }

  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID.trim(),
    key_secret: process.env.RAZORPAY_KEY_SECRET.trim()
  });

  console.log("💳 Razorpay initialized with key:", process.env.RAZORPAY_KEY_ID.substring(0, 15) + "...");
  (async () => {
    try {
      const testOrder = await razorpay.orders.create({
        amount: 100,
        currency: "INR",
        receipt: "init_test_" + Date.now()
      });
      console.log("✅ Razorpay test order created:", testOrder.id);
    } catch (e) {
      console.log("⚠️ Razorpay init test failed (can be ignored in dev):", e.message);
    }
  })();
} catch (e) {
  console.error("❌ Razorpay init error:", e.message);
}

/* ============================================================
   ENSURE UPLOAD DIRECTORIES
   ============================================================ */
["uploads", "uploads/resumes", "uploads/photos"].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

/* ============================================================
   MIDDLEWARE
   ============================================================ */
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/* ============================================================
   ADMIN AUTH
   ============================================================ */
const adminAuth = async (req, res, next) => {
  try {
    const adminToken = req.cookies.adminToken ||
      req.headers["x-admin-token"] ||
      req.query.adminToken ||
      req.headers["admin-token"];

    if (!adminToken) {
      console.log(`🚫 ADMIN BLOCKED: No token from ${req.ip} → ${req.originalUrl}`);
      return res.status(401).json({ error: "Admin access required" });
    }
    if (adminToken !== ADMIN_SECRET) {
      console.log(`🚫 ADMIN BLOCKED: Invalid token from ${req.ip}`);
      return res.status(401).json({ error: "Invalid admin credentials" });
    }
    console.log(`🛡️ ADMIN OK: ${req.ip} → ${req.originalUrl}`);
    next();
  } catch (err) {
    console.error("❌ Admin auth error:", err);
    res.status(500).json({ error: "Admin verification failed" });
  }
};

/* ============================================================
   DATABASE
   ============================================================ */
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/solutionhub")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  });

/* ============================================================
   SCHEMAS
   ============================================================ */
const User = mongoose.model("User", new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  role: { type: String, default: "client" }
}));

const Expert = mongoose.model("Expert", new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  field: String,
  experience: Number,
  headline: String,
  summary: String,
  linkedin: String,
  resumePath: String,
  avatar: String,
  role: { type: String, default: "expert" },
  status: { type: String, default: "pending" },
  price: { type: Number, default: 500 }
}, { timestamps: true }));

const Message = mongoose.model("Message", new mongoose.Schema({
  room: String,
  author: String,
  authorRole: String,
  message: String
}, { timestamps: true }));

const Payment = mongoose.model("Payment", new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  paymentId: String,
  signature: String,
  amount: { type: Number, required: true },
  currency: { type: String, default: "INR" },
  status: { type: String, default: "created" },
  clientEmail: { type: String, required: true },
  expertEmail: { type: String, required: true },
  expertField: String,
  clientName: String,
  verified: { type: Boolean, default: false },
  notes: Object
}, { timestamps: true }));

/* ============================================================
   AUTH MIDDLEWARE
   ============================================================ */
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1] ||
      req.query.token ||
      req.headers.token;
    if (!token) return res.status(401).json({ error: "No token provided" });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

/* ============================================================
   ROUTES (client, login, profile, experts etc.)
   (kept the same as your original server)
   ============================================================ */

/* -- register, login, pro-signup, profile, messages, conversations, experts, admin endpoints, payments --
   (I omitted repeating those route blocks here for brevity in this explanation — but in the file you have them
   exactly as before; keep them unchanged.)
*/

/* For clarity: paste your unchanged route code here as in original file.
   (In your repo you already have these; do NOT duplicate or remove them.)
*/

/* ============================================================
   AI: Resilient Gemini REST handler (no SDK, robust fallback)
   ============================================================ */

/**
 * Helper: try generate content with a specific model name.
 * Returns { ok: true, answer } or { ok: false, status, body }
 */
async function tryGenerateWithModel(modelName, prompt) {
  const key = process.env.GEMINI_API_KEY;
  if (!key) return { ok: false, status: 500, body: { error: "GEMINI_API_KEY not set" } };

  const url = `https://generativelanguage.googleapis.com/v1/models/${encodeURIComponent(modelName)}:generateContent?key=${key}`;

  try {
    // Use the v1 request shape — this is tolerant and works for many keys
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        // v1 generateContent minimal payload
        // Some accounts accept "prompt:{text:...}" while others accept "contents:[{parts:[{text:...}]}]"
        // We'll send the "contents" shape (safe).
        contents: [
          {
            parts: [{ text: prompt }]
          }
        ],
        // you can include additional fields like temperature, maxOutputTokens, etc. if desired:
        // temperature: 0.2,
        // maxOutputTokens: 512
      })
    });

    let bodyParsed;
    try {
      bodyParsed = await resp.json();
    } catch (e) {
      bodyParsed = { _raw: await resp.text().catch(() => "(no body)") };
    }

    if (!resp.ok) {
      return { ok: false, status: resp.status, body: bodyParsed };
    }

    // Attempt to extract text from common response shapes
    const answer =
      bodyParsed?.candidates?.[0]?.content?.parts?.[0]?.text ||
      bodyParsed?.candidates?.[0]?.content?.[0]?.text ||
      bodyParsed?.candidates?.[0]?.content ||
      bodyParsed?.output?.[0]?.content?.[0]?.text ||
      bodyParsed?.result?.output?.[0]?.content?.[0]?.text ||
      (typeof bodyParsed === "string" ? bodyParsed : JSON.stringify(bodyParsed).slice(0, 4000));

    return { ok: true, answer, raw: bodyParsed };
  } catch (err) {
    return { ok: false, status: 500, body: { error: String(err && err.message ? err.message : err) } };
  }
}

/**
 * List available models for this API key (helpful for fallback).
 */
async function listModels() {
  const key = process.env.GEMINI_API_KEY;
  if (!key) return { ok: false, error: "GEMINI_API_KEY not set" };

  const url = `https://generativelanguage.googleapis.com/v1/models?key=${key}`;
  try {
    const resp = await fetch(url);
    const json = await resp.json().catch(() => ({ _raw: "non-json response" }));
    if (!resp.ok) return { ok: false, status: resp.status, body: json };
    return { ok: true, models: json.models || [] };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

/**
 * POST /api/ai/ask
 * Body: { prompt: "..." }
 */
app.post("/api/ai/ask", async (req, res) => {
  try {
    const prompt = (req.body && (req.body.prompt || req.body.input || req.body.text)) || "";
    if (!prompt || !String(prompt).trim()) {
      return res.status(400).json({ error: "Missing prompt in request body (expected { prompt: '...' })" });
    }

    if (!process.env.GEMINI_API_KEY) {
      console.error("GEMINI_API_KEY not set");
      return res.status(500).json({ error: "GEMINI_API_KEY not set" });
    }

    // Primary model to try (allow override via env)
    const primaryModel = process.env.GEMINI_MODEL || "gemini-1.5-flash";

    console.log("AI: trying primary model:", primaryModel);
    let result = await tryGenerateWithModel(primaryModel, prompt);

    if (result.ok) {
      console.log("AI: primary model success:", primaryModel);
      return res.json({ answer: result.answer, meta: { model: primaryModel } });
    }

    console.warn("AI: primary model failed:", primaryModel, result.status, result.body);

    // As a fallback, list available models and attempt a gemini-* model
    const listed = await listModels();
    if (!listed.ok) {
      console.error("AI: listModels failed:", listed);
      // return the original failure details for debugging
      return res.status(500).json({ error: "AI generation failed", details: { primary: result, listError: listed } });
    }

    const modelNames = (listed.models || []).map(m => m.name || m.model || "").filter(Boolean);
    console.log("AI: available models count:", modelNames.length);

    // Try to pick the best gemini candidate
    let candidate = modelNames.find(n => /gemini.*flash/i.test(n)) ||
                    modelNames.find(n => /gemini/i.test(n)) ||
                    modelNames[0];

    if (!candidate) {
      return res.status(500).json({
        error: "No usable model found for your API key",
        availableModels: modelNames.slice(0, 50) // limit size
      });
    }

    console.log("AI: trying fallback model:", candidate);
    result = await tryGenerateWithModel(candidate, prompt);

    if (result.ok) {
      console.log("AI: fallback model success:", candidate);
      return res.json({ answer: result.answer, meta: { model: candidate } });
    }

    // If still failed, return helpful debug info
    console.error("AI: fallback also failed:", candidate, result.status, result.body);
    return res.status(500).json({
      error: "AI generation failed",
      primary: { model: primaryModel, status: result.status, details: result.body },
      fallbackAttempted: candidate,
      fallbackDetails: result.body,
      availableModels: modelNames.slice(0, 50)
    });

  } catch (err) {
    console.error("AI generation exception:", err && err.stack ? err.stack : err);
    return res.status(500).json({ error: "AI generation failed", details: String(err.message || err) });
  }
});

/* ============================================================
   SOCKET.IO - LIVE CHAT
   ============================================================ */
const onlineUsers = {};

io.on("connection", (socket) => {
  console.log("🔌 Socket connected:", socket.id);

  socket.on("authenticate", async ({ token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const { email, role, name } = decoded;

      const expert = await Expert.findOne({ email: email.toLowerCase() });
      if (role === "expert" && (!expert || expert.status !== "approved")) {
        socket.emit("auth_error", "Expert not approved yet");
        return;
      }

      onlineUsers[email] = {
        socketId: socket.id,
        name: name || email.split("@")[0],
        role,
        field: expert?.field,
        status: expert?.status || "client",
        connectedAt: new Date()
      };

      console.log("✅ User authenticated:", email, role);
      socket.emit("auth_success", { email, role });
      io.emit("online_users", onlineUsers);
    } catch (err) {
      console.error("❌ Socket auth error:", err.message);
      socket.emit("auth_error", "Invalid token");
    }
  });

  socket.on("user_online", ({ email, name, role }) => {
    onlineUsers[email] = {
      socketId: socket.id,
      name,
      role,
      connectedAt: new Date()
    };
    io.emit("online_users", onlineUsers);
  });

  socket.on("join_private", async (room) => {
    socket.join(room);
    try {
      const history = await Message.find({ room })
        .sort({ createdAt: 1 })
        .limit(50);
      socket.emit("chat_history", history);
    } catch (err) {
      console.error("❌ Error loading chat history:", err);
    }
  });

  socket.on("send_private_message", async (data) => {
    try {
      const msg = await Message.create(data);
      io.to(data.room).emit("receive_message", msg);

      const emails = data.room.split("_");
      emails.forEach(email => {
        if (onlineUsers[email] && onlineUsers[email].socketId) {
          io.to(onlineUsers[email].socketId).emit("new_message_notification", {
            room: data.room,
            message: msg
          });
        }
      });
    } catch (err) {
      console.error("❌ Message save failed:", err);
      socket.emit("error", "Message failed");
    }
  });

  socket.on("disconnect", () => {
    for (let email in onlineUsers) {
      if (onlineUsers[email].socketId === socket.id) {
        delete onlineUsers[email];
        io.emit("online_users", onlineUsers);
        break;
      }
    }
  });
});

/* ============================================================
   START SERVER
   ============================================================ */
server.listen(PORT, () => {
  console.log(`\n🚀 ============================================`);
  console.log(`🚀 SolutionHub v9.1 LIVE - FULL SYSTEM 🎉`);
  console.log(`🚀 ============================================`);
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`💬 Socket.IO: Ready`);
  console.log(`💳 Razorpay: ${razorpay ? "Enabled ✅" : "DISABLED ❌"}`);
  console.log(`🤖 AI: ${process.env.GEMINI_API_KEY ? "Enabled ✅" : "Disabled"}`);
  console.log(`🔐 Admin Login: http://localhost:${PORT}/admin-login.html`);
  console.log(`🛡️ Admin Dashboard: http://localhost:${PORT}/admin.html`);
  console.log(`✅ Public Experts: http://localhost:${PORT}/experts.html`);
  console.log(`💬 Chat System: FULLY ENABLED`);
  console.log(`💰 Payment System: ACTIVE (if Razorpay enabled)`);
  console.log(`👥 Expert Profiles: ENHANCED`);
  console.log(`🔑 Admin Secret: ${String(ADMIN_SECRET || "").substring(0, 10)}...`);
  console.log(`🔑 Razorpay Key: ${(process.env.RAZORPAY_KEY_ID || "NOT_SET").substring(0, 15)}...`);
  console.log(`🚀 ============================================\n`);
});