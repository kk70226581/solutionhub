require("dotenv").config();

const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { rateLimit } = require("express-rate-limit");
const { Server } = require("socket.io");
const Razorpay = require("razorpay");
const QRCode = require("qrcode");

const {
  normalizeEmail,
  initials,
  timeAgo,
} = require("./utils/shared-helpers.cjs");
const {
  getRatingStats,
  getRatingStatsBatch,
} = require("./utils/db-query-helpers.cjs");
const { sendPasswordResetEmail: createEmailService } = require("./utils/password-reset-email-service.cjs");
const {
  getClientExpertChatAccess: getClientExpertChatAccessHelper,
  verifyRazorpaySignature,
  handleRazorpayWebhookEvent,
} = require("./utils/payment-access-helpers.cjs");
const { authMiddleware, adminAuth } = require("./middleware/auth-middleware.cjs");
const { verifyTOTP, getAdmin2FASecret } = require("./middleware/admin-totp.cjs");
const {
  cacheGetJson,
  cacheSetJson,
} = require("./middleware/cache-middleware.cjs");
const { ensureUploadDirs, upload, fileToDataUrl } = require("./config/upload-config.cjs");
const {
  getOnlineUsersSnapshot,
  setRedisPresence,
  clearRedisPresenceSocket,
  addLocalOnlineUser,
  removeLocalOnlineUser,
} = require("./socket/presence-store.cjs");
const { registerSocketHandlers } = require("./socket/realtime-handlers.cjs");
const { connectDatabase, User, Expert, Message, Payment, Rating, AdminSecurity } = require("./models/app-models.cjs");
const { registerAuthRoutes } = require("./routes/auth-routes.cjs");
const { registerPublicRoutes } = require("./routes/public-routes.cjs");
const { registerAdminPaymentRoutes } = require("./routes/admin-payment-routes.cjs");
const { registerAIExpertRoutes } = require("./routes/ai-expert-routes.cjs");
const { AIConversation, AIMessage, AIUserFeedback } = require("./models/app-models.cjs");

const fetch = (...args) =>
  import("node-fetch").then(({ default: nodeFetch }) => nodeFetch(...args));

const app = express();
// Render terminates HTTPS at one reverse proxy before forwarding to this app.
// Trust that hop so express-rate-limit can safely use the real client IP.
app.set("trust proxy", 1);
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "solutionhub_secret";
const PASSWORD_SALT_ROUNDS = (() => {
  const value = Number(process.env.PASSWORD_SALT_ROUNDS || 12);
  return Number.isFinite(value) && value >= 10 ? Math.floor(value) : 12;
})();
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const RATE_LIMIT_MAX_GLOBAL = Number(process.env.RATE_LIMIT_MAX_GLOBAL || 300);
const RATE_LIMIT_MAX_AUTH = Number(process.env.RATE_LIMIT_MAX_AUTH || 20);
const REDIS_URL = String(process.env.REDIS_URL || "").trim();
const CACHE_EXPERTS_TTL_SEC = Number(process.env.CACHE_EXPERTS_TTL_SEC || 120);
const CACHE_HOME_TTL_SEC = Number(process.env.CACHE_HOME_TTL_SEC || 60);
const GOOGLE_CLIENT_ID = String(process.env.GOOGLE_CLIENT_ID || "").trim();
const ADMIN_ALLOWED_EMAILS = String(process.env.ADMIN_ALLOWED_EMAILS || "")
  .split(",")
  .map((entry) => entry.trim().toLowerCase())
  .filter(Boolean);
const EMAIL_PROVIDER = String(process.env.EMAIL_PROVIDER || "none").trim().toLowerCase();
const FRONTEND_BASE_URL =
  process.env.FRONTEND_URL || process.env.PUBLIC_APP_URL || "http://localhost:5173";
const FRONTEND_ROUTER_MODE = String(process.env.FRONTEND_ROUTER_MODE || "history")
  .trim()
  .toLowerCase();

const PASSWORD_POLICY = Object.freeze({
  minLength: 8,
  maxLength: 64,
  requiresUpper: true,
  requiresLower: true,
  requiresNumber: true,
  requiresSpecial: true,
});

const validatePasswordStrength = (passwordRaw) => {
  const password = String(passwordRaw || "");
  if (password.length < PASSWORD_POLICY.minLength) {
    return `Password must be at least ${PASSWORD_POLICY.minLength} characters`;
  }
  if (password.length > PASSWORD_POLICY.maxLength) {
    return `Password must be at most ${PASSWORD_POLICY.maxLength} characters`;
  }
  if (PASSWORD_POLICY.requiresUpper && !/[A-Z]/.test(password)) {
    return "Password must include at least one uppercase letter";
  }
  if (PASSWORD_POLICY.requiresLower && !/[a-z]/.test(password)) {
    return "Password must include at least one lowercase letter";
  }
  if (PASSWORD_POLICY.requiresNumber && !/[0-9]/.test(password)) {
    return "Password must include at least one number";
  }
  if (
    PASSWORD_POLICY.requiresSpecial &&
    !/[!@#$%^&*()_\-+=[\]{};:'",.<>/?\\|`~]/.test(password)
  ) {
    return "Password must include at least one special character";
  }
  return "";
};

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "rzp_test_YOUR_KEY_ID",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "YOUR_KEY_SECRET",
});
const sendPasswordResetEmail = createEmailService(fetch);

let redisClient = null;
let redisReady = false;

const onlineUsers = {};
const localUserSockets = new Map();

const initRedisCache = async () => {
  if (!REDIS_URL) {
    return;
  }

  try {
    const { createClient } = require("redis");
    redisClient = createClient({ url: REDIS_URL });
    redisClient.on("error", (err) => {
      redisReady = false;
      console.warn("Redis error:", err.message);
    });
    await redisClient.connect();
    redisReady = true;
    console.log("Redis cache connected");
  } catch (err) {
    redisClient = null;
    redisReady = false;
    console.warn("Redis cache disabled:", err.message);
  }
};

const getCacheJson = (key) => cacheGetJson(redisClient, redisReady, key);
const setCacheJson = (key, value, ttlSec) =>
  cacheSetJson(redisClient, redisReady, key, value, ttlSec);
const getOnlineUsersSnapshotLocal = () =>
  getOnlineUsersSnapshot(redisClient, redisReady, onlineUsers);
const setRedisPresenceLocal = (email, presence) =>
  setRedisPresence(redisClient, redisReady, email, presence);
const clearRedisPresenceSocketLocal = (email, socketId) =>
  clearRedisPresenceSocket(redisClient, redisReady, email, socketId);
const addLocalOnlineUserLocal = (email, presence) =>
  addLocalOnlineUser(email, presence, localUserSockets, onlineUsers);
const removeLocalOnlineUserLocal = (email, socketId) =>
  removeLocalOnlineUser(email, socketId, localUserSockets, onlineUsers);
// Each limiter receives its own store. `identifier` makes the standard RateLimit
// response header distinguish global, auth, and AI limits for API consumers.
const createRateLimiter = ({ windowMs, max, keyPrefix }) =>
  rateLimit({
    windowMs,
    limit: max,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    identifier: keyPrefix,
    message: { error: "Too many requests. Please try again later." },
  });
const getClientExpertChatAccess = (clientEmail, expertEmail) =>
  getClientExpertChatAccessHelper(Payment, Message, clientEmail, expertEmail);

const emitOnlineUsersSnapshot = async () => {
  const snapshot = await getOnlineUsersSnapshotLocal();
  io.emit("online_users", snapshot);
};

const emitUserPresence = async (email, online) => {
  io.emit("user_online", {
    email: normalizeEmail(email),
    online: Boolean(online),
  });
  await emitOnlineUsersSnapshot();
};

const authRateLimiter = createRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX_AUTH,
  keyPrefix: "auth",
});

ensureUploadDirs();

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(
  "/api",
  createRateLimiter({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max: RATE_LIMIT_MAX_GLOBAL,
    keyPrefix: "global",
  })
);

app.get("/admin-login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-login.html"));
});

app.get("/admin.html", adminAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

registerAuthRoutes(app, {
  bcrypt,
  jwt,
  fetch,
  upload,
  fileToDataUrl,
  User,
  Expert,
  AdminSecurity,
  authRateLimiter,
  authMiddleware,
  validatePasswordStrength,
  passwordSaltRounds: PASSWORD_SALT_ROUNDS,
  passwordPolicy: PASSWORD_POLICY,
  jwtSecret: JWT_SECRET,
  googleClientId: GOOGLE_CLIENT_ID,
  adminAllowedEmails: ADMIN_ALLOWED_EMAILS,
  getAdmin2FASecret,
  verifyTOTP,
  QRCode,
  sendPasswordResetEmail,
  emailProvider: EMAIL_PROVIDER,
  frontendBaseUrl: FRONTEND_BASE_URL,
  frontendRouterMode: FRONTEND_ROUTER_MODE,
});

registerPublicRoutes(app, {
  fetch,
  port: PORT,
  isRedisReady: () => redisReady,
  cacheExpertsTtlSec: CACHE_EXPERTS_TTL_SEC,
  cacheHomeTtlSec: CACHE_HOME_TTL_SEC,
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
});

registerAdminPaymentRoutes(app, {
  adminAuth,
  authMiddleware,
  razorpay,
  Expert,
  Payment,
  isRedisReady: () => redisReady,
  getOnlineUsersSnapshot: getOnlineUsersSnapshotLocal,
  getClientExpertChatAccess,
  verifyRazorpaySignature,
  handleRazorpayWebhookEvent,
});

registerAIExpertRoutes(app, {
  authMiddleware,
  createRateLimiter,
  AIConversation,
  AIMessage,
  AIUserFeedback,
  Expert,
  normalizeEmail,
});

const boot = async () => {
  await initRedisCache();
  await connectDatabase(process.env.MONGO_URI || "mongodb://localhost:27017/solutionhub")
    .then(() => {
      if (String(process.env.NODE_ENV || "").toLowerCase() !== "test") {
        console.log("MongoDB connected");
      }
    })
    .catch((err) => {
      console.error("MongoDB error:", err);
      process.exit(1);
    });
};

const bootPromise = boot();

io.on("connection", (socket) => {
  registerSocketHandlers(
    io,
    socket,
    { Expert, Message, Payment },
    onlineUsers,
    addLocalOnlineUserLocal,
    removeLocalOnlineUserLocal,
    emitUserPresence,
    {
      setRedisPresence: setRedisPresenceLocal,
      clearRedisPresenceSocket: clearRedisPresenceSocketLocal,
    }
  );
});

if (require.main === module) {
  bootPromise.then(() => {
    server.listen(PORT, () => {
      console.log("SolutionHub backend live");
      console.log(`Server: http://localhost:${PORT}`);
      console.log(`Admin Login: http://localhost:${PORT}/admin-login.html`);
      console.log(`Admin Dashboard: http://localhost:${PORT}/admin.html`);
      console.log(`API Docs: http://localhost:${PORT}/api/docs`);
    });
  });
}

module.exports = {
  app,
  server,
  bootPromise,
};
