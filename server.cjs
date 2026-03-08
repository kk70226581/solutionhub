/**
 * ============================================================
 * SOLUTIONHUB CORE v9.0 – STABLE BACKEND (RAZORPAY + GEMINI v1) 💳✅
 * ============================================================
 */

require("dotenv").config();

const express = require("express");
const http = require("http");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const { Server } = require("socket.io");
const Razorpay = require("razorpay");
const crypto = require("crypto");

// node-fetch v3 in CommonJS
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

/* ============================================================
   BASIC SETUP
============================================================ */
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "solutionhub_secret";
const PASSWORD_SALT_ROUNDS = (() => {
  const n = Number(process.env.PASSWORD_SALT_ROUNDS || 12);
  return Number.isFinite(n) && n >= 10 ? Math.floor(n) : 12;
})();
const ADMIN_SECRET =
  process.env.ADMIN_SECRET || "your-super-secret-admin-key-2025-CHANGE-THIS";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const ADMIN_ALLOWED_EMAILS = String(process.env.ADMIN_ALLOWED_EMAILS || "")
  .split(",")
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean);
const ADMIN_2FA_SECRET = String(process.env.ADMIN_2FA_SECRET || "").trim();
const ADMIN_2FA_SECRETS = (() => {
  try {
    const raw = process.env.ADMIN_2FA_SECRETS || "{}";
    const obj = JSON.parse(raw);
    const out = {};
    Object.keys(obj || {}).forEach((k) => {
      out[String(k).toLowerCase()] = String(obj[k] || "").trim();
    });
    return out;
  } catch {
    return {};
  }
})();

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

const EMAIL_PROVIDER = String(process.env.EMAIL_PROVIDER || "none")
  .trim()
  .toLowerCase();
const FRONTEND_ROUTER_MODE = String(process.env.FRONTEND_ROUTER_MODE || "hash")
  .trim()
  .toLowerCase();
const EMAIL_FROM = String(process.env.EMAIL_FROM || "").trim();
const RESEND_API_KEY = String(process.env.RESEND_API_KEY || "").trim();
const SENDGRID_API_KEY = String(process.env.SENDGRID_API_KEY || "").trim();

const sendPasswordResetEmail = async ({ toEmail, resetLink }) => {
  const subject = "Reset your Solvenut password";
  const text = [
    "We received a request to reset your Solvenut password.",
    "",
    "Use the link below to reset it (valid for 15 minutes):",
    resetLink,
    "",
    "If you did not request this, you can ignore this email.",
  ].join("\n");
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111827">
      <h2 style="margin:0 0 12px">Reset your Solvenut password</h2>
      <p>We received a request to reset your Solvenut password.</p>
      <p>
        <a href="${resetLink}" style="display:inline-block;padding:10px 14px;background:#0ea5e9;color:#fff;text-decoration:none;border-radius:8px">
          Reset Password
        </a>
      </p>
      <p style="font-size:12px;color:#6b7280">This link expires in 15 minutes.</p>
      <p style="font-size:12px;color:#6b7280">If you did not request this, you can ignore this email.</p>
    </div>
  `;

  if (EMAIL_PROVIDER === "none") {
    return { ok: false, error: "EMAIL_PROVIDER is not configured" };
  }
  if (!EMAIL_FROM) {
    return { ok: false, error: "EMAIL_FROM is missing" };
  }

  if (EMAIL_PROVIDER === "resend") {
    if (!RESEND_API_KEY) {
      return { ok: false, error: "RESEND_API_KEY is missing" };
    }
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: [toEmail],
        subject,
        html,
        text,
      }),
    });
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      return { ok: false, error: `Resend error (${r.status}): ${body}` };
    }
    return { ok: true };
  }

  if (EMAIL_PROVIDER === "sendgrid") {
    if (!SENDGRID_API_KEY) {
      return { ok: false, error: "SENDGRID_API_KEY is missing" };
    }
    const r = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${SENDGRID_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: toEmail }] }],
        from: { email: EMAIL_FROM },
        subject,
        content: [
          { type: "text/plain", value: text },
          { type: "text/html", value: html },
        ],
      }),
    });
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      return { ok: false, error: `SendGrid error (${r.status}): ${body}` };
    }
    return { ok: true };
  }

  return { ok: false, error: `Unsupported EMAIL_PROVIDER: ${EMAIL_PROVIDER}` };
};

/* ============================================================
   ENV DEBUG
============================================================ */
console.log("🔍 ENV CHECK:");
console.log(
  "RAZORPAY_KEY_ID:",
  (process.env.RAZORPAY_KEY_ID || "MISSING").substring(0, 15) + "..."
);
console.log(
  "RAZORPAY_KEY_SECRET:",
  process.env.RAZORPAY_KEY_SECRET ? "✅ LOADED" : "❌ MISSING"
);
console.log("MONGO_URI:", process.env.MONGO_URI ? "✅ LOADED" : "❌ MISSING");
console.log(
  "GEMINI_API_KEY:",
  process.env.GEMINI_API_KEY ? "✅ LOADED" : "❌ MISSING"
);

/* ============================================================
   RAZORPAY SETUP
============================================================ */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || "rzp_test_YOUR_KEY_ID",
  key_secret: process.env.RAZORPAY_KEY_SECRET || "YOUR_KEY_SECRET",
});

console.log(
  "💳 Razorpay initialized with key:",
  (process.env.RAZORPAY_KEY_ID || "TEST_KEY").substring(0, 15) + "..."
);

/* ============================================================
   ENSURE UPLOAD DIRECTORIES
============================================================ */
["uploads", "uploads/resumes", "uploads/photos"].forEach((dir) => {
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
   ADMIN SECURITY MIDDLEWARE
============================================================ */
const adminAuth = async (req, res, next) => {
  try {
    const legacyAdminToken =
      req.cookies.adminToken ||
      req.headers["x-admin-token"] ||
      req.query.adminToken ||
      req.headers["admin-token"];
    const bearer = req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.split(" ")[1]
      : null;
    const adminSessionToken =
      bearer ||
      req.headers["x-admin-session"] ||
      req.cookies.adminSession;

    // Backward-compatible legacy secret token path.
    if (legacyAdminToken && legacyAdminToken === ADMIN_SECRET) {
      req.admin = { email: "legacy-admin@local", method: "legacy-secret" };
      return next();
    }

    if (!adminSessionToken) {
      console.log(
        `🚫 ADMIN BLOCKED: No token from ${req.ip} → ${req.originalUrl}`
      );
      return res.status(401).json({ error: "Admin access required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(adminSessionToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid admin session" });
    }

    const email = String(decoded?.email || "").toLowerCase();
    if (decoded?.type !== "admin" || !email) {
      return res.status(401).json({ error: "Invalid admin credentials" });
    }
    if (
      ADMIN_ALLOWED_EMAILS.length > 0 &&
      !ADMIN_ALLOWED_EMAILS.includes(email)
    ) {
      return res.status(403).json({ error: "Admin email not authorized" });
    }

    console.log(`🛡️ ADMIN OK: ${req.ip} → ${req.originalUrl}`);
    req.admin = { email, method: "google-2fa" };
    next();
  } catch (err) {
    console.error("❌ Admin auth error:", err);
    res.status(500).json({ error: "Admin verification failed" });
  }
};

const base32ToBuffer = (base32) => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(base32 || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const c of clean) {
    const v = alphabet.indexOf(c);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
};

const verifyTOTP = (codeRaw, base32Secret, window = 1) => {
  const code = String(codeRaw || "").replace(/\D/g, "");
  if (code.length !== 6 || !base32Secret) return false;
  const key = base32ToBuffer(base32Secret);
  if (!key.length) return false;

  const step = 30;
  const now = Math.floor(Date.now() / 1000);

  const hotp = (counter) => {
    const ctr = Buffer.alloc(8);
    ctr.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    ctr.writeUInt32BE(counter % 0x100000000, 4);
    const hmac = crypto.createHmac("sha1", key).update(ctr).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    return String(binary % 1000000).padStart(6, "0");
  };

  const counterNow = Math.floor(now / step);
  for (let i = -window; i <= window; i++) {
    if (hotp(counterNow + i) === code) return true;
  }
  return false;
};

const getAdmin2FASecret = (email) => {
  const key = String(email || "").toLowerCase();
  return ADMIN_2FA_SECRETS[key] || ADMIN_2FA_SECRET;
};

/* ============================================================
   DATABASE
============================================================ */
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/solutionhub")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  });

/* ============================================================
   SCHEMAS
============================================================ */
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    name: String,
    email: { type: String, unique: true, lowercase: true },
    password: String,
    role: { type: String, default: "client" },
    resetPasswordTokenHash: String,
    resetPasswordExpires: Date,
  })
);

const Expert = mongoose.model(
  "Expert",
  new mongoose.Schema(
    {
      name: String,
      email: { type: String, unique: true, lowercase: true },
      password: String,
      field: String,
      experience: Number,
      headline: String,
      summary: String,
      location: String,
      linkedin: String,
      resumePath: String,
      avatar: String,
      role: { type: String, default: "expert" },
      status: { type: String, default: "pending" },
      price: { type: Number, default: 500 },
      resetPasswordTokenHash: String,
      resetPasswordExpires: Date,
    },
    { timestamps: true }
  )
);

const Message = mongoose.model(
  "Message",
  new mongoose.Schema(
    {
      room: String,
      author: String,
      authorRole: String,
      message: String,
      messageType: { type: String, enum: ["text", "image"], default: "text" },
      imageUrl: String,
      imageName: String,
    },
    { timestamps: true }
  )
);

const Payment = mongoose.model(
  "Payment",
  new mongoose.Schema(
    {
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
      notes: Object,
    },
    { timestamps: true }
  )
);

const Rating = mongoose.model(
  "Rating",
  new mongoose.Schema(
    {
      expertEmail: { type: String, required: true, lowercase: true, index: true },
      clientEmail: { type: String, required: true, lowercase: true, index: true },
      room: { type: String, default: "" },
      score: { type: Number, required: true, min: 1, max: 5 },
      review: { type: String, default: "" },
    },
    { timestamps: true }
  )
);

const CHAT_ACCESS_HOURS = 24;
const CHAT_ACCESS_MS = CHAT_ACCESS_HOURS * 60 * 60 * 1000;

async function getClientExpertChatAccess(clientEmailRaw, expertEmailRaw) {
  const clientEmail = String(clientEmailRaw || "").toLowerCase();
  const expertEmail = String(expertEmailRaw || "").toLowerCase();

  if (!clientEmail || !expertEmail) {
    return {
      hasPaid: false,
      hasAccess: false,
      reason: "missing_emails",
      payment: null,
      firstExpertReplyAt: null,
      accessUntil: null,
      hoursLeft: 0,
    };
  }

  const payment = await Payment.findOne({
    clientEmail,
    expertEmail,
    status: "paid",
    verified: true,
  }).sort({ createdAt: -1 });

  if (!payment) {
    return {
      hasPaid: false,
      hasAccess: false,
      reason: "payment_required",
      payment: null,
      firstExpertReplyAt: null,
      accessUntil: null,
      hoursLeft: 0,
    };
  }

  const room = [clientEmail, expertEmail].sort().join("_");
  const firstExpertReply = await Message.findOne({
    room,
    authorRole: "expert",
    createdAt: { $gte: payment.createdAt },
  }).sort({ createdAt: 1 });

  if (!firstExpertReply) {
    return {
      hasPaid: true,
      hasAccess: true,
      reason: "awaiting_first_expert_reply",
      payment,
      firstExpertReplyAt: null,
      accessUntil: null,
      hoursLeft: CHAT_ACCESS_HOURS,
    };
  }

  const firstReplyAt = new Date(firstExpertReply.createdAt);
  const accessUntilDate = new Date(firstReplyAt.getTime() + CHAT_ACCESS_MS);
  const now = Date.now();
  const remainingMs = accessUntilDate.getTime() - now;
  const hasAccess = remainingMs > 0;

  return {
    hasPaid: true,
    hasAccess,
    reason: hasAccess ? "within_24h_window" : "window_expired",
    payment,
    firstExpertReplyAt: firstReplyAt.toISOString(),
    accessUntil: accessUntilDate.toISOString(),
    hoursLeft: hasAccess ? Number((remainingMs / (60 * 60 * 1000)).toFixed(2)) : 0,
  };
}

/* ============================================================
   AUTH MIDDLEWARE
============================================================ */
const authMiddleware = async (req, res, next) => {
  try {
    const token =
      req.headers.authorization?.split(" ")[1] ||
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
   ADMIN PAGES
============================================================ */
app.get("/admin-login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-login.html"));
});

app.get("/admin.html", adminAuth, (req, res) => {
  console.log(`🛡️ ADMIN DASHBOARD ACCESS: ${req.ip}`);
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

/* ============================================================
   ROUTES - CLIENT REGISTER
============================================================ */
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields required" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const passwordErr = validatePasswordStrength(password);
    if (passwordErr) {
      return res.status(400).json({ error: passwordErr });
    }

    const hash = await bcrypt.hash(password, PASSWORD_SALT_ROUNDS);
    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hash,
    });

    console.log("✅ Client registered:", email);
    res.json({
      success: true,
      user: {
        name: newUser.name,
        email: newUser.email,
        role: newUser.role || "client",
      },
    });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

/* ============================================================
   ROUTES - LOGIN
============================================================ */
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { email: user.email, role: "client", name: user.name },
        JWT_SECRET,
        { expiresIn: "24h" }
      );

      console.log("✅ Client logged in:", user.email);
      return res.json({
        success: true,
        token,
        email: user.email,
        name: user.name,
        role: "client",
      });
    }

    const expert = await Expert.findOne({ email: email.toLowerCase() });
    if (expert && (await bcrypt.compare(password, expert.password))) {
      const token = jwt.sign(
        { email: expert.email, role: "expert", name: expert.name },
        JWT_SECRET,
        { expiresIn: "24h" }
      );

      console.log(
        "✅ Expert logged in:",
        expert.email,
        "| Status:",
        expert.status
      );
      return res.json({
        success: true,
        token,
        email: expert.email,
        name: expert.name,
        role: "expert",
        status: expert.status,
      });
    }

    res.status(401).json({ error: "Invalid credentials" });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

/* ============================================================
   ROUTES - EXPERT SIGNUP
============================================================ */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(
      null,
      file.fieldname === "resume" ? "uploads/resumes" : "uploads/photos"
    );
  },
  filename: (req, file, cb) => {
    const cleanName = path.basename(file.originalname).replace(/\s/g, "-");
    cb(null, Date.now() + "-" + cleanName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "photo") {
      if (file.mimetype.startsWith("image/")) cb(null, true);
      else cb(new Error("Only image files are allowed for photo"));
    } else if (file.fieldname === "resume") {
      if (file.mimetype === "application/pdf") cb(null, true);
      else cb(new Error("Only PDF files are allowed for resume"));
    } else cb(null, true);
  },
});

const fileToDataUrl = (filePath, mimeType = "image/jpeg") => {
  const absPath = path.isAbsolute(filePath)
    ? filePath
    : path.join(__dirname, filePath);
  const bytes = fs.readFileSync(absPath);
  return `data:${mimeType};base64,${bytes.toString("base64")}`;
};

const MAX_CHAT_IMAGE_DATA_URL_LEN = 3 * 1024 * 1024; // ~2MB binary image payload
const toChatImageDataUrl = (raw) => {
  const v = String(raw || "").trim();
  if (!v) return "";
  if (!/^data:image\/[a-zA-Z0-9+.-]+;base64,/i.test(v)) return "";
  if (v.length > MAX_CHAT_IMAGE_DATA_URL_LEN) return "";
  return v;
};

app.post(
  "/api/pro-signup",
  upload.fields([
    { name: "resume", maxCount: 1 },
    { name: "photo", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const {
        name,
        email,
        password,
        field,
        experience,
        headline,
        summary,
        linkedin,
        price,
      } = req.body;

      if (
        !name ||
        !email ||
        !password ||
        !field ||
        !experience ||
        !headline ||
        !summary ||
        !price
      ) {
        return res
          .status(400)
          .json({ error: "All required fields must be filled" });
      }

      if (!req.files?.resume?.[0] || !req.files?.photo?.[0]) {
        return res
          .status(400)
          .json({ error: "Photo and resume are required" });
      }

      const existingExpert = await Expert.findOne({
        email: email.toLowerCase(),
      });
      if (existingExpert) {
        return res
          .status(400)
          .json({ error: "Expert with this email already exists" });
      }

      const passwordErr = validatePasswordStrength(password);
      if (passwordErr) {
        return res.status(400).json({ error: passwordErr });
      }

      const hash = await bcrypt.hash(password, PASSWORD_SALT_ROUNDS);

      const photoFile = req.files.photo[0];
      let avatarValue = photoFile.path;
      try {
        avatarValue = fileToDataUrl(photoFile.path, photoFile.mimetype);
      } catch (imgErr) {
        console.warn("⚠️ Could not convert signup photo to data URL:", imgErr.message);
      }

      const newExpert = await Expert.create({
        name: name.trim(),
        email: email.toLowerCase().trim(),
        password: hash,
        field: field.trim(),
        experience: parseInt(experience),
        headline: headline.trim(),
        summary: summary.trim(),
        linkedin: linkedin?.trim() || "",
        price: parseInt(price),
        resumePath: req.files.resume[0].path,
        avatar: avatarValue,
        status: "pending",
      });

      console.log("✅ Expert registered:", newExpert.email);
      res.json({
        success: true,
        message:
          "Registration successful! Your profile will be reviewed by our team.",
        expert: {
          name: newExpert.name,
          email: newExpert.email,
          role: "expert",
          field: newExpert.field,
          headline: newExpert.headline,
          experience: newExpert.experience,
          price: newExpert.price,
          avatar: newExpert.avatar,
          status: newExpert.status,
        },
      });
    } catch (err) {
      console.error("❌ Professional signup error:", err);
      res.status(500).json({ error: "Registration failed: " + err.message });
    }
  }
);

/* ============================================================
   ROUTES - PROFILE
============================================================ */
app.get("/api/profile", async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).json({ error: "Email required" });
    }

    const normalizedEmail = email.toLowerCase();
    const user = await User.findOne({ email: normalizedEmail }).select("-password");

    // For expert accounts, prefer Expert document so avatar/profile fields are returned.
    if (user?.role === "expert") {
      const expert = await Expert.findOne({ email: normalizedEmail }).select("-password");
      if (expert) {
        const summary = await Rating.aggregate([
          { $match: { expertEmail: normalizedEmail } },
          { $group: { _id: "$expertEmail", avgRating: { $avg: "$score" }, ratingsCount: { $sum: 1 } } },
        ]);
        const ratingInfo = summary[0] || { avgRating: 0, ratingsCount: 0 };
        return res.json({
          ...expert.toObject(),
          avgRating: Number((ratingInfo.avgRating || 0).toFixed(2)),
          ratingsCount: ratingInfo.ratingsCount || 0,
        });
      }
    }

    if (user) return res.json(user);

    const expert = await Expert.findOne({ email: normalizedEmail }).select("-password");
    if (expert) {
      const summary = await Rating.aggregate([
        { $match: { expertEmail: normalizedEmail } },
        { $group: { _id: "$expertEmail", avgRating: { $avg: "$score" }, ratingsCount: { $sum: 1 } } },
      ]);
      const ratingInfo = summary[0] || { avgRating: 0, ratingsCount: 0 };
      return res.json({
        ...expert.toObject(),
        avgRating: Number((ratingInfo.avgRating || 0).toFixed(2)),
        ratingsCount: ratingInfo.ratingsCount || 0,
      });
    }

    res.status(404).json({ error: "User not found" });
  } catch (err) {
    console.error("❌ Profile error:", err);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    if (req.user?.role !== "expert") {
      return res.status(403).json({ error: "Only experts can update this profile" });
    }

    const email = req.user.email?.toLowerCase();
    if (!email) {
      return res.status(400).json({ error: "Invalid auth token" });
    }

    const allowed = ["name", "field", "headline", "summary", "location", "linkedin", "price", "experience"];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }
    // Frontend uses "bio"; schema stores it as "summary".
    if (req.body.bio !== undefined) updates.summary = req.body.bio;

    if (updates.price !== undefined) {
      const n = Number(updates.price);
      updates.price = Number.isFinite(n) ? n : 0;
    }
    if (updates.experience !== undefined) {
      const n = Number(updates.experience);
      updates.experience = Number.isFinite(n) ? n : 0;
    }

    const expert = await Expert.findOneAndUpdate(
      { email },
      { $set: updates },
      { new: true }
    ).select("-password");

    if (!expert) {
      return res.status(404).json({ error: "Expert not found" });
    }

    return res.json({ success: true, expert });
  } catch (err) {
    console.error("❌ Profile update error:", err);
    return res.status(500).json({ error: "Failed to update profile" });
  }
});

app.get("/api/password-policy", (req, res) => {
  return res.json({ success: true, policy: PASSWORD_POLICY });
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    let account = await User.findOne({ email });
    let role = "client";
    if (!account) {
      account = await Expert.findOne({ email });
      role = "expert";
    }

    // Never reveal whether account exists.
    if (!account) {
      return res.json({
        success: true,
        message: "If this email is registered, a reset link has been generated.",
      });
    }

    const resetToken = jwt.sign(
      { type: "password_reset", email, role },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    const tokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    account.resetPasswordTokenHash = tokenHash;
    account.resetPasswordExpires = expiresAt;
    await account.save();

    const base =
      process.env.FRONTEND_URL || process.env.PUBLIC_APP_URL || "http://localhost:5173";
    const cleanBase = base.replace(/\/+$/, "");
    const resetPath = `login?mode=reset&token=${encodeURIComponent(resetToken)}`;
    const resetLink =
      FRONTEND_ROUTER_MODE === "hash"
        ? `${cleanBase}/#/${resetPath}`
        : `${cleanBase}/${resetPath}`;
    const mailResult = await sendPasswordResetEmail({ toEmail: email, resetLink });
    if (!mailResult.ok) {
      console.warn(`⚠️ Reset email delivery issue for ${email}: ${mailResult.error}`);
    } else {
      console.log(`📧 Password reset email sent to ${email} via ${EMAIL_PROVIDER}`);
    }

    console.log(`🔐 Password reset link (${email}): ${resetLink}`);

    const response = {
      success: true,
      message: "If this email is registered, a reset link has been generated.",
    };

    if (String(process.env.NODE_ENV || "").toLowerCase() !== "production") {
      response.resetLink = resetLink;
      response.token = resetToken;
      response.emailDelivery =
        mailResult.ok ? "sent" : `not_sent: ${mailResult.error}`;
    }

    return res.json(response);
  } catch (err) {
    console.error("❌ Forgot password error:", err);
    return res.status(500).json({ error: "Failed to process forgot password request" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    const password = String(req.body?.password || "");

    if (!token || !password) {
      return res.status(400).json({ error: "Token and new password are required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).json({ error: "Reset token is invalid or expired" });
    }

    if (decoded?.type !== "password_reset") {
      return res.status(400).json({ error: "Invalid reset token type" });
    }

    const email = String(decoded.email || "").toLowerCase();
    const role = String(decoded.role || "");
    const Model = role === "expert" ? Expert : User;
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const account = await Model.findOne({
      email,
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!account) {
      return res.status(400).json({ error: "Reset token is invalid or expired" });
    }

    const passwordErr = validatePasswordStrength(password);
    if (passwordErr) {
      return res.status(400).json({ error: passwordErr });
    }

    account.password = await bcrypt.hash(password, PASSWORD_SALT_ROUNDS);
    account.resetPasswordTokenHash = undefined;
    account.resetPasswordExpires = undefined;
    await account.save();

    return res.json({ success: true, message: "Password reset successful. Please login." });
  } catch (err) {
    console.error("❌ Reset password error:", err);
    return res.status(500).json({ error: "Failed to reset password" });
  }
});

app.put("/api/profile/photo", authMiddleware, upload.single("photo"), async (req, res) => {
  try {
    if (req.user?.role !== "expert") {
      return res.status(403).json({ error: "Only experts can update profile photo" });
    }

    const email = req.user.email?.toLowerCase();
    if (!email) {
      return res.status(400).json({ error: "Invalid auth token" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "Photo file is required" });
    }

    let avatarValue = req.file.path;
    try {
      avatarValue = fileToDataUrl(req.file.path, req.file.mimetype);
    } catch (imgErr) {
      console.warn("⚠️ Could not convert profile photo to data URL:", imgErr.message);
    }

    const expert = await Expert.findOneAndUpdate(
      { email },
      { $set: { avatar: avatarValue } },
      { new: true }
    ).select("-password");

    if (!expert) {
      return res.status(404).json({ error: "Expert not found" });
    }

    return res.json({ success: true, expert });
  } catch (err) {
    console.error("❌ Profile photo update error:", err);
    return res.status(500).json({ error: "Failed to update profile photo" });
  }
});

/* ============================================================
   ROUTES - GET CHAT HISTORY
============================================================ */
app.get("/api/messages", async (req, res) => {
  try {
    const { room } = req.query;

    if (!room) {
      return res.status(400).json({ error: "Room ID required" });
    }

    const messages = await Message.find({ room })
      .sort({ createdAt: 1 })
      .limit(100);

    res.json(messages);
  } catch (err) {
    console.error("❌ Error fetching messages:", err);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

/* ============================================================
   ROUTES - GET ALL CONVERSATIONS FOR EXPERT
============================================================ */
app.get("/api/conversations", async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).json({ error: "Email required" });
    }

    const messages = await Message.find({
      room: { $regex: email },
    }).sort({ createdAt: -1 });

    const roomMap = {};
    messages.forEach((msg) => {
      if (!roomMap[msg.room]) {
        const preview = msg.messageType === "image"
          ? (msg.imageName ? `[Image] ${msg.imageName}` : "[Image]")
          : (msg.message || "");
        roomMap[msg.room] = {
          room: msg.room,
          lastMessage: preview,
          lastMessageTime: msg.createdAt,
          otherEmail: msg.room.split("_").find((e) => e !== email),
        };
      }
    });

    res.json(Object.values(roomMap));
  } catch (err) {
    console.error("❌ Error fetching conversations:", err);
    res.status(500).json({ error: "Failed to fetch conversations" });
  }
});

/* ============================================================
   ROUTES - PUBLIC EXPERTS LIST
============================================================ */
app.get("/api/experts", async (req, res) => {
  try {
    const { status = "approved", field } = req.query;

    const filter = {};
    if (status !== "all") filter.status = status;
    if (field && field !== "all") filter.field = new RegExp(field, "i");

    const experts = await Expert.find(filter)
      .select("-password")
      .sort({ experience: -1, createdAt: -1 });
    const emails = experts.map((e) => String(e.email || "").toLowerCase()).filter(Boolean);
    const ratings = await Rating.aggregate([
      { $match: { expertEmail: { $in: emails } } },
      { $group: { _id: "$expertEmail", avgRating: { $avg: "$score" }, ratingsCount: { $sum: 1 } } },
    ]);
    const ratingsMap = new Map(
      ratings.map((r) => [String(r._id).toLowerCase(), { avgRating: Number((r.avgRating || 0).toFixed(2)), ratingsCount: r.ratingsCount || 0 }])
    );
    const out = experts.map((e) => {
      const k = String(e.email || "").toLowerCase();
      const info = ratingsMap.get(k) || { avgRating: 0, ratingsCount: 0 };
      return { ...e.toObject(), avgRating: info.avgRating, ratingsCount: info.ratingsCount };
    });
    res.json(out);
  } catch (err) {
    console.error("❌ EXPERTS ERROR:", err);
    res.status(500).json({ error: "Failed to fetch experts" });
  }
});

app.get("/api/public-home-data", async (req, res) => {
  try {
    const palette = ["#22d3ee", "#34d399", "#fbbf24", "#a78bfa"];
    const initials = (name) => String(name || "")
      .split(" ")
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() || "")
      .join("") || "EX";
    const ago = (ts) => {
      const t = new Date(ts || 0).getTime();
      if (!t) return "now";
      const mins = Math.max(1, Math.floor((Date.now() - t) / 60000));
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 60);
      if (hrs < 24) return `${hrs}h ago`;
      const days = Math.floor(hrs / 24);
      return `${days}d ago`;
    };

    const [approvedExperts, paidSessions, totalMessages, avgRatingAgg, expertsRaw, recentPayments] = await Promise.all([
      Expert.countDocuments({ status: "approved" }),
      Payment.countDocuments({ status: "paid", verified: true }),
      Message.countDocuments({}),
      Rating.aggregate([{ $group: { _id: null, avgScore: { $avg: "$score" } } }]),
      Expert.find({ status: "approved" }).select("name field experience email").sort({ experience: -1, createdAt: -1 }).lean(),
      Payment.find({ status: "paid", verified: true })
        .sort({ createdAt: -1 })
        .limit(5)
        .select("clientName clientEmail expertField createdAt")
        .lean(),
    ]);

    const expertEmails = expertsRaw.map((e) => String(e.email || "").toLowerCase()).filter(Boolean);
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
      ratingsByExpert.map((r) => [String(r._id || "").toLowerCase(), { avg: Number(r.avgRating || 0), count: Number(r.ratingsCount || 0) }])
    );
    const sessionsMap = new Map(
      sessionsByExpert.map((s) => [String(s._id || "").toLowerCase(), Number(s.sessions || 0)])
    );

    const experts = expertsRaw
      .map((e, i) => {
        const email = String(e.email || "").toLowerCase();
        const r = ratingMap.get(email) || { avg: 0, count: 0 };
        const sessions = sessionsMap.get(email) || 0;
        const domain = String(e.field || "General Consulting");
        const expYears = Number(e.experience || 0);
        return {
          name: e.name || "Expert",
          domain,
          exp: `${expYears}+ yrs`,
          sessions,
          tag: r.avg >= 4.7 ? "Top rated" : sessions >= 20 ? "Active expert" : "Verified expert",
          color: palette[i % palette.length],
          initial: initials(e.name),
          score: r.avg,
        };
      })
      .sort((a, b) => (b.score - a.score) || (b.sessions - a.sessions))
      .slice(0, 4)
      .map(({ score, ...rest }) => rest);

    const activityIcons = ["🎯", "💼", "📈", "✅", "🚀"];
    const activity = recentPayments.map((p, i) => {
      const who = p.clientName || (p.clientEmail ? p.clientEmail.split("@")[0] : "Client");
      const field = String(p.expertField || "expert");
      return {
        icon: activityIcons[i % activityIcons.length],
        text: `${who} booked a ${field} session`,
        time: ago(p.createdAt),
      };
    });

    const avgScore = Number(avgRatingAgg?.[0]?.avgScore || 0);
    const satisfactionPct = avgScore > 0 ? Math.round((avgScore / 5) * 100) : 97;

    return res.json({
      stats: {
        approvedExperts,
        sessionsCompleted: paidSessions,
        decisionsMade: totalMessages,
        clientSatisfaction: satisfactionPct,
      },
      experts,
      activity,
    });
  } catch (err) {
    console.error("❌ PUBLIC HOME DATA ERROR:", err);
    return res.status(500).json({ error: "Failed to fetch home data" });
  }
});

app.post("/api/ratings", authMiddleware, async (req, res) => {
  try {
    if (req.user?.role !== "client") {
      return res.status(403).json({ error: "Only clients can submit ratings" });
    }

    const clientEmail = String(req.user.email || "").toLowerCase();
    const expertEmail = String(req.body.expertEmail || "").toLowerCase();
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

    const saved = await Rating.findOneAndUpdate(
      { expertEmail, clientEmail },
      { $set: { score, review, room } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    return res.json({ success: true, rating: saved });
  } catch (err) {
    console.error("❌ Rating save error:", err);
    return res.status(500).json({ error: "Failed to save rating" });
  }
});

app.get("/api/ratings/my", authMiddleware, async (req, res) => {
  try {
    const clientEmail = String(req.user.email || "").toLowerCase();
    const expertEmail = String(req.query.expertEmail || "").toLowerCase();
    if (!expertEmail) {
      return res.status(400).json({ error: "expertEmail is required" });
    }
    const rating = await Rating.findOne({ clientEmail, expertEmail }).lean();
    return res.json({ success: true, rating: rating || null });
  } catch (err) {
    console.error("❌ Rating fetch error:", err);
    return res.status(500).json({ error: "Failed to fetch rating" });
  }
});

/* ============================================================
   ADMIN ROUTES
============================================================ */
app.post("/api/admin/expert-status", adminAuth, async (req, res) => {
  try {
    const { email, status } = req.body;
    if (!email || !["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid email or status" });
    }

    const expert = await Expert.findOneAndUpdate(
      { email: email.toLowerCase() },
      { status },
      { new: true }
    ).select("-password");

    if (!expert) {
      return res.status(404).json({ error: "Expert not found" });
    }

    res.json({
      success: true,
      expert: {
        name: expert.name,
        email: expert.email,
        field: expert.field,
        status: expert.status,
      },
    });
  } catch (err) {
    console.error("❌ ADMIN ERROR:", err);
    res.status(500).json({ error: "Update failed: " + err.message });
  }
});

const onlineUsers = {};

app.get("/api/health", adminAuth, (req, res) => {
  res.json({
    status: "healthy",
    onlineExperts: Object.values(onlineUsers).filter(
      (u) => u.role === "expert"
    ).length,
    adminAccess: true,
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/admin/auth-config", (req, res) => {
  const hasGoogleClientId = !!GOOGLE_CLIENT_ID;
  const hasAllowedAdminEmails = ADMIN_ALLOWED_EMAILS.length > 0;
  const hasGlobal2FASecret = !!ADMIN_2FA_SECRET;
  const hasPerEmail2FASecrets =
    Object.values(ADMIN_2FA_SECRETS).filter(Boolean).length > 0;
  const has2FASecret = hasGlobal2FASecret || hasPerEmail2FASecrets;

  res.json({
    success: true,
    hasGoogleClientId,
    googleClientId: GOOGLE_CLIENT_ID || "",
    hasAllowedAdminEmails,
    has2FASecret,
    hasPerEmail2FASecrets,
    hasGlobal2FASecret,
    allowedAdminEmailsCount: ADMIN_ALLOWED_EMAILS.length,
  });
});

app.post("/api/admin/google-auth", async (req, res) => {
  try {
    const idToken = String(req.body?.idToken || "");
    if (!idToken) {
      return res.status(400).json({ error: "Google ID token required" });
    }
    if (!GOOGLE_CLIENT_ID) {
      return res
        .status(500)
        .json({ error: "GOOGLE_CLIENT_ID is not configured on server" });
    }

    const verifyRes = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(
        idToken
      )}`
    );
    const verifyData = await verifyRes.json().catch(() => ({}));
    if (!verifyRes.ok || verifyData?.error) {
      return res.status(401).json({ error: "Invalid Google token" });
    }

    const aud = String(verifyData.aud || "");
    const email = String(verifyData.email || "").toLowerCase();
    const emailVerified = String(verifyData.email_verified || "false") === "true";

    if (aud !== GOOGLE_CLIENT_ID) {
      return res.status(401).json({ error: "Google token audience mismatch" });
    }
    if (!email || !emailVerified) {
      return res.status(401).json({ error: "Google email is not verified" });
    }
    if (
      ADMIN_ALLOWED_EMAILS.length > 0 &&
      !ADMIN_ALLOWED_EMAILS.includes(email)
    ) {
      return res.status(403).json({ error: "Admin email not authorized" });
    }
    if (!getAdmin2FASecret(email)) {
      return res.status(500).json({
        error: "Admin 2FA secret not configured for this email",
      });
    }

    const pre2faToken = jwt.sign(
      { email, type: "admin_pre2fa" },
      JWT_SECRET,
      { expiresIn: "5m" }
    );

    return res.json({ success: true, email, pre2faToken });
  } catch (err) {
    console.error("❌ Admin google-auth error:", err);
    return res.status(500).json({ error: "Admin Google auth failed" });
  }
});

app.post("/api/admin/2fa/verify", async (req, res) => {
  try {
    const pre2faToken = String(req.body?.pre2faToken || "");
    const code = String(req.body?.code || "");
    if (!pre2faToken || !code) {
      return res.status(400).json({ error: "pre2faToken and code are required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(pre2faToken, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid or expired pre-2FA token" });
    }
    if (decoded?.type !== "admin_pre2fa") {
      return res.status(401).json({ error: "Invalid pre-2FA token type" });
    }

    const email = String(decoded.email || "").toLowerCase();
    const secret = getAdmin2FASecret(email);
    if (!secret) {
      return res.status(500).json({ error: "Admin 2FA secret missing" });
    }

    if (!verifyTOTP(code, secret, 1)) {
      return res.status(401).json({ error: "Invalid 2FA code" });
    }

    const adminSessionToken = jwt.sign(
      { email, type: "admin", role: "admin" },
      JWT_SECRET,
      { expiresIn: "8h" }
    );
    return res.json({ success: true, adminSessionToken, email });
  } catch (err) {
    console.error("❌ Admin 2FA verify error:", err);
    return res.status(500).json({ error: "Admin 2FA verification failed" });
  }
});

/* ============================================================
   RAZORPAY PAYMENT ROUTES
============================================================ */
app.post("/api/create-order", authMiddleware, async (req, res) => {
  try {
    const { expertEmail, expertField } = req.body;
    const clientEmail = req.user.email;
    const clientName = req.user.name;

    const expert = await Expert.findOne({ email: expertEmail.toLowerCase() });
    if (!expert) {
      return res.status(404).json({ error: "Expert not found" });
    }
    if (expert.status !== "approved") {
      return res.status(400).json({ error: "Expert not approved yet" });
    }

    const amount = expert.price || 500;

    const options = {
      amount: amount * 100,
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
      notes: {
        expertEmail,
        expertField: expert.field,
        clientEmail,
        clientName,
        expertName: expert.name,
        purpose: "Expert Consultation",
      },
    };

    const order = await razorpay.orders.create(options);

    await Payment.create({
      orderId: order.id,
      amount: amount,
      currency: "INR",
      status: "created",
      clientEmail,
      expertEmail,
      expertField: expert.field,
      clientName,
      notes: options.notes,
    });

    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: process.env.RAZORPAY_KEY_ID || "rzp_test_YOUR_KEY_ID",
      expertName: expert.name,
      expertField: expert.field,
    });
  } catch (error) {
    console.error("❌ Order creation error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create order",
      error: error.message,
    });
  }
});

app.post("/api/verify-payment", authMiddleware, async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
    } = req.body;

    const generated_signature = crypto
      .createHmac(
        "sha256",
        process.env.RAZORPAY_KEY_SECRET || "YOUR_KEY_SECRET"
      )
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");

    if (generated_signature === razorpay_signature) {
      const payment = await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        {
          paymentId: razorpay_payment_id,
          signature: razorpay_signature,
          status: "paid",
          verified: true,
        },
        { new: true }
      );

      if (!payment) {
        return res.status(404).json({ error: "Payment record not found" });
      }

      res.json({
        success: true,
        message: "Payment verified successfully",
        paymentId: razorpay_payment_id,
        orderId: razorpay_order_id,
        expertEmail: payment.expertEmail,
        amount: payment.amount,
      });
    } else {
      await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { status: "failed" }
      );

      res.status(400).json({
        success: false,
        message: "Payment verification failed",
      });
    }
  } catch (error) {
    console.error("❌ Verification error:", error);
    res.status(500).json({
      success: false,
      message: "Verification failed",
      error: error.message,
    });
  }
});

app.get("/api/payment-status/:paymentId", authMiddleware, async (req, res) => {
  try {
    const { paymentId } = req.params;

    const localPayment = await Payment.findOne({ paymentId });

    if (localPayment) {
      return res.json({
        success: true,
        status: localPayment.status,
        amount: localPayment.amount,
        currency: localPayment.currency,
        verified: localPayment.verified,
        expertEmail: localPayment.expertEmail,
        clientEmail: localPayment.clientEmail,
      });
    }

    const payment = await razorpay.payments.fetch(paymentId);

    res.json({
      success: true,
      status: payment.status,
      amount: payment.amount / 100,
      currency: payment.currency,
      method: payment.method,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch payment status",
      error: error.message,
    });
  }
});

app.get("/api/check-payment", authMiddleware, async (req, res) => {
  try {
    const { expertEmail } = req.query;
    const clientEmail = req.user.email;
    const access = await getClientExpertChatAccess(clientEmail, expertEmail);
    const payment = access.payment;

    res.json({
      hasPaid: access.hasPaid,
      hasAccess: access.hasAccess,
      reason: access.reason,
      firstExpertReplyAt: access.firstExpertReplyAt,
      accessUntil: access.accessUntil,
      hoursLeft: access.hoursLeft,
      payment: payment
        ? {
            paymentId: payment.paymentId,
            amount: payment.amount,
            date: payment.createdAt,
          }
        : null,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/my-payments", authMiddleware, async (req, res) => {
  try {
    const email = req.user.email;

    const payments = await Payment.find({
      $or: [{ clientEmail: email }, { expertEmail: email }],
    }).sort({ createdAt: -1 });

    res.json(payments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/razorpay-webhook", async (req, res) => {
  try {
    const webhookSignature = req.headers["x-razorpay-signature"];
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!webhookSecret) {
      return res.status(200).json({ status: "ok" });
    }

    const expectedSignature = crypto
      .createHmac("sha256", webhookSecret)
      .update(JSON.stringify(req.body))
      .digest("hex");

    if (webhookSignature === expectedSignature) {
      const event = req.body.event;
      const payload = req.body.payload;

      switch (event) {
        case "payment.captured":
          await Payment.findOneAndUpdate(
            { orderId: payload.payment.entity.order_id },
            {
              status: "paid",
              paymentId: payload.payment.entity.id,
            }
          );
          break;

        case "payment.failed":
          await Payment.findOneAndUpdate(
            { orderId: payload.payment.entity.order_id },
            { status: "failed" }
          );
          break;

        default:
          console.log("📌 Unhandled event:", event);
      }

      res.json({ status: "ok" });
    } else {
      res.status(400).json({ error: "Invalid signature" });
    }
  } catch (error) {
    console.error("❌ Webhook error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ============================================================
   AI CORE – GEMINI v1 + gemini-2.5-flash
============================================================ */
async function callGemini(prompt) {
  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    return {
      ok: false,
      reason: "NO_KEY",
      message: "GEMINI_API_KEY not set",
    };
  }

  // FINAL FIX: v1 + gemini-2.5-flash
  const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";
  const url = `https://generativelanguage.googleapis.com/v1/models/${encodeURIComponent(
    model
  )}:generateContent?key=${key}`;

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
      message: String(err && err.message ? err.message : err),
    };
  }
}

app.get("/api/ai/debug", (req, res) => {
  res.json({
    hasKey: !!process.env.GEMINI_API_KEY,
    model: process.env.GEMINI_MODEL || "gemini-2.5-flash",
    base: "v1",
  });
});

app.post("/api/ai/ask", async (req, res) => {
  try {
    const prompt =
      (req.body && (req.body.prompt || req.body.input || req.body.text)) || "";
    if (!prompt.trim()) {
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

/* ============================================================
   SOCKET.IO - LIVE CHAT
============================================================ */
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
        connectedAt: new Date(),
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
      connectedAt: new Date(),
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
      const senderEntry = Object.entries(onlineUsers).find(
        ([, info]) => info.socketId === socket.id
      );
      const senderEmail = String(senderEntry?.[0] || data.author || "").toLowerCase();
      const senderRole = String(senderEntry?.[1]?.role || data.authorRole || "").toLowerCase();
      const room = String(data.room || "");

      if (!room) {
        socket.emit("error", "Invalid room");
        return;
      }

      // Enforce payment/access window for client messages.
      if (senderRole === "client") {
        const emails = room.split("_").map((e) => String(e || "").toLowerCase());
        const expertEmail = emails.find((e) => e && e !== senderEmail) || "";
        const access = await getClientExpertChatAccess(senderEmail, expertEmail);
        if (!access.hasAccess) {
          socket.emit("chat_access_denied", {
            reason: access.reason,
            message:
              access.reason === "window_expired"
                ? "Your 24-hour chat window has expired. Please make a new payment to continue."
                : "Please complete payment to continue chatting with this expert.",
          });
          return;
        }
      }

      const payload = {
        ...data,
        room,
        author: senderEmail || data.author,
        authorRole: senderRole || data.authorRole,
      };
      const text = String(payload.message || "").trim();
      const imageUrl = toChatImageDataUrl(payload.imageUrl);
      const imageName = String(payload.imageName || "").trim().slice(0, 120);
      const hasText = Boolean(text);
      const hasImage = Boolean(imageUrl);

      if (!hasText && !hasImage) {
        socket.emit("error", "Message cannot be empty");
        return;
      }

      payload.messageType = hasImage ? "image" : "text";
      payload.message = text;
      payload.imageUrl = hasImage ? imageUrl : "";
      payload.imageName = hasImage ? imageName : "";

      const msg = await Message.create(payload);
      io.to(room).emit("receive_message", msg);

      const emails = room.split("_");
      emails.forEach((email) => {
        if (onlineUsers[email] && onlineUsers[email].socketId) {
          io.to(onlineUsers[email].socketId).emit("new_message_notification", {
            room,
            message: msg,
          });
        }
      });
    } catch (err) {
      console.error("❌ Message save failed:", err);
      socket.emit("error", "Message failed");
    }
  });

  socket.on("disconnect", () => {
    for (const email in onlineUsers) {
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
  console.log(`🚀 SolutionHub v9.0 LIVE - STABLE BACKEND 🎉`);
  console.log(`🚀 ============================================`);
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`💬 Socket.IO: Ready`);
  console.log(
    `💳 Razorpay: ${
      process.env.RAZORPAY_KEY_ID ? "Enabled ✅" : "TEST MODE (env key missing)"
    }`
  );
  console.log(
    `🤖 AI: ${
      process.env.GEMINI_API_KEY
        ? "Enabled (v1, gemini-2.5-flash, safe fallback)"
        : "Disabled (no key)"
    }`
  );
  console.log(
    `🔐 Admin Login: http://localhost:${PORT}/admin-login.html`
  );
  console.log(
    `🛡️ Admin Dashboard: http://localhost:${PORT}/admin.html`
  );
  console.log(`✅ Public Experts: http://localhost:${PORT}/experts.html`);
  console.log(`💬 Chat System: FULLY ENABLED`);
  console.log(`💰 Payment System: ACTIVE`);
  console.log(
    `🔑 Razorpay Key: ${(process.env.RAZORPAY_KEY_ID || "NOT_SET").substring(
      0,
      15
    )}...`
  );
  console.log(`🚀 ============================================\n`);
});
