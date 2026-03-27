/**
 * MIDDLEWARE – Authentication & Authorization
 */

const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "solutionhub_secret";

// User authentication middleware
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

// Admin authentication middleware
const adminAuth = async (req, res, next) => {
  try {
    const ADMIN_SECRET = process.env.ADMIN_SECRET || "your-super-secret-admin-key-2025-CHANGE-THIS";
    const ADMIN_ALLOWED_EMAILS = String(process.env.ADMIN_ALLOWED_EMAILS || "")
      .split(",")
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean);

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

    // Legacy secret token path
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

module.exports = {
  authMiddleware,
  adminAuth,
};
