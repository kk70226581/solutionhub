/**
 * CACHING & RATE LIMITING – Consolidate cache and rate limit logic
 */

// In-memory rate limiter
const createInMemoryRateLimiter = ({ windowMs, max, keyPrefix }) => {
  const buckets = new Map();
  return (req, res, next) => {
    const ip =
      String(
        req.headers["x-forwarded-for"] ||
          req.ip ||
          req.socket?.remoteAddress ||
          "unknown"
      )
        .split(",")[0]
        .trim();
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();
    const bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (bucket.count >= max) {
      const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({
        error: "Too many requests. Please try again later.",
      });
    }
    bucket.count += 1;
    return next();
  };
};

// Cache helpers for Redis
const cacheGetJson = async (redisClient, redisReady, key) => {
  if (!redisReady || !redisClient) return null;
  try {
    const raw = await redisClient.get(key);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
};

const cacheSetJson = async (redisClient, redisReady, key, value, ttlSec) => {
  if (!redisReady || !redisClient) return;
  try {
    await redisClient.set(key, JSON.stringify(value), { EX: ttlSec });
  } catch {
    // ignore cache write errors
  }
};

module.exports = {
  createInMemoryRateLimiter,
  cacheGetJson,
  cacheSetJson,
};
