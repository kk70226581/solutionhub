/**
 * 2FA (TOTP) – Admin two-factor authentication helpers
 */

const crypto = require("crypto");
const { base32ToBuffer } = require("../utils/shared-helpers.cjs");

// Verify TOTP code against secret
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

// Get 2FA secret for admin email (with fallback to global)
const getAdmin2FASecret = (email) => {
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

  const key = String(email || "").toLowerCase();
  return ADMIN_2FA_SECRETS[key] || ADMIN_2FA_SECRET;
};

module.exports = {
  verifyTOTP,
  getAdmin2FASecret,
};
