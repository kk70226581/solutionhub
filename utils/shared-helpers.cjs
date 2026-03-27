/**
 * HELPERS – Common utility functions to eliminate redundancy
 */

// Email normalization (replace 60+ repetitions)
const normalizeEmail = (emailRaw) => String(emailRaw || "").trim().toLowerCase();

// Parse room emails
const parseRoomEmails = (roomRaw) =>
  String(roomRaw || "")
    .split("_")
    .map((email) => normalizeEmail(email))
    .filter(Boolean);

// Normalize private room name (sort emails for consistent naming)
const normalizePrivateRoom = (roomRaw) =>
  parseRoomEmails(roomRaw).sort().join("_");

// Format initials from name
const initials = (name) =>
  String(name || "")
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() || "")
    .join("") || "EX";

// Format time-ago display
const timeAgo = (ts) => {
  const t = new Date(ts || 0).getTime();
  if (!t) return "now";
  const mins = Math.max(1, Math.floor((Date.now() - t) / 60000));
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
};

// Base32 decode for TOTP
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

// Chat attachment validators
const CHAT_ATTACHMENT_DATA_URL_RE =
  /^data:(image\/[a-zA-Z0-9+.-]+|audio\/[a-zA-Z0-9+.-]+|application\/pdf|text\/plain|application\/msword|application\/vnd\.openxmlformats-officedocument\.wordprocessingml\.document);base64,/i;

const getChatAttachmentTypeFromMime = (mimeRaw) => {
  const mime = String(mimeRaw || "").trim().toLowerCase();
  if (!mime) return "";
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("audio/")) return "audio";
  if (mime === "application/pdf") return "pdf";
  if (
    mime === "text/plain" ||
    mime === "application/msword" ||
    mime === "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  ) {
    return "file";
  }
  return "";
};

const toChatAttachmentDataUrl = (raw, maxLen = 11 * 1024 * 1024) => {
  const v = String(raw || "").trim();
  if (!v) return "";
  const match = v.match(/^data:([^;]+);base64,/i);
  if (!match || !CHAT_ATTACHMENT_DATA_URL_RE.test(v)) return "";
  const attachmentType = getChatAttachmentTypeFromMime(match[1]);
  if (!attachmentType) return "";
  if (v.length > maxLen) return "";
  return v;
};

module.exports = {
  normalizeEmail,
  parseRoomEmails,
  normalizePrivateRoom,
  initials,
  timeAgo,
  base32ToBuffer,
  getChatAttachmentTypeFromMime,
  toChatAttachmentDataUrl,
  CHAT_ATTACHMENT_DATA_URL_RE,
};
