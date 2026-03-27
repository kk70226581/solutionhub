/**
 * PAYMENT HELPERS – Consolidate Razorpay & payment notification logic
 */

const crypto = require("crypto");
const { normalizeEmail } = require("./shared-helpers.cjs");

const CHAT_ACCESS_HOURS = 24;
const CHAT_ACCESS_MS = CHAT_ACCESS_HOURS * 60 * 60 * 1000;

// Check if client has access to chat with expert
const getClientExpertChatAccess = async (Payment, Message, clientEmailRaw, expertEmailRaw) => {
  const clientEmail = normalizeEmail(clientEmailRaw);
  const expertEmail = normalizeEmail(expertEmailRaw);

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
};

// Verify Razorpay signature (reusable for webhook + direct verification)
const verifyRazorpaySignature = (orderId, paymentId, signature, secret) => {
  const generated = crypto
    .createHmac("sha256", secret)
    .update(orderId + "|" + paymentId)
    .digest("hex");
  return generated === signature;
};

// Process webhook events (consolidate duplicate handlers)
const handleRazorpayWebhookEvent = async (event, payload, Payment, models = {}) => {
  switch (event) {
    case "payment.captured":
      return Payment.findOneAndUpdate(
        { orderId: payload?.payment?.entity?.order_id },
        { status: "paid", paymentId: payload?.payment?.entity?.id }
      );

    case "payment.failed":
      return Payment.findOneAndUpdate(
        { orderId: payload?.payment?.entity?.order_id },
        { status: "failed" }
      );

    default:
      console.log("📌 Unhandled webhook event:", event);
      return null;
  }
};

module.exports = {
  getClientExpertChatAccess,
  verifyRazorpaySignature,
  handleRazorpayWebhookEvent,
  CHAT_ACCESS_HOURS,
  CHAT_ACCESS_MS,
};
