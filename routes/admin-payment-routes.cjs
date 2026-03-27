const registerAdminPaymentRoutes = (app, deps) => {
  const {
    adminAuth,
    authMiddleware,
    razorpay,
    Expert,
    Payment,
    isRedisReady,
    getOnlineUsersSnapshot,
    getClientExpertChatAccess,
    verifyRazorpaySignature,
    handleRazorpayWebhookEvent,
  } = deps;

  app.post("/api/admin/expert-status", adminAuth, async (req, res) => {
    try {
      const email = String(req.body?.email || "").trim().toLowerCase();
      const status = String(req.body?.status || "");

      if (!email || !["approved", "rejected"].includes(status)) {
        return res.status(400).json({ error: "Invalid email or status" });
      }

      const expert = await Expert.findOneAndUpdate({ email }, { status }, { new: true }).select("-password");
      if (!expert) {
        return res.status(404).json({ error: "Expert not found" });
      }

      return res.json({
        success: true,
        expert: {
          name: expert.name,
          email: expert.email,
          field: expert.field,
          status: expert.status,
        },
      });
    } catch (err) {
      console.error("ADMIN ERROR:", err);
      return res.status(500).json({ error: `Update failed: ${err.message}` });
    }
  });

  app.get("/api/health", adminAuth, async (req, res) => {
    const snapshot = await getOnlineUsersSnapshot();
    res.json({
      status: "healthy",
      onlineExperts: Object.values(snapshot).filter((user) => user.role === "expert").length,
      adminAccess: true,
      timestamp: new Date().toISOString(),
      presenceStore: isRedisReady() ? "redis" : "memory",
    });
  });

  app.get("/api/presence", async (req, res) => {
    try {
      const email = String(req.query.email || "").toLowerCase().trim();
      if (!email) {
        return res.status(400).json({ error: "Email required" });
      }

      const snapshot = await getOnlineUsersSnapshot();
      const user = snapshot[email] || null;
      return res.json({
        email,
        online: Boolean(user?.socketId),
        user,
        source: isRedisReady() ? "redis" : "memory",
      });
    } catch (err) {
      console.error("Presence lookup failed:", err);
      return res.status(500).json({ error: "Failed to load presence" });
    }
  });

  app.post("/api/create-order", authMiddleware, async (req, res) => {
    try {
      const expertEmail = String(req.body?.expertEmail || "").trim().toLowerCase();
      const clientEmail = String(req.user?.email || "").trim().toLowerCase();
      const clientName = String(req.user?.name || "").trim();

      const expert = await Expert.findOne({ email: expertEmail });
      if (!expert) {
        return res.status(404).json({ error: "Expert not found" });
      }
      if (expert.status !== "approved") {
        return res.status(400).json({ error: "Expert not approved yet" });
      }

      const amount = expert.price || 500;
      const notes = {
        expertEmail,
        expertField: expert.field,
        clientEmail,
        clientName,
        expertName: expert.name,
        purpose: "Expert Consultation",
      };

      const order = await razorpay.orders.create({
        amount: amount * 100,
        currency: "INR",
        receipt: `receipt_${Date.now()}`,
        notes,
      });

      await Payment.create({
        orderId: order.id,
        amount,
        currency: "INR",
        status: "created",
        clientEmail,
        expertEmail,
        expertField: expert.field,
        clientName,
        notes,
      });

      return res.json({
        success: true,
        orderId: order.id,
        amount: order.amount,
        currency: order.currency,
        key: process.env.RAZORPAY_KEY_ID || "rzp_test_YOUR_KEY_ID",
        expertName: expert.name,
        expertField: expert.field,
      });
    } catch (err) {
      console.error("Order creation error:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to create order",
        error: err.message,
      });
    }
  });

  app.post("/api/verify-payment", authMiddleware, async (req, res) => {
    try {
      const orderId = String(req.body?.razorpay_order_id || "");
      const paymentId = String(req.body?.razorpay_payment_id || "");
      const signature = String(req.body?.razorpay_signature || "");
      const secret = process.env.RAZORPAY_KEY_SECRET || "YOUR_KEY_SECRET";

      if (!verifyRazorpaySignature(orderId, paymentId, signature, secret)) {
        await Payment.findOneAndUpdate({ orderId }, { status: "failed" });
        return res.status(400).json({
          success: false,
          message: "Payment verification failed",
        });
      }

      const payment = await Payment.findOneAndUpdate(
        { orderId },
        {
          paymentId,
          signature,
          status: "paid",
          verified: true,
        },
        { new: true }
      );

      if (!payment) {
        return res.status(404).json({ error: "Payment record not found" });
      }

      return res.json({
        success: true,
        message: "Payment verified successfully",
        paymentId,
        orderId,
        expertEmail: payment.expertEmail,
        amount: payment.amount,
      });
    } catch (err) {
      console.error("Verification error:", err);
      return res.status(500).json({
        success: false,
        message: "Verification failed",
        error: err.message,
      });
    }
  });

  app.get("/api/payment-status/:paymentId", authMiddleware, async (req, res) => {
    try {
      const paymentId = String(req.params.paymentId || "");
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
      return res.json({
        success: true,
        status: payment.status,
        amount: payment.amount / 100,
        currency: payment.currency,
        method: payment.method,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Failed to fetch payment status",
        error: err.message,
      });
    }
  });

  app.get("/api/check-payment", authMiddleware, async (req, res) => {
    try {
      const expertEmail = String(req.query.expertEmail || "").trim().toLowerCase();
      const clientEmail = String(req.user?.email || "").trim().toLowerCase();
      const access = await getClientExpertChatAccess(clientEmail, expertEmail);
      const payment = access.payment;

      return res.json({
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
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/my-payments", authMiddleware, async (req, res) => {
    try {
      const email = String(req.user?.email || "").trim().toLowerCase();
      const payments = await Payment.find({
        $or: [{ clientEmail: email }, { expertEmail: email }],
      }).sort({ createdAt: -1 });

      return res.json(payments);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/razorpay-webhook", async (req, res) => {
    try {
      const webhookSignature = req.headers["x-razorpay-signature"];
      const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

      if (!webhookSecret) {
        return res.status(200).json({ status: "ok" });
      }

      const crypto = require("crypto");
      const expectedSignature = crypto
        .createHmac("sha256", webhookSecret)
        .update(JSON.stringify(req.body))
        .digest("hex");

      if (webhookSignature !== expectedSignature) {
        return res.status(400).json({ error: "Invalid signature" });
      }

      await handleRazorpayWebhookEvent(req.body.event, req.body.payload, Payment);
      return res.json({ status: "ok" });
    } catch (err) {
      console.error("Webhook error:", err);
      return res.status(500).json({ error: err.message });
    }
  });
};

module.exports = {
  registerAdminPaymentRoutes,
};
