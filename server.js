/**
 * ============================================================
 * SOLUTIONHUB CORE v9.0 – COMPLETE WITH RAZORPAY + ENHANCED EXPERT PROFILES 💳✅
 * Current Date: January 05, 2026
 * ============================================================
 */

require("dotenv").config();

const express = require("express");
const http = require("http");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const fetch = require("node-fetch");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const { Server } = require("socket.io");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const Razorpay = require("razorpay");
const crypto = require("crypto");

/* ============================================================
   BASIC SETUP
============================================================ */
const app = express();
const server = http.createServer(app);
const io = new Server(server, { 
  cors: { origin: "*", methods: ["GET", "POST"] } 
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "solutionhub_secret";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "your-super-secret-admin-key-2025-CHANGE-THIS";

/* ============================================================
   🆕 RAZORPAY SETUP
============================================================ */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_YOUR_KEY_ID',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'YOUR_KEY_SECRET'
});

console.log("💳 Razorpay initialized with key:", (process.env.RAZORPAY_KEY_ID || 'TEST_KEY').substring(0, 15) + "...");

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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/* ============================================================
   🔐 ADMIN SECURITY MIDDLEWARE
============================================================ */
const adminAuth = async (req, res, next) => {
  try {
    const adminToken = req.cookies.adminToken || 
                      req.headers['x-admin-token'] || 
                      req.query.adminToken ||
                      req.headers['admin-token'];
    
    if (!adminToken) {
      console.log(`🚫 ADMIN BLOCKED: No token from ${req.ip} → ${req.originalUrl}`);
      return res.status(401).json({ error: 'Admin access required' });
    }

    if (adminToken !== ADMIN_SECRET) {
      console.log(`🚫 ADMIN BLOCKED: Invalid token from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    console.log(`🛡️ ADMIN OK: ${req.ip} → ${req.originalUrl}`);
    next();
  } catch (err) {
    console.error('❌ Admin auth error:', err);
    res.status(500).json({ error: 'Admin verification failed' });
  }
};

/* ============================================================
   DATABASE
============================================================ */
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/solutionhub")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

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
  field: String, // Domain: Programming, Medical, Engineering, etc.
  experience: Number,
  headline: String, // Professional tagline (e.g., "Senior Full Stack Developer")
  summary: String, // Detailed bio/description
  linkedin: String, // LinkedIn profile URL
  resumePath: String,
  avatar: String,
  role: { type: String, default: "expert" },
  status: { type: String, default: "pending" }, // pending, approved, rejected
  price: { type: Number, default: 500 } // Consultation fee in INR
}, { timestamps: true }));

const Message = mongoose.model("Message", new mongoose.Schema({
  room: String,
  author: String,
  authorRole: String,
  message: String
}, { timestamps: true }));

// 🆕 PAYMENT SCHEMA
const Payment = mongoose.model("Payment", new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  paymentId: String,
  signature: String,
  amount: { type: Number, required: true },
  currency: { type: String, default: 'INR' },
  status: { type: String, default: 'created' }, // created, paid, failed
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
   🔐 PROTECTED ROUTES - ADMIN PAGES
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

    const hash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ 
      name: name.trim(), 
      email: email.toLowerCase().trim(), 
      password: hash 
    });
    
    console.log("✅ Client registered:", newUser.email);
    res.json({ success: true });
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

    // CLIENT
    const user = await User.findOne({ email: email.toLowerCase() });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ 
        email: user.email, 
        role: "client", 
        name: user.name 
      }, JWT_SECRET, { expiresIn: "24h" });
      
      console.log("✅ Client logged in:", user.email);
      return res.json({ 
        success: true, 
        token, 
        email: user.email, 
        name: user.name, 
        role: "client" 
      });
    }

    // EXPERT
    const expert = await Expert.findOne({ email: email.toLowerCase() });
    if (expert && await bcrypt.compare(password, expert.password)) {
      const token = jwt.sign({ 
        email: expert.email, 
        role: "expert", 
        name: expert.name 
      }, JWT_SECRET, { expiresIn: "24h" });
      
      console.log("✅ Expert logged in:", expert.email, "| Status:", expert.status);
      return res.json({ 
        success: true, 
        token, 
        email: expert.email, 
        name: expert.name, 
        role: "expert", 
        status: expert.status 
      });
    }

    res.status(401).json({ error: "Invalid credentials" });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

/* ============================================================
   ROUTES - ENHANCED EXPERT SIGNUP
============================================================ */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, file.fieldname === "resume" ? "uploads/resumes" : "uploads/photos");
  },
  filename: (req, file, cb) => {
    const cleanName = path.basename(file.originalname).replace(/\s/g, '-');
    cb(null, Date.now() + "-" + cleanName);
  }
});

const upload = multer({ 
  storage, 
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'photo') {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed for photo'));
      }
    } else if (file.fieldname === 'resume') {
      if (file.mimetype === 'application/pdf') {
        cb(null, true);
      } else {
        cb(new Error('Only PDF files are allowed for resume'));
      }
    } else {
      cb(null, true);
    }
  }
});

app.post("/api/pro-signup", upload.fields([
  { name: "resume", maxCount: 1 }, 
  { name: "photo", maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('📝 Professional signup request received');
    console.log('📋 Body:', req.body);
    console.log('📎 Files:', req.files);
    
    const { 
      name, 
      email, 
      password, 
      field, 
      experience, 
      headline, 
      summary, 
      linkedin,
      price 
    } = req.body;
    
    // Validation
    if (!name || !email || !password || !field || !experience || !headline || !summary || !price) {
      console.log('❌ Missing required fields');
      return res.status(400).json({ error: "All required fields must be filled" });
    }
    
    if (!req.files?.resume?.[0] || !req.files?.photo?.[0]) {
      console.log('❌ Missing files');
      return res.status(400).json({ error: "Photo and resume are required" });
    }
    
    // Check if expert already exists
    const existingExpert = await Expert.findOne({ email: email.toLowerCase() });
    if (existingExpert) {
      console.log('❌ Expert already exists:', email);
      return res.status(400).json({ error: "Expert with this email already exists" });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10);
    
    // Create expert
    const newExpert = await Expert.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hash,
      field: field.trim(),
      experience: parseInt(experience),
      headline: headline.trim(),
      summary: summary.trim(),
      linkedin: linkedin?.trim() || '',
      price: parseInt(price),
      resumePath: req.files.resume[0].path,
      avatar: req.files.photo[0].path,
      status: "pending"
    });
    
    console.log('✅ Expert registered:', newExpert.email);
    console.log('   Field:', newExpert.field);
    console.log('   Price:', '₹' + newExpert.price);
    console.log('   Resume:', newExpert.resumePath);
    console.log('   Photo:', newExpert.avatar);
    console.log('   Status:', newExpert.status);
    
    res.json({ 
      success: true,
      message: "Registration successful! Your profile will be reviewed by our team.",
      expert: {
        name: newExpert.name,
        email: newExpert.email,
        field: newExpert.field,
        status: newExpert.status
      }
    });
    
  } catch (err) {
    console.error('❌ Professional signup error:', err);
    res.status(500).json({ 
      error: "Registration failed: " + err.message 
    });
  }
});

/* ============================================================
   ROUTES - PROFILE
============================================================ */
app.get("/api/profile", async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: "Email required" });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() }).select('-password');
    if (user) {
      return res.json(user);
    }
    
    const expert = await Expert.findOne({ email: email.toLowerCase() }).select('-password');
    if (expert) {
      return res.json(expert);
    }
    
    res.status(404).json({ error: "User not found" });
  } catch (err) {
    console.error("❌ Profile error:", err);
    res.status(500).json({ error: "Failed to fetch profile" });
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
    
    console.log(`📜 Fetching messages for room: ${room}`);
    
    const messages = await Message.find({ room })
      .sort({ createdAt: 1 })
      .limit(100);
    
    console.log(`✅ Found ${messages.length} messages`);
    
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
    
    console.log(`📜 Fetching conversations for: ${email}`);
    
    const messages = await Message.find({
      room: { $regex: email }
    }).sort({ createdAt: -1 });
    
    const roomMap = {};
    messages.forEach(msg => {
      if (!roomMap[msg.room]) {
        roomMap[msg.room] = {
          room: msg.room,
          lastMessage: msg.message,
          lastMessageTime: msg.createdAt,
          otherEmail: msg.room.split('_').find(e => e !== email)
        };
      }
    });
    
    const conversations = Object.values(roomMap);
    console.log(`✅ Found ${conversations.length} conversations`);
    
    res.json(conversations);
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
    
    let filter = {};
    
    // Filter by status
    if (status !== "all") {
      filter.status = status;
    }
    
    // Filter by field/domain
    if (field && field !== "all") {
      filter.field = new RegExp(field, 'i');
    }

    const experts = await Expert.find(filter)
      .select("-password")
      .sort({ experience: -1, createdAt: -1 });
    
    console.log(`✅ FETCHED ${experts.length} experts (status: ${status}, field: ${field || 'all'})`);
    res.json(experts);
  } catch (err) {
    console.error("❌ EXPERTS ERROR:", err);
    res.status(500).json({ error: "Failed to fetch experts" });
  }
});

/* ============================================================
   🔐 ROUTES - ADMIN APPROVE/REJECT
============================================================ */
app.post("/api/admin/expert-status", adminAuth, async (req, res) => {
  try {
    console.log("🛡️ ADMIN STATUS UPDATE:", req.body);
    
    const { email, status } = req.body;
    if (!email || !["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid email or status" });
    }

    const expert = await Expert.findOneAndUpdate(
      { email: email.toLowerCase() },
      { status },
      { new: true }
    ).select('-password');

    if (!expert) {
      return res.status(404).json({ error: "Expert not found" });
    }

    console.log(`✅ ADMIN ${status.toUpperCase()}:`, email);
    res.json({ 
      success: true, 
      expert: { 
        name: expert.name, 
        email: expert.email,
        field: expert.field,
        status: expert.status 
      } 
    });
  } catch (err) {
    console.error("❌ ADMIN ERROR:", err);
    res.status(500).json({ error: "Update failed: " + err.message });
  }
});

/* ============================================================
   🔐 ROUTES - ADMIN HEALTH CHECK
============================================================ */
app.get("/api/health", adminAuth, (req, res) => {
  res.json({ 
    status: "healthy", 
    onlineExperts: Object.values(onlineUsers).filter(u => u.role === 'expert').length,
    adminAccess: true,
    timestamp: new Date().toISOString()
  });
});

/* ============================================================
   💳 RAZORPAY PAYMENT ROUTES
============================================================ */

// CREATE PAYMENT ORDER
app.post("/api/create-order", authMiddleware, async (req, res) => {
  try {
    const { expertEmail, expertField } = req.body;
    const clientEmail = req.user.email;
    const clientName = req.user.name;
    
    console.log(`💳 Creating order for ${clientEmail} → ${expertEmail}`);
    
    // Get expert details and price
    const expert = await Expert.findOne({ email: expertEmail.toLowerCase() });
    if (!expert) {
      return res.status(404).json({ error: "Expert not found" });
    }
    
    if (expert.status !== 'approved') {
      return res.status(400).json({ error: "Expert not approved yet" });
    }
    
    const amount = expert.price || 500;
    
    // Create Razorpay order
    const options = {
      amount: amount * 100, // Convert to paise
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
      notes: {
        expertEmail,
        expertField: expert.field,
        clientEmail,
        clientName,
        expertName: expert.name,
        purpose: 'Expert Consultation'
      }
    };
    
    const order = await razorpay.orders.create(options);
    
    // Save payment record
    await Payment.create({
      orderId: order.id,
      amount: amount,
      currency: 'INR',
      status: 'created',
      clientEmail,
      expertEmail,
      expertField: expert.field,
      clientName,
      notes: options.notes
    });
    
    console.log(`✅ Order created: ${order.id} for ₹${amount}`);
    
    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: process.env.RAZORPAY_KEY_ID || 'rzp_test_YOUR_KEY_ID',
      expertName: expert.name,
      expertField: expert.field
    });
    
  } catch (error) {
    console.error('❌ Order creation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create order',
      error: error.message
    });
  }
});

// VERIFY PAYMENT
app.post("/api/verify-payment", authMiddleware, async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body;
    
    console.log(`💳 Verifying payment: ${razorpay_payment_id}`);
    
    // Generate signature for verification
    const generated_signature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'YOUR_KEY_SECRET')
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');
    
    // Verify signature
    if (generated_signature === razorpay_signature) {
      console.log('✅ Payment signature verified');
      
      // Update payment record
      const payment = await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { 
          paymentId: razorpay_payment_id,
          signature: razorpay_signature,
          status: 'paid',
          verified: true
        },
        { new: true }
      );
      
      if (!payment) {
        return res.status(404).json({ error: "Payment record not found" });
      }
      
      console.log(`✅ Payment verified: ${razorpay_payment_id}`);
      console.log(`   Client: ${payment.clientEmail}`);
      console.log(`   Expert: ${payment.expertEmail}`);
      console.log(`   Amount: ₹${payment.amount}`);
      
      res.json({
        success: true,
        message: 'Payment verified successfully',
        paymentId: razorpay_payment_id,
        orderId: razorpay_order_id,
        expertEmail: payment.expertEmail,
        amount: payment.amount
      });
      
    } else {
      console.log('❌ Payment verification failed - signature mismatch');
      
      await Payment.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { status: 'failed' }
      );
      
      res.status(400).json({
        success: false,
        message: 'Payment verification failed'
      });
    }
    
  } catch (error) {
    console.error('❌ Verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Verification failed',
      error: error.message
    });
  }
});

// GET PAYMENT STATUS
app.get("/api/payment-status/:paymentId", authMiddleware, async (req, res) => {
  try {
    const { paymentId } = req.params;
    
    // Check our database first
    const localPayment = await Payment.findOne({ paymentId });
    
    if (localPayment) {
      return res.json({
        success: true,
        status: localPayment.status,
        amount: localPayment.amount,
        currency: localPayment.currency,
        verified: localPayment.verified,
        expertEmail: localPayment.expertEmail,
        clientEmail: localPayment.clientEmail
      });
    }
    
    // Fetch from Razorpay if not in database
    const payment = await razorpay.payments.fetch(paymentId);
    
    res.json({
      success: true,
      status: payment.status,
      amount: payment.amount / 100,
      currency: payment.currency,
      method: payment.method
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch payment status',
      error: error.message
    });
  }
});

// CHECK IF USER HAS PAID FOR EXPERT
app.get("/api/check-payment", authMiddleware, async (req, res) => {
  try {
    const { expertEmail } = req.query;
    const clientEmail = req.user.email;
    
    const payment = await Payment.findOne({
      clientEmail,
      expertEmail: expertEmail.toLowerCase(),
      status: 'paid',
      verified: true
    }).sort({ createdAt: -1 });
    
    res.json({
      hasPaid: !!payment,
      payment: payment ? {
        paymentId: payment.paymentId,
        amount: payment.amount,
        date: payment.createdAt
      } : null
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET USER'S PAYMENT HISTORY
app.get("/api/my-payments", authMiddleware, async (req, res) => {
  try {
    const email = req.user.email;
    
    const payments = await Payment.find({
      $or: [
        { clientEmail: email },
        { expertEmail: email }
      ]
    }).sort({ createdAt: -1 });
    
    console.log(`✅ Found ${payments.length} payments for ${email}`);
    res.json(payments);
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// RAZORPAY WEBHOOK (Optional - for production)
app.post("/api/razorpay-webhook", async (req, res) => {
  try {
    const webhookSignature = req.headers['x-razorpay-signature'];
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
    
    if (!webhookSecret) {
      console.log('⚠️ Webhook secret not configured');
      return res.status(200).json({ status: 'ok' });
    }
    
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(JSON.stringify(req.body))
      .digest('hex');
    
    if (webhookSignature === expectedSignature) {
      console.log('✅ Webhook verified');
      
      const event = req.body.event;
      const payload = req.body.payload;
      
      switch (event) {
        case 'payment.captured':
          console.log('💰 Payment captured:', payload.payment.entity.id);
          await Payment.findOneAndUpdate(
            { orderId: payload.payment.entity.order_id },
            { 
              status: 'paid',
              paymentId: payload.payment.entity.id 
            }
          );
          break;
          
        case 'payment.failed':
          console.log('❌ Payment failed:', payload.payment.entity.id);
          await Payment.findOneAndUpdate(
            { orderId: payload.payment.entity.order_id },
            { status: 'failed' }
          );
          break;
          
        default:
          console.log('📌 Unhandled event:', event);
      }
      
      res.json({ status: 'ok' });
    } else {
      console.log('❌ Invalid webhook signature');
      res.status(400).json({ error: 'Invalid signature' });
    }
  } catch (error) {
    console.error('❌ Webhook error:', error);
    res.status(500).json({ error: error.message });
  }
});

/* ============================================================
   AI CORE
============================================================ */
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "");
let activeModel;

(async () => {
  try {
    if (process.env.GEMINI_API_KEY) {
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${process.env.GEMINI_API_KEY}`);
      const d = await r.json();
      const model = d.models.find(m => m.name.includes("flash"));
      activeModel = genAI.getGenerativeModel({ model: model.name.split("/")[1] });
      console.log("✨ AI Ready");
    }
  } catch (err) {
    console.log("⚠️ AI disabled");
  }
})();

app.post("/api/ai/ask", async (req, res) => {
  try {
    if (!activeModel) return res.status(503).json({ error: "AI unavailable" });
    const result = await activeModel.generateContent(req.body.prompt);
    res.json({ answer: result.response.text() });
  } catch (err) {
    res.status(500).json({ error: "AI failed" });
  }
});

/* ============================================================
   SOCKET.IO - LIVE CHAT & EXPERTS
============================================================ */
const onlineUsers = {};

io.on("connection", (socket) => {
  console.log("🔌 Socket connected:", socket.id);

  // Authentication
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
        name: name || email.split('@')[0],
        role,
        field: expert?.field,
        status: expert?.status || 'client',
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

  // Manual online status
  socket.on("user_online", ({ email, name, role }) => {
    onlineUsers[email] = { 
      socketId: socket.id, 
      name, 
      role, 
      connectedAt: new Date() 
    };
    console.log("✅ User online:", email, role);
    io.emit("online_users", onlineUsers);
  });

  // Join private room
  socket.on("join_private", async (room) => {
    socket.join(room);
    console.log(`📥 Socket ${socket.id} joined room: ${room}`);
    
    try {
      const history = await Message.find({ room })
        .sort({ createdAt: 1 })
        .limit(50);
      socket.emit("chat_history", history);
      console.log(`📜 Sent ${history.length} messages to ${socket.id}`);
    } catch (err) {
      console.error("❌ Error loading chat history:", err);
    }
  });

  // Send message
  socket.on("send_private_message", async (data) => {
    try {
      console.log("📤 Message received from socket:", socket.id);
      console.log("   Room:", data.room);
      console.log("   Author:", data.author);
      console.log("   Message:", data.message);
      
      const msg = await Message.create(data);
      console.log("✅ Message saved to DB with ID:", msg._id);
      
      io.to(data.room).emit("receive_message", msg);
      console.log(`📨 Message broadcast to room: ${data.room}`);
      
      const emails = data.room.split('_');
      emails.forEach(email => {
        if (onlineUsers[email] && onlineUsers[email].socketId) {
          io.to(onlineUsers[email].socketId).emit("new_message_notification", {
            room: data.room,
            message: msg
          });
          console.log(`🔔 Direct notification sent to: ${email}`);
        }
      });
      
    } catch (err) {
      console.error("❌ Message save failed:", err);
      socket.emit("error", "Message failed");
    }
  });

  // Disconnect
  socket.on("disconnect", () => {
    for (let email in onlineUsers) {
      if (onlineUsers[email].socketId === socket.id) {
        console.log("❌ User disconnected:", email);
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
  console.log(`🚀 SolutionHub v9.0 LIVE - FULL SYSTEM 🎉`);
  console.log(`🚀 ============================================`);
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`💬 Socket.IO: Ready`);
  console.log(`💳 Razorpay: ${process.env.RAZORPAY_KEY_ID ? 'Enabled ✅' : 'TEST MODE'}`);
  console.log(`🤖 AI: ${process.env.GEMINI_API_KEY ? 'Enabled ✅' : 'Disabled'}`);
  console.log(`🔐 Admin Login: http://localhost:${PORT}/admin-login.html`);
  console.log(`🛡️ Admin Dashboard: http://localhost:${PORT}/admin.html`);
  console.log(`✅ Public Experts: http://localhost:${PORT}/experts.html`);
  console.log(`💬 Chat System: FULLY ENABLED`);
  console.log(`💰 Payment System: ACTIVE`);
  console.log(`👥 Expert Profiles: ENHANCED`);
  console.log(`📂 Expert Domains: 11 Categories`);
  console.log(`🔑 Admin Secret: ${ADMIN_SECRET.substring(0, 10)}...`);
  console.log(`🔑 Razorpay Key: ${(process.env.RAZORPAY_KEY_ID || 'NOT_SET').substring(0, 15)}...`);
  console.log(`🚀 ============================================\n`);
});
