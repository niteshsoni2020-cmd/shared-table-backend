// server.js - SECURE VERSION

require('dotenv').config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs"); // SECURITY: Password Hashing

// 1. Initialize App
const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// --- 2. CONNECT TO MONGODB ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => console.error("❌ MongoDB Error:", err));

// --- 3. SETUP CLOUDINARY ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "shared-table-uploads",
    allowed_formats: ["jpg", "png", "jpeg"]
  }
});
const upload = multer({ storage: storage });

// --- 4. SETUP EMAIL ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendEmail({ to, subject, html }) {
  if (!process.env.EMAIL_USER) return;
  try {
    await transporter.sendMail({ from: `"The Shared Table Story" <${process.env.EMAIL_USER}>`, to, subject, html });
  } catch (err) { console.error("❌ Email failed:", err.message); }
}

// --- 5. SCHEMAS ---
const schemaOpts = { toJSON: { virtuals: true }, toObject: { virtuals: true } };

const notificationSchema = new mongoose.Schema({
    message: String,
    type: { type: String, default: "info" },
    date: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String, // Now stores HASH, not text
  role: { type: String, default: "Guest" },
  profilePic: { type: String, default: "" },
  isPremiumHost: { type: Boolean, default: false },
  vacationMode: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  bio: String, location: String, mobile: String,
  preferences: [String],
  payoutDetails: Object, 
  notifications: [notificationSchema],
  guestRating: { type: Number, default: 0 },
  guestReviewCount: { type: Number, default: 0 }
}, schemaOpts);

// (Experience, Booking, Review, Bookmark Schemas remain unchanged)
const experienceSchema = new mongoose.Schema({
  hostId: String, hostName: String, hostPic: String,
  title: String, description: String, city: String,
  price: Number, maxGuests: Number, originalMaxGuests: Number,
  startDate: String, endDate: String, blockedDates: [String],
  availableDays: { type: [String], default: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] },
  isPaused: { type: Boolean, default: false },
  tags: [String], timeSlots: [String],
  imageUrl: String, images: [String],
  lat: { type: Number, default: -37.8136 }, lng: { type: Number, default: 144.9631 },
  privateCapacity: Number, privatePrice: Number,
  dynamicDiscounts: Object,
  averageRating: { type: Number, default: 0 }, reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

const bookingSchema = new mongoose.Schema({
  experienceId: String, guestId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  guestName: String, guestEmail: String,
  numGuests: Number, bookingDate: String, timeSlot: String,
  status: { type: String, default: "pending_payment" },
  stripeSessionId: String, paymentStatus: { type: String, default: "unpaid" },
  pricing: Object, refundAmount: Number, cancellationReason: String,
  dispute: { active: { type: Boolean, default: false }, reason: String, status: String },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

const reviewSchema = new mongoose.Schema({
  experienceId: String, bookingId: String, authorId: String, authorName: String,
  targetId: String, type: { type: String, default: "guest_to_host" }, 
  rating: Number, comment: String, hostReply: String,
  date: { type: Date, default: Date.now }
}, schemaOpts);

const Bookmark = mongoose.model("Bookmark", new mongoose.Schema({ userId: String, experienceId: String }, schemaOpts));
const User = mongoose.model("User", userSchema);
const Experience = mongoose.model("Experience", experienceSchema);
const Booking = mongoose.model("Booking", bookingSchema);
const Review = mongoose.model("Review", reviewSchema);

// --- 6. MIDDLEWARE ---
async function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Missing header" });
  const token = authHeader.split(" ")[1]; 
  const dbId = token.replace("user-", ""); 
  try {
      const user = await User.findById(dbId);
      if (!user) return res.status(401).json({ message: "User not found" });
      req.user = user;
      next();
  } catch (err) { res.status(401).json({ message: "Invalid Token" }); }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ message: "Access denied. Admins only." });
    next();
  });
}

function sanitizeUser(u) { 
    const obj = u.toObject({ virtuals: true });
    if (obj.payoutDetails) {
        obj.payoutDetails = { ...obj.payoutDetails, bsb: "***", accountNumber: "****" + (obj.payoutDetails.accountNumber ? obj.payoutDetails.accountNumber.slice(-4) : "0000") };
    }
    const { password, ...safe } = obj; 
    return { ...safe, isHost: obj.isPremiumHost }; 
}

// --- 7. HELPER: CAPACITY CHECK ---
async function checkCapacity(experienceId, date, timeSlot, newGuests) {
    const existing = await Booking.find({ experienceId, bookingDate: date, timeSlot, status: { $in: ['confirmed', 'paid'] } });
    const currentCount = existing.reduce((sum, b) => sum + b.numGuests, 0);
    const exp = await Experience.findById(experienceId);
    
    if (exp.isPaused) return { available: false, message: "Host is currently not accepting bookings." };
    if (exp.blockedDates && exp.blockedDates.includes(date)) return { available: false, message: "Date is blocked by host." };

    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const searchDay = days[new Date(date).getUTCDay()];
    if (exp.availableDays && !exp.availableDays.includes(searchDay)) {
        return { available: false, message: `Host is not available on ${searchDay}s.` };
    }
    
    if (currentCount + newGuests > exp.maxGuests) {
        return { available: false, remaining: exp.maxGuests - currentCount, message: `Only ${exp.maxGuests - currentCount} spots left.` };
    }
    return { available: true };
}

function calculateRefund(booking, experience) {
    const now = new Date();
    const startStr = experience.startDate + "T" + (booking.timeSlot ? booking.timeSlot.split('-')[0] : '00:00');
    const startTime = new Date(startStr);
    const bookingTime = new Date(booking.createdAt);
    const hoursUntilStart = (startTime - now) / (1000 * 60 * 60);
    const hoursSinceBooked = (now - bookingTime) / (1000 * 60 * 60);

    if (hoursUntilStart < 48) return { percent: 0, amount: 0, reason: "Cancellation within 48h" };
    if (hoursSinceBooked > 24) {
        const refund = booking.pricing.totalPrice * 0.70;
        return { percent: 70, amount: parseFloat(refund.toFixed(2)), reason: "Standard cancellation (30% fee)" };
    }
    return { percent: 100, amount: booking.pricing.totalPrice, reason: "Cooling off period" };
}

// ====================== ROUTES ======================

// 🔴 SECURITY FIX: LOCKED DOWN UPLOAD ROUTE
app.post("/api/upload", authMiddleware, upload.array("photos", 3), (req, res) => {
  if (!req.files) return res.status(400).json({ message: "No files" });
  res.json({ images: req.files.map(f => f.path) });
});

// --- AUTH ---
app.post("/api/auth/register", async (req, res) => {
  try {
      if (await User.findOne({ email: req.body.email })) return res.status(400).json({ message: "Email taken" });
      
      // 🔴 SECURITY FIX: HASH PASSWORD
      const hashedPassword = await bcrypt.hash(req.body.password, 10);

      const user = new User({ ...req.body, password: hashedPassword, role: "Guest", notifications: [{message: "Welcome to The Shared Table!", type: "success"}] });
      await user.save();
      
      sendEmail({ 
          to: user.email, 
          subject: `Welcome to The Shared Table Story, ${user.name} 🌍🍽️`, 
          html: `<p>Hi ${user.name}, welcome to the family.</p>`
      });

      res.status(201).json({ token: `user-${user._id}`, user: sanitizeUser(user) });
  } catch (e) { res.status(500).json({ message: "Error" }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
      const user = await User.findOne({ email: req.body.email });
      if (!user) return res.status(400).json({ message: "Invalid credentials" });

      // 🔴 SECURITY FIX: COMPARE HASH
      const isMatch = await bcrypt.compare(req.body.password, user.password);
      if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

      res.json({ token: `user-${user._id}`, user: sanitizeUser(user) });
  } catch (e) { res.status(500).json({ message: "Error" }); }
});

// (All other routes remain unchanged - pasting abbreviated versions for brevity but keep them full in your file)
app.post("/api/auth/reset", async (req, res) => res.json({ message: "If that email exists, we sent a link." }));
app.get("/api/me", authMiddleware, (req, res) => res.json(sanitizeUser(req.user)));
app.put("/api/me", authMiddleware, async (req, res) => { 
    const { role, isAdmin, payoutDetails, vacationMode, ...updates } = req.body;
    if (typeof vacationMode !== 'undefined') { req.user.vacationMode = vacationMode; await Experience.updateMany({ hostId: req.user._id }, { isPaused: vacationMode }); }
    Object.assign(req.user, updates); await req.user.save(); res.json(sanitizeUser(req.user)); 
});
app.get("/api/notifications", authMiddleware, async (req, res) => { res.json((req.user.notifications || []).reverse().slice(0, 5)); });
app.post("/api/host/onboard", authMiddleware, async (req, res) => { req.user.role = "Host"; req.user.isPremiumHost = true; req.user.payoutDetails = { ...req.body, country: "Australia" }; req.user.notifications.push({ message: "You are now a verified Host!", type: "success" }); await req.user.save(); res.json(sanitizeUser(req.user)); });
app.post("/api/experiences", authMiddleware, async (req, res) => { const { maxGuests, images, ...rest } = req.body; const exp = new Experience({ hostId: req.user._id, hostName: req.user.name, hostPic: req.user.profilePic || "", maxGuests: Number(maxGuests), originalMaxGuests: Number(maxGuests), images: images || [], imageUrl: (images && images.length > 0) ? images[0] : null, isPaused: req.user.vacationMode || false, ...rest }); await exp.save(); res.status(201).json(exp); });
app.put("/api/experiences/:id", authMiddleware, async (req, res) => { const exp = await Experience.findById(req.params.id); if (!exp || exp.hostId !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" }); const { images, maxGuests, ...updates } = req.body; if (maxGuests) exp.maxGuests = maxGuests; if (images) { exp.images = images; exp.imageUrl = images[0]; } Object.assign(exp, updates); await exp.save(); res.json(exp); });
app.delete("/api/experiences/:id", authMiddleware, async (req, res) => { const exp = await Experience.findById(req.params.id); if (!exp || (exp.hostId !== String(req.user._id) && !req.user.isAdmin)) return res.status(403).json({ message: "Unauthorized" }); await Booking.updateMany({ experienceId: exp._id, status: 'confirmed' }, { status: 'cancelled_by_host', refundAmount: 100 }); await Experience.findByIdAndDelete(req.params.id); res.json({ message: "Deleted" }); });
app.get("/api/experiences", async (req, res) => { const { city, q, sort, date } = req.query; let query = { isPaused: false }; if (city) query.city = { $regex: city, $options: "i" }; if (q) query.title = { $regex: q, $options: "i" }; if (date) { query.startDate = { $lte: date }; query.endDate = { $gte: date }; const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]; const d = new Date(date); const dayName = days[d.getUTCDay()]; query.availableDays = { $in: [dayName] }; } let sortObj = {}; if (sort === 'price_asc') sortObj.price = 1; if (sort === 'rating_desc') sortObj.averageRating = -1; const exps = await Experience.find(query).sort(sortObj); res.json(exps); });
app.get("/api/experiences/:id", async (req, res) => { try { const exp = await Experience.findById(req.params.id); res.json(exp); } catch { res.status(404).json({ message: "Not found" }); } });
app.post("/api/experiences/:id/book", authMiddleware, async (req, res) => { const exp = await Experience.findById(req.params.id); if (exp.hostId === String(req.user._id)) return res.status(400).json({ message: "Self-booking not allowed." }); const { numGuests, isPrivate, bookingDate, timeSlot } = req.body; const cap = await checkCapacity(exp._id, bookingDate, timeSlot, Number(numGuests)); if (!cap.available) return res.status(400).json({ message: cap.message || `Only ${cap.remaining} spots left.` }); let total = exp.price * numGuests; if (isPrivate && exp.privatePrice) total = exp.privatePrice; const booking = new Booking({ experienceId: exp._id, guestId: req.user._id, guestName: req.user.name, guestEmail: req.user.email, numGuests, bookingDate, timeSlot, pricing: { totalPrice: parseFloat(total.toFixed(2)) } }); await booking.save(); try { const session = await stripe.checkout.sessions.create({ payment_method_types: ['card'], line_items: [{ price_data: { currency: 'aud', product_data: { name: exp.title }, unit_amount: Math.round(total * 100) }, quantity: 1 }], mode: 'payment', success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}&booking_id=${booking._id}`, cancel_url: `${req.headers.origin}/experience.html?id=${exp._id}`, }); booking.stripeSessionId = session.id; await booking.save(); res.json({ url: session.url }); } catch (e) { res.status(500).json({ message: "Payment failed" }); } });
app.post("/api/bookings/verify", authMiddleware, async (req, res) => { const { bookingId, sessionId } = req.body; const booking = await Booking.findById(bookingId); if (!booking || booking.status === "confirmed") return res.json({ status: booking ? booking.status : "not_found" }); try { const session = await stripe.checkout.sessions.retrieve(sessionId); if (session.payment_status === 'paid') { booking.status = "confirmed"; booking.paymentStatus = "paid"; await booking.save(); sendEmail({ to: req.user.email, subject: `Confirmed!`, html: `<p>Booking Confirmed</p>` }); const exp = await Experience.findById(booking.experienceId); const host = await User.findById(exp.hostId); if (host) { host.notifications.push({ message: `New Booking: ${req.user.name}`, type: "success" }); await host.save(); } return res.json({ status: "confirmed" }); } return res.status(400).json({ status: "unpaid" }); } catch (e) { res.status(500).json({ message: "Verification failed" }); } });
app.put("/api/bookings/:id/reschedule", authMiddleware, async (req, res) => { const { newDate, newSlot } = req.body; const b = await Booking.findById(req.params.id); if (!b || b.guestId.toString() !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" }); const cap = await checkCapacity(b.experienceId, newDate, newSlot, b.numGuests); if (!cap.available) return res.status(400).json({ message: cap.message }); b.bookingDate = newDate; b.timeSlot = newSlot; await b.save(); res.json({ message: "Rescheduled successfully!" }); });
app.post("/api/bookings/:id/cancel", authMiddleware, async (req, res) => { const b = await Booking.findById(req.params.id); if (b.guestId.toString() !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" }); const exp = await Experience.findById(b.experienceId); const refundData = calculateRefund(b, exp); b.status = "cancelled"; b.refundAmount = refundData.amount; b.cancellationReason = refundData.reason; await b.save(); res.json({ message: "Cancelled", refund: refundData }); });
app.post("/api/bookings/:id/report", authMiddleware, async (req, res) => { const { reason } = req.body; const b = await Booking.findById(req.params.id); if (!b) return res.status(404).json({ message: "Not found" }); b.dispute = { active: true, reason, status: "pending_admin" }; await b.save(); res.json({ message: "Reported." }); });
app.get("/api/my/bookings", authMiddleware, async (req, res) => { const bookings = await Booking.find({ guestId: req.user._id }); res.json(bookings); });
app.get("/api/host/bookings/:experienceId", authMiddleware, async (req, res) => { const exp = await Experience.findById(req.params.experienceId); if (exp.hostId !== String(req.user._id) && !req.user.isAdmin) return res.status(403).json({message: "Unauthorized"}); const bookings = await Booking.find({ experienceId: req.params.experienceId, status: { $in: ['confirmed', 'paid'] } }).populate("guestId", "name email mobile profilePic"); res.json(bookings); });
app.post("/api/reviews", authMiddleware, async (req, res) => { const { experienceId, bookingId, rating, comment, type, targetId } = req.body; const reviewType = type || "guest_to_host"; if(await Review.findOne({ bookingId, authorId: req.user._id })) return res.status(400).json({ message: "Duplicate" }); const review = new Review({ experienceId, bookingId, authorId: req.user._id, authorName: req.user.name, targetId, type: reviewType, rating, comment }); await review.save(); if (reviewType === "guest_to_host") { const reviews = await Review.find({ experienceId, type: "guest_to_host" }); const avg = reviews.reduce((acc, r) => acc + r.rating, 0) / reviews.length; await Experience.findByIdAndUpdate(experienceId, { averageRating: avg, reviewCount: reviews.length }); } else { const userReviews = await Review.find({ targetId, type: "host_to_guest" }); const avg = userReviews.reduce((acc, r) => acc + r.rating, 0) / userReviews.length; await User.findByIdAndUpdate(targetId, { guestRating: avg, guestReviewCount: userReviews.length }); } res.json(review); });
app.post("/api/reviews/:id/reply", authMiddleware, async (req, res) => { const review = await Review.findById(req.params.id); if(!review) return res.status(404).json({ message: "Not found" }); const exp = await Experience.findById(review.experienceId); if(exp.hostId !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" }); review.hostReply = req.body.reply; await review.save(); res.json({ message: "Replied" }); });
app.get("/api/experiences/:id/reviews", async (req, res) => { const reviews = await Review.find({ experienceId: req.params.id, type: "guest_to_host" }).sort({ date: -1 }); res.json(reviews); });
app.post("/api/bookmarks/:experienceId", authMiddleware, async (req, res) => { const { experienceId } = req.params; const userId = req.user._id; const existing = await Bookmark.findOne({ userId, experienceId }); if (existing) { await Bookmark.findByIdAndDelete(existing._id); return res.json({ message: "Removed" }); } await Bookmark.create({ userId, experienceId }); res.json({ message: "Added" }); });
app.get("/api/my/bookmarks", authMiddleware, async (req, res) => { const bms = await Bookmark.find({ userId: req.user._id }); res.json(bms.map(b => b.experienceId)); });
app.get("/api/my/bookmarks/details", authMiddleware, async (req, res) => { const bms = await Bookmark.find({ userId: req.user._id }); const exps = await Experience.find({ _id: { $in: bms.map(b => b.experienceId) } }); res.json(exps); });
app.get("/api/admin/stats", adminMiddleware, async (req, res) => { const revenueDocs = await Booking.find({ status: 'confirmed' }, "pricing"); res.json({ userCount: await User.countDocuments(), expCount: await Experience.countDocuments(), bookingCount: await Booking.countDocuments(), totalRevenue: revenueDocs.reduce((acc, b) => acc + (b.pricing.totalPrice || 0), 0) }); });
app.get("/api/admin/users", adminMiddleware, async (req, res) => { const users = await User.find({}, "name email role _id isPremiumHost"); res.json(users.map(u => ({ id: u._id, name: u.name, email: u.email, role: u.role }))); });
app.delete("/api/admin/users/:id", adminMiddleware, async (req, res) => { await User.findByIdAndDelete(req.params.id); res.json({ message: "User deleted" }); });
app.get("/api/admin/bookings", adminMiddleware, async (req, res) => { const bookings = await Booking.find().sort({ createdAt: -1 }).limit(50); res.json(bookings); });
app.post("/api/contact", async (req, res) => { await sendEmail({ to: process.env.EMAIL_USER, subject: `Contact`, html: `<p>${req.body.message}</p>` }); res.json({ message: "Sent" }); });
app.get("/api/recommendations", authMiddleware, async (req, res) => { const query = req.user.preferences?.length > 0 ? { tags: { $in: req.user.preferences }, isPaused: false } : { isPaused: false }; const exps = await Experience.find(query).sort({ averageRating: -1 }).limit(4); res.json(exps.length > 0 ? exps : await Experience.find({ isPaused: false }).limit(4)); });
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));