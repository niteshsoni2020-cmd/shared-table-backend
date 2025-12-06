// server.js - FINAL STABLE VERSION (Merged GPT Fixes + Gemini Features)

require('dotenv').config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs"); // Using pure JS version to avoid Render crash

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
  params: { folder: "shared-table-uploads", allowed_formats: ["jpg", "png", "jpeg"] }
});
const upload = multer({ storage: storage });

// --- 4. EMAIL ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});
async function sendEmail({ to, subject, html }) {
  if (!process.env.EMAIL_USER) return;
  try { await transporter.sendMail({ from: `"The Shared Table Story" <${process.env.EMAIL_USER}>`, to, subject, html }); } 
  catch (err) { console.error("❌ Email failed:", err.message); }
}

// --- 5. SCHEMAS ---
const schemaOpts = { toJSON: { virtuals: true }, toObject: { virtuals: true } };

const notificationSchema = new mongoose.Schema({ message: String, type: { type: String, default: "info" }, date: { type: Date, default: Date.now } });

const userSchema = new mongoose.Schema({
  name: String, email: { type: String, unique: true }, password: String,
  role: { type: String, default: "Guest" }, profilePic: { type: String, default: "" },
  isPremiumHost: { type: Boolean, default: false }, vacationMode: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false }, bio: String, location: String, mobile: String,
  preferences: [String], payoutDetails: Object, notifications: [notificationSchema],
  guestRating: { type: Number, default: 0 }, guestReviewCount: { type: Number, default: 0 }
}, schemaOpts);

const experienceSchema = new mongoose.Schema({
  hostId: String, hostName: String, hostPic: String,
  title: String, description: String, city: String,
  price: Number, maxGuests: Number, originalMaxGuests: Number,
  startDate: String, endDate: String, blockedDates: [String],
  availableDays: { type: [String], default: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] },
  isPaused: { type: Boolean, default: false },
  tags: [String], timeSlots: [String], imageUrl: String, images: [String],
  lat: { type: Number, default: -37.8136 }, lng: { type: Number, default: 144.9631 },
  privateCapacity: Number, privatePrice: Number, dynamicDiscounts: Object,
  averageRating: { type: Number, default: 0 }, reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

const bookingSchema = new mongoose.Schema({
  experienceId: String, guestId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  hostId: { type: String, required: false }, // Explicit Host ID storage
  guestName: String, guestEmail: String,
  numGuests: Number, bookingDate: String, timeSlot: String,
  guestNotes: { type: String, default: "" }, 
  status: { type: String, default: "pending_payment" },
  stripeSessionId: String, paymentStatus: { type: String, default: "unpaid" },
  pricing: Object, refundAmount: Number, cancellationReason: String,
  dispute: { active: { type: Boolean, default: false }, reason: String, status: String },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

// Virtuals for easy population
bookingSchema.virtual('experience', { ref: 'Experience', localField: 'experienceId', foreignField: '_id', justOne: true });
bookingSchema.virtual('user', { ref: 'User', localField: 'guestId', foreignField: '_id', justOne: true });

const reviewSchema = new mongoose.Schema({
  experienceId: String, bookingId: String, authorId: String, authorName: String, targetId: String, 
  type: { type: String, default: "guest_to_host" }, rating: Number, comment: String, hostReply: String, date: { type: Date, default: Date.now }
}, schemaOpts);

const Bookmark = mongoose.model("Bookmark", new mongoose.Schema({ userId: String, experienceId: String }, schemaOpts));
const User = mongoose.model("User", userSchema);
const Experience = mongoose.model("Experience", experienceSchema);
const Booking = mongoose.model("Booking", bookingSchema);
const Review = mongoose.model("Review", reviewSchema);

// --- MIDDLEWARE ---
async function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Missing header" });
  const token = authHeader.split(" ")[1]; const dbId = token.replace("user-", ""); 
  try { const user = await User.findById(dbId); if (!user) return res.status(401).json({ message: "User not found" }); req.user = user; next(); } catch (err) { res.status(401).json({ message: "Invalid Token" }); }
}
function adminMiddleware(req, res, next) { authMiddleware(req, res, () => { if (!req.user.isAdmin) return res.status(403).json({ message: "Access denied." }); next(); }); }
function sanitizeUser(u) { const obj = u.toObject({ virtuals: true }); if (obj.payoutDetails) { obj.payoutDetails = { ...obj.payoutDetails, bsb: "***", accountNumber: "****" + (obj.payoutDetails.accountNumber ? obj.payoutDetails.accountNumber.slice(-4) : "0000") }; } const { password, ...safe } = obj; return { ...safe, isHost: obj.isPremiumHost }; }
async function checkCapacity(experienceId, date, timeSlot, newGuests) {
    const existing = await Booking.find({ experienceId, bookingDate: date, timeSlot, status: { $in: ['confirmed', 'paid'] } });
    const currentCount = existing.reduce((sum, b) => sum + b.numGuests, 0);
    const exp = await Experience.findById(experienceId);
    if (exp.isPaused) return { available: false, message: "Host is paused." };
    if (exp.blockedDates && exp.blockedDates.includes(date)) return { available: false, message: "Date blocked." };
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const searchDay = days[new Date(date).getUTCDay()];
    if (exp.availableDays && !exp.availableDays.includes(searchDay)) return { available: false, message: `Closed on ${searchDay}s.` };
    if (currentCount + newGuests > exp.maxGuests) return { available: false, remaining: exp.maxGuests - currentCount, message: `Only ${exp.maxGuests - currentCount} spots left.` };
    return { available: true };
}
function calculateRefund(booking, exp) { 
    // Basic MVP logic: 100% refund if cancelled > 48 hours before
    return { percent: 0, amount: 0, reason: "Manual payment - coordinate with host" }; 
}

// --- ROUTES ---

// 1. Upload Images
app.post("/api/upload", authMiddleware, upload.array("photos", 3), (req, res) => { if (!req.files) return res.status(400).json({ message: "No files" }); res.json({ images: req.files.map(f => f.path) }); });

// 2. Auth Routes
app.post("/api/auth/register", async (req, res) => { try { if (await User.findOne({ email: req.body.email })) return res.status(400).json({ message: "Taken" }); const hashedPassword = await bcrypt.hash(req.body.password, 10); const user = new User({ ...req.body, password: hashedPassword, role: "Guest", notifications: [{message: "Welcome!", type: "success"}] }); await user.save(); sendEmail({ to: user.email, subject: `Welcome to The Shared Table Story 🌏`, html: `<p>Welcome ${user.name}!</p>` }); res.status(201).json({ token: `user-${user._id}`, user: sanitizeUser(user) }); } catch (e) { res.status(500).json({ message: "Error" }); } });
app.post("/api/auth/login", async (req, res) => { try { const user = await User.findOne({ email: req.body.email }); if (!user || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: "Invalid credentials" }); res.json({ token: `user-${user._id}`, user: sanitizeUser(user) }); } catch (e) { res.status(500).json({ message: "Error" }); } });
app.post("/api/auth/reset", async (req, res) => res.json({ message: "If valid, link sent." }));

// 🔴 FIX 1: API Alias Routes (So both /api/me and /api/auth/me work)
app.get("/api/auth/me", authMiddleware, (req, res) => res.json(sanitizeUser(req.user)));
app.get("/api/me", authMiddleware, (req, res) => res.json(sanitizeUser(req.user))); // Alias

app.put("/api/auth/update", authMiddleware, async (req, res) => {
    try {
        const { role, isAdmin, payoutDetails, vacationMode, ...updates } = req.body; 
        if (typeof vacationMode !== 'undefined') { 
            req.user.vacationMode = vacationMode; 
            await Experience.updateMany({ hostId: req.user._id }, { isPaused: vacationMode }); 
        } 
        if (req.body.payoutDetails) {
            req.user.payoutDetails = { ...req.user.payoutDetails, ...req.body.payoutDetails };
        }
        Object.assign(req.user, updates); 
        await req.user.save(); 
        res.json(sanitizeUser(req.user)); 
    } catch(err) { res.status(500).json({message: "Update failed"}); }
});

app.get("/api/notifications", authMiddleware, async (req, res) => { res.json((req.user.notifications || []).reverse().slice(0, 5)); });
app.post("/api/host/onboard", authMiddleware, async (req, res) => { req.user.role = "Host"; req.user.isPremiumHost = true; req.user.payoutDetails = { ...req.body, country: "Australia" }; req.user.notifications.push({ message: "Verified Host!", type: "success" }); await req.user.save(); res.json(sanitizeUser(req.user)); });

// 3. Experience Routes
app.post("/api/experiences", authMiddleware, async (req, res) => { const exp = new Experience({ hostId: req.user._id, hostName: req.user.name, hostPic: req.user.profilePic||"", isPaused: req.user.vacationMode||false, ...req.body, imageUrl: req.body.images[0]||"" }); await exp.save(); res.status(201).json(exp); });
app.put("/api/experiences/:id", authMiddleware, async (req, res) => { const exp = await Experience.findById(req.params.id); if (!exp || exp.hostId !== String(req.user._id)) return res.status(403).json({ message: "No" }); Object.assign(exp, req.body); if(req.body.images) exp.imageUrl = req.body.images[0]; await exp.save(); res.json(exp); });
app.delete("/api/experiences/:id", authMiddleware, async (req, res) => { const exp = await Experience.findById(req.params.id); if (!exp || (exp.hostId !== String(req.user._id) && !req.user.isAdmin)) return res.status(403).json({ message: "No" }); await Booking.updateMany({ experienceId: exp._id }, { status: 'cancelled_by_host' }); await Experience.findByIdAndDelete(req.params.id); res.json({ message: "Deleted" }); });

// Search Route (With Date Filtering)
app.get("/api/experiences", async (req, res) => { 
    const { city, q, sort, date, minPrice, maxPrice, category } = req.query; 
    let query = { isPaused: false }; 

    if (city) query.city = { $regex: city, $options: "i" }; 
    if (q) query.title = { $regex: q, $options: "i" }; 
    if (category) query.tags = { $in: [category] };
    if (minPrice || maxPrice) { query.price = {}; if (minPrice) query.price.$gte = Number(minPrice); if (maxPrice) query.price.$lte = Number(maxPrice); } 
    if (date) { 
        query.startDate = { $lte: date }; query.endDate = { $gte: date }; 
        const days = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"]; query.availableDays = { $in: [days[new Date(date).getUTCDay()]] }; 
    } 

    let sortObj = {}; 
    if (sort === 'price_asc') sortObj.price = 1; 
    if (sort === 'rating_desc') sortObj.averageRating = -1; 

    const exps = await Experience.find(query).sort(sortObj); 
    res.json(exps); 
});
app.get("/api/experiences/:id", async (req, res) => { try { const exp = await Experience.findById(req.params.id); res.json(exp); } catch { res.status(404).json({ message: "Not found" }); } });

// 4. Booking Routes
app.post("/api/experiences/:id/book", authMiddleware, async (req, res) => { 
    const exp = await Experience.findById(req.params.id); 
    if (exp.hostId === String(req.user._id)) return res.status(400).json({ message: "No self-booking." }); 
    const { numGuests, isPrivate, bookingDate, timeSlot, guestNotes } = req.body; 
    const cap = await checkCapacity(exp._id, bookingDate, timeSlot, Number(numGuests)); 
    if (!cap.available) return res.status(400).json({ message: cap.message }); 
    
    let total = exp.price * numGuests; 
    if (isPrivate && exp.privatePrice) total = exp.privatePrice; 
    
    // 🔴 FIX 2: Store hostId as String for reliable querying
    const booking = new Booking({ 
        experienceId: exp._id, 
        guestId: req.user._id, 
        guestName: req.user.name, 
        guestEmail: req.user.email,
        hostId: String(exp.hostId || req.user._id), // Force String
        numGuests, bookingDate, timeSlot, 
        guestNotes: guestNotes || "", 
        pricing: { totalPrice: parseFloat(total.toFixed(2)) } 
    }); 
    
    await booking.save(); 
    
    try { 
        const session = await stripe.checkout.sessions.create({ 
            payment_method_types: ['card'], 
            line_items: [{ price_data: { currency: 'aud', product_data: { name: exp.title }, unit_amount: Math.round(total * 100) }, quantity: 1 }], 
            mode: 'payment', 
            success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}&booking_id=${booking._id}`, 
            cancel_url: `${req.headers.origin}/experience.html?id=${exp._id}`, 
        }); 
        booking.stripeSessionId = session.id; 
        await booking.save(); 
        res.json({ url: session.url }); 
    } catch (e) { res.status(500).json({ message: "Payment failed" }); } 
});

app.post("/api/bookings/verify", authMiddleware, async (req, res) => { const { bookingId, sessionId } = req.body; const booking = await Booking.findById(bookingId); if (!booking || booking.status === "confirmed") return res.json({ status: booking ? booking.status : "not_found" }); try { const session = await stripe.checkout.sessions.retrieve(sessionId); if (session.payment_status === 'paid') { booking.status = "confirmed"; booking.paymentStatus = "paid"; await booking.save(); sendEmail({ to: req.user.email, subject: `Confirmed!`, html: `<p>Booking Confirmed</p>` }); const exp = await Experience.findById(booking.experienceId); const host = await User.findById(exp.hostId); if (host) { const notesHtml = booking.guestNotes ? `<p><strong>Guest Note:</strong> ${booking.guestNotes}</p>` : ""; host.notifications.push({ message: `New Booking: ${req.user.name}`, type: "success" }); await host.save(); sendEmail({ to: host.email, subject: `New Booking!`, html: `<p>${req.user.name} booked.</p>${notesHtml}` }); } return res.json({ status: "confirmed" }); } return res.status(400).json({ status: "unpaid" }); } catch (e) { res.status(500).json({ message: "Verification failed" }); } });

// 🔴 FIX 3: Host Booking Routes (Fixed Querying + New Route)
app.get("/api/bookings/host-bookings", authMiddleware, async (req, res) => {
    try {
        const hostId = String(req.user._id); // Ensure ID is string
        const bookings = await Booking.find({ hostId })
            .populate('experience', 'title images price')
            .populate('guestId', 'name email profilePic mobile') // Populate actual Guest info
            .populate('user', 'name email profilePic mobile')    // Fallback population
            .sort({ bookingDate: 1 });
        res.json(bookings);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// NEW: Per-experience guest list route (requested by frontend modal)
app.get("/api/host/bookings/:experienceId", authMiddleware, async (req, res) => {
    try {
        const hostId = String(req.user._id);
        const experienceId = req.params.experienceId;
        const bookings = await Booking.find({ hostId, experienceId })
            .populate('experience', 'title images price')
            .populate('guestId', 'name email profilePic mobile')
            .sort({ bookingDate: 1 });
        res.json(bookings);
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// 🔴 FIX 4: My Bookings Alias Route
app.get("/api/bookings/my-bookings", authMiddleware, async (req, res) => { 
    const bookings = await Booking.find({ guestId: req.user._id }).populate('experience').sort({ bookingDate: -1 });
    res.json(bookings); 
});
app.get("/api/my/bookings", authMiddleware, async (req, res) => { // Alias
    const bookings = await Booking.find({ guestId: req.user._id }).populate('experience').sort({ bookingDate: -1 });
    res.json(bookings); 
});

// 🔴 FIX 5: Cancel Booking Route (Missing Feature)
app.post("/api/bookings/:id/cancel", authMiddleware, async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.id);
        if (!booking) return res.status(404).json({ message: "Booking not found" });
        if (String(booking.guestId) !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" });
        if (booking.status === 'cancelled' || booking.status === 'cancelled_by_host') return res.status(400).json({ message: "Already cancelled" });
        
        booking.status = 'cancelled';
        booking.refundAmount = 0; // Stub: Add refund logic here
        booking.cancellationReason = "User requested cancellation";
        await booking.save();
        
        res.json({ message: "Booking cancelled.", refund: { amount: 0, reason: "Manual processing" } });
    } catch (err) { res.status(500).json({ message: "Server error" }); }
});

// 5. Review & Bookmark Routes
app.post("/api/reviews", authMiddleware, async (req, res) => { const { experienceId, bookingId, rating, comment, type, targetId } = req.body; const reviewType = type || "guest_to_host"; if(await Review.findOne({ bookingId, authorId: req.user._id })) return res.status(400).json({ message: "Duplicate" }); const review = new Review({ experienceId, bookingId, authorId: req.user._id, authorName: req.user.name, targetId, type: reviewType, rating, comment }); await review.save(); if (reviewType === "guest_to_host") { const reviews = await Review.find({ experienceId, type: "guest_to_host" }); const avg = reviews.reduce((acc, r) => acc + r.rating, 0) / reviews.length; await Experience.findByIdAndUpdate(experienceId, { averageRating: avg, reviewCount: reviews.length }); } else { const userReviews = await Review.find({ targetId, type: "host_to_guest" }); const avg = userReviews.reduce((acc, r) => acc + r.rating, 0) / userReviews.length; await User.findByIdAndUpdate(targetId, { guestRating: avg, guestReviewCount: userReviews.length }); } res.json(review); });
app.get("/api/experiences/:id/reviews", async (req, res) => { const reviews = await Review.find({ experienceId: req.params.id, type: "guest_to_host" }).sort({ date: -1 }); res.json(reviews); });
app.post("/api/bookmarks/:experienceId", authMiddleware, async (req, res) => { const { experienceId } = req.params; const userId = req.user._id; const existing = await Bookmark.findOne({ userId, experienceId }); if (existing) { await Bookmark.findByIdAndDelete(existing._id); return res.json({ message: "Removed" }); } await Bookmark.create({ userId, experienceId }); res.json({ message: "Added" }); });
app.get("/api/my/bookmarks/details", authMiddleware, async (req, res) => { const bms = await Bookmark.find({ userId: req.user._id }); const exps = await Experience.find({ _id: { $in: bms.map(b => b.experienceId) } }); res.json(exps); });

// 6. Admin & Utility Routes
app.get("/api/admin/stats", adminMiddleware, async (req, res) => { const revenueDocs = await Booking.find({ status: 'confirmed' }, "pricing"); res.json({ userCount: await User.countDocuments(), expCount: await Experience.countDocuments(), bookingCount: await Booking.countDocuments(), totalRevenue: revenueDocs.reduce((acc, b) => acc + (b.pricing.totalPrice || 0), 0) }); });
app.get("/api/recommendations", authMiddleware, async (req, res) => { const exps = await Experience.find({ isPaused: false }).sort({ averageRating: -1 }).limit(4); res.json(exps.length > 0 ? exps : await Experience.find({ isPaused: false }).limit(4)); });

// NUCLEAR SEED ROUTE
app.get("/api/admin/seed-force", async (req, res) => {
    try {
        await User.deleteMany({}); await Experience.deleteMany({}); await Review.deleteMany({}); await Booking.deleteMany({});
        const adminPass = await bcrypt.hash("admin", 10);
        const userPass = await bcrypt.hash("123", 10);
        await User.create({ name: `Super Admin`, email: `admin@sharedtable.com`, password: adminPass, role: `Admin`, isAdmin: true });
        const host = await User.create({ name: `Abhishek`, email: `founder@sharedtable.com`, password: userPass, role: `Host`, isPremiumHost: true, profilePic: `https://images.unsplash.com/photo-1599566150163-29194dcaad36?q=80&w=200&auto=format&fit=crop` });
        const exp = await Experience.create({ hostId: host._id, hostName: host.name, hostPic: host.profilePic, title: `Aussie Christmas Eve Feast`, city: `Melbourne`, price: 85, tags: ["Culture & Festivals"], availableDays: ["Fri", "Sat"], images: ["https://images.unsplash.com/photo-1576402187878-974f70c890a5?q=80&w=800&auto=format&fit=crop"] });
        res.send("✅ LIVE DATABASE SEEDED!");
    } catch(e) { res.status(500).send(e.message); }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));