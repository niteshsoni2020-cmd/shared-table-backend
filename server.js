// server.js

require('dotenv').config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const nodemailer = require("nodemailer");

// 1. Initialize App (MUST BE FIRST)
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
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendEmail({ to, subject, html }) {
  if (!process.env.EMAIL_USER) return;
  try {
    await transporter.sendMail({
      from: `"The Shared Table Story" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html
    });
    console.log(`📧 Email sent to ${to}`);
  } catch (err) {
    console.error("❌ Email failed:", err.message);
  }
}

// --- 5. SCHEMAS ---
const schemaOpts = { toJSON: { virtuals: true }, toObject: { virtuals: true } };

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "Guest" },
  isPremiumHost: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  bio: String, location: String, mobile: String,
  preferences: [String],
  agreements: Object,
  payoutDetails: Object
}, schemaOpts);

const experienceSchema = new mongoose.Schema({
  hostId: String,
  hostName: String,
  title: String, description: String, city: String,
  price: Number, maxGuests: Number, originalMaxGuests: Number,
  startDate: String, endDate: String,
  tags: [String], timeSlots: [String],
  imageUrl: String, images: [String],
  lat: { type: Number, default: -37.8136 },
  lng: { type: Number, default: 144.9631 },
  privateCapacity: Number, privatePrice: Number,
  dynamicDiscounts: Object,
  averageRating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

const bookingSchema = new mongoose.Schema({
  experienceId: String, guestId: String,
  numGuests: Number, bookingDate: String, timeSlot: String,
  status: { type: String, default: "pending_payment" },
  stripeSessionId: String,
  paymentStatus: { type: String, default: "unpaid" },
  pricing: Object,
  refundAmount: Number, cancellationReason: String,
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

const reviewSchema = new mongoose.Schema({
  experienceId: String, guestId: String, guestName: String,
  rating: Number, comment: String,
  date: { type: Date, default: Date.now }
}, schemaOpts);

const bookmarkSchema = new mongoose.Schema({
  userId: String, experienceId: String
}, schemaOpts);

const User = mongoose.model("User", userSchema);
const Experience = mongoose.model("Experience", experienceSchema);
const Booking = mongoose.model("Booking", bookingSchema);
const Review = mongoose.model("Review", reviewSchema);
const Bookmark = mongoose.model("Bookmark", bookmarkSchema);

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
    const { password, agreements, payoutDetails, ...safe } = obj; 
    return { ...safe, isHost: obj.isPremiumHost }; 
}

// --- 7. HELPERS ---
function calculateRefund(booking, experience) {
    const now = new Date();
    const startStr = experience.startDate + "T" + (booking.timeSlot ? booking.timeSlot.split('-')[0] : '00:00');
    const startTime = new Date(startStr);
    const bookingTime = new Date(booking.createdAt);
    
    const hoursUntilStart = (startTime - now) / (1000 * 60 * 60);
    const hoursSinceBooked = (now - bookingTime) / (1000 * 60 * 60);

    if (hoursUntilStart < 48) return { percent: 0, amount: 0, reason: "Cancellation within 48h of start" };
    if (hoursSinceBooked > 24) {
        const refund = booking.pricing.totalPrice * 0.70;
        return { percent: 70, amount: parseFloat(refund.toFixed(2)), reason: "Standard cancellation (30% fee)" };
    }
    return { percent: 100, amount: booking.pricing.totalPrice, reason: "Cooling off period" };
}

function getDiscountPercent(experience, guests) {
    const dd = experience.dynamicDiscounts || {};
    let best = 0;
    for (let g = 1; g <= guests; g++) {
      const val = dd[g] ?? dd[String(g)];
      if (typeof val === "number" && val >= best) best = val;
    }
    if (Object.keys(dd).length === 0) {
        if (guests <= 2) return 0;
        if (guests <= 4) return 15;
        return 30;
    }
    return best;
}

function getMaxDiscountForExperience(exp) {
    const dd = exp.dynamicDiscounts || {};
    let max = 0;
    Object.values(dd).forEach(v => { if(v > max) max = v; });
    return max || 30;
}


// ====================== ROUTES ======================

// --- UPLOAD ---
app.post("/api/upload", upload.array("photos", 3), (req, res) => {
  if (!req.files) return res.status(400).json({ message: "No files" });
  res.json({ images: req.files.map(f => f.path) });
});

// --- AUTH ---
app.post("/api/auth/register", async (req, res) => {
  try {
      if (await User.findOne({ email: req.body.email })) return res.status(400).json({ message: "Email taken" });
      
      const user = new User({ ...req.body, role: "Guest" });
      await user.save();
      
      sendEmail({
          to: user.email,
          subject: "Welcome to The Shared Table Story! 🌏",
          html: `<h1>Hi ${user.name},</h1><p>Welcome to our community! You can now book authentic local experiences or become a host.</p>`
      });

      res.status(201).json({ token: `user-${user._id}`, user: sanitizeUser(user) });
  } catch (e) { res.status(500).json({ message: "Error" }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
      const user = await User.findOne({ email: req.body.email, password: req.body.password });
      if (!user) return res.status(400).json({ message: "Invalid credentials" });
      res.json({ token: `user-${user._id}`, user: sanitizeUser(user) });
  } catch (e) { res.status(500).json({ message: "Error" }); }
});

app.get("/api/me", authMiddleware, (req, res) => res.json(sanitizeUser(req.user)));

app.put("/api/me", authMiddleware, async (req, res) => {
    Object.assign(req.user, req.body);
    await req.user.save();
    res.json(sanitizeUser(req.user));
});

app.post("/api/host/onboard", authMiddleware, async (req, res) => {
    req.user.role = "Host";
    req.user.isPremiumHost = true;
    req.user.payoutDetails = { ...req.body, country: "Australia" };
    await req.user.save();
    res.json(sanitizeUser(req.user));
});

// --- EXPERIENCES ---
app.post("/api/experiences", authMiddleware, async (req, res) => {
    const { maxGuests, images, ...rest } = req.body;
    const exp = new Experience({
        hostId: req.user._id,
        hostName: req.user.name,
        maxGuests: Number(maxGuests),
        originalMaxGuests: Number(maxGuests),
        images: images || [],
        imageUrl: (images && images.length > 0) ? images[0] : null,
        ...rest
    });
    await exp.save();
    res.status(201).json(exp);
});

app.put("/api/experiences/:id", authMiddleware, async (req, res) => {
    const exp = await Experience.findById(req.params.id);
    if (!exp) return res.status(404).json({ message: "Not found" });
    if (exp.hostId !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" });

    const { images, maxGuests, ...updates } = req.body;
    
    if (maxGuests) {
        const allowed = Math.ceil(exp.originalMaxGuests * 1.20);
        if (maxGuests > allowed) return res.status(400).json({ message: `Max capacity limit: ${allowed}` });
        exp.maxGuests = maxGuests;
    }
    
    if (images) { exp.images = images; exp.imageUrl = images[0]; }
    
    Object.assign(exp, updates);
    await exp.save();
    res.json(exp);
});

app.delete("/api/experiences/:id", authMiddleware, async (req, res) => {
    const exp = await Experience.findById(req.params.id);
    if (!exp) return res.status(404).json({ message: "Not found" });
    if (exp.hostId !== String(req.user._id) && !req.user.isAdmin) return res.status(403).json({ message: "Unauthorized" });

    await Booking.updateMany(
        { experienceId: exp._id, status: 'confirmed' },
        { status: 'cancelled_by_host', refundAmount: 100, cancellationReason: "Host deleted listing" }
    );

    await Experience.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
});

app.delete("/api/admin/experiences/:id", adminMiddleware, async (req, res) => {
    await Experience.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted by Admin" });
});

app.get("/api/experiences", async (req, res) => {
    const { city, q, sort } = req.query;
    let query = {};
    if (city) query.city = { $regex: city, $options: "i" };
    if (q) query.title = { $regex: q, $options: "i" };
    
    let sortObj = {};
    if (sort === 'price_asc') sortObj.price = 1;
    if (sort === 'price_desc') sortObj.price = -1;
    if (sort === 'rating_desc') sortObj.averageRating = -1;

    const exps = await Experience.find(query).sort(sortObj);
    res.json(exps);
});

app.get("/api/experiences/:id", async (req, res) => {
    try {
        const exp = await Experience.findById(req.params.id);
        res.json(exp);
    } catch { res.status(404).json({ message: "Not found" }); }
});

// --- BOOKINGS ---
app.post("/api/experiences/:id/book", authMiddleware, async (req, res) => {
  const exp = await Experience.findById(req.params.id);
  const { numGuests, isPrivate, bookingDate, timeSlot } = req.body;
  let total = exp.price * numGuests;
  if (isPrivate && exp.privatePrice) total = exp.privatePrice;
  
  const booking = new Booking({
      experienceId: exp._id, guestId: req.user._id, numGuests, bookingDate, timeSlot, 
      status: "pending_payment", paymentStatus: "unpaid", pricing: { totalPrice: parseFloat(total.toFixed(2)) }
  });
  await booking.save();

  try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
            price_data: {
                currency: 'aud',
                product_data: { name: exp.title, description: `${bookingDate} at ${timeSlot}` },
                unit_amount: Math.round(total * 100),
            },
            quantity: 1,
        }],
        mode: 'payment',
        success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}&booking_id=${booking._id}`,
        cancel_url: `${req.headers.origin}/experience.html?id=${exp._id}`,
      });

      booking.stripeSessionId = session.id;
      await booking.save();
      
      res.json({ url: session.url });
  } catch (e) {
      console.error("Stripe Error:", e);
      res.status(500).json({ message: "Payment creation failed" });
  }
});

app.post("/api/bookings/verify", authMiddleware, async (req, res) => {
    const { bookingId, sessionId } = req.body;
    const booking = await Booking.findById(bookingId);
    if (!booking) return res.status(404).json({ message: "Not found" });
    if (booking.status === "confirmed") return res.json({ status: "confirmed" });

    try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (session.payment_status === 'paid') {
            booking.status = "confirmed";
            booking.paymentStatus = "paid";
            await booking.save();

            // Email Guest
            sendEmail({
                to: req.user.email,
                subject: "Booking Confirmed! 🎉",
                html: `<h1>You're going to ${booking.experienceId}!</h1><p>Your booking for ${booking.bookingDate} is confirmed.</p>`
            });

            return res.json({ status: "confirmed" });
        } else {
            return res.status(400).json({ status: "unpaid" });
        }
    } catch (e) { res.status(500).json({ message: "Verification failed" }); }
});

app.post("/api/bookings/:id/cancel", authMiddleware, async (req, res) => {
    const b = await Booking.findById(req.params.id);
    if (b.guestId !== String(req.user._id)) return res.status(403).json({ message: "No" });
    
    const exp = await Experience.findById(b.experienceId);
    const refundData = calculateRefund(b, exp);

    b.status = "cancelled";
    b.refundAmount = refundData.amount;
    b.cancellationReason = refundData.reason;
    await b.save();
    res.json({ message: "Cancelled", refund: refundData });
});

app.get("/api/my/bookings", authMiddleware, async (req, res) => {
    const bookings = await Booking.find({ guestId: req.user._id });
    res.json(bookings);
});

// --- BOOKMARKS ---
app.post("/api/bookmarks/:experienceId", authMiddleware, async (req, res) => {
    const { experienceId } = req.params;
    const userId = req.user._id;
    const existing = await Bookmark.findOne({ userId, experienceId });
    if (existing) { await Bookmark.findByIdAndDelete(existing._id); return res.json({ message: "Removed" }); }
    await Bookmark.create({ userId, experienceId });
    res.json({ message: "Added" });
});

app.get("/api/my/bookmarks", authMiddleware, async (req, res) => {
    const bms = await Bookmark.find({ userId: req.user._id });
    res.json(bms.map(b => b.experienceId));
});

app.get("/api/my/bookmarks/details", authMiddleware, async (req, res) => {
    const bms = await Bookmark.find({ userId: req.user._id });
    const ids = bms.map(b => b.experienceId);
    const exps = await Experience.find({ _id: { $in: ids } });
    res.json(exps);
});

// --- REVIEWS ---
app.post("/api/reviews", authMiddleware, async (req, res) => {
    const { experienceId } = req.body;
    const review = new Review({ ...req.body, guestId: req.user._id, guestName: req.user.name });
    await review.save();
    
    const reviews = await Review.find({ experienceId });
    const avg = reviews.reduce((acc, r) => acc + r.rating, 0) / reviews.length;
    await Experience.findByIdAndUpdate(experienceId, { averageRating: avg, reviewCount: reviews.length });
    
    res.json(review);
});

app.get("/api/experiences/:id/reviews", async (req, res) => {
    const reviews = await Review.find({ experienceId: req.params.id }).sort({ date: -1 });
    res.json(reviews);
});

// --- ADMIN STATS ---
app.get("/api/admin/stats", adminMiddleware, async (req, res) => {
    const userCount = await User.countDocuments();
    const expCount = await Experience.countDocuments();
    const bookingCount = await Booking.countDocuments();
    res.json({ userCount, expCount, bookingCount, totalRevenue: 0 });
});

app.get("/api/admin/users", adminMiddleware, async (req, res) => {
    const users = await User.find({}, "name email role _id");
    res.json(users.map(u => ({ id: u._id, name: u.name, email: u.email, role: u.role })));
});

app.delete("/api/admin/users/:id", adminMiddleware, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: "User deleted" });
});

// --- CONTACT FORM ---
app.post("/api/contact", async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message) return res.status(400).json({ message: "Missing fields" });

  await sendEmail({
    to: process.env.EMAIL_USER,
    subject: `Contact: ${subject || "New Message"}`,
    html: `<h3>Message from ${name} (${email})</h3><p>${message}</p>`
  });

  res.json({ message: "Sent" });
});

// --- RECOMMENDATIONS ---
app.get("/api/recommendations", authMiddleware, async (req, res) => {
    const exps = await Experience.find().sort({ averageRating: -1 }).limit(4);
    res.json(exps);
});

app.get("/api/discounts/max", async (req, res) => res.json({ maxDiscount: 30 }));

// --- SEED ADMIN ---
app.get("/api/seed", async (req, res) => {
    const email = "admin@sharedtable.com";
    if (!await User.findOne({ email })) {
        await User.create({
            name: "Super Admin", email, password: "admin",
            role: "Admin", isAdmin: true, isPremiumHost: true
        });
        res.send("Admin created.");
    } else res.send("Admin exists.");
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));