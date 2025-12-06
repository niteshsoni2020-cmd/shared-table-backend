// server.js - FULL VERSION (Public Profile Route + Category Pillars + DISCOUNT LOGIC)

require('dotenv').config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");

// 🔹 Single Source of Truth for Categories (3 Pillars)
const CATEGORY_PILLARS = ["Culture", "Food", "Nature"];

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
  try {
    await transporter.sendMail({
      from: `"The Shared Table Story" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html
    });
  } catch (err) {
    console.error("❌ Email failed:", err.message);
  }
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
  password: String,
  role: { type: String, default: "Guest" },
  profilePic: { type: String, default: "" },
  isPremiumHost: { type: Boolean, default: false },
  vacationMode: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  bio: String,
  location: String,
  mobile: String,
  preferences: [String],
  payoutDetails: Object,
  notifications: [notificationSchema],
  guestRating: { type: Number, default: 0 },
  guestReviewCount: { type: Number, default: 0 }
}, schemaOpts);

const experienceSchema = new mongoose.Schema({
  hostId: String,
  hostName: String,
  hostPic: String,
  title: String,
  description: String,
  city: String,
  price: Number,
  maxGuests: Number,
  originalMaxGuests: Number,
  startDate: String,
  endDate: String,
  blockedDates: [String],
  availableDays: {
    type: [String],
    default: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
  },
  isPaused: { type: Boolean, default: false },
  tags: [String], // Supports Multi-Category: ["Food", "Culture"]
  timeSlots: [String],
  imageUrl: String,
  images: [String],
  lat: { type: Number, default: -37.8136 },
  lng: { type: Number, default: 144.9631 },
  privateCapacity: Number,
  privatePrice: Number,
  dynamicDiscounts: Object,
  averageRating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

const bookingSchema = new mongoose.Schema({
  experienceId: String,
  guestId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  hostId: { type: String, required: false },
  guestName: String,
  guestEmail: String,
  numGuests: Number,
  bookingDate: String,
  timeSlot: String,
  guestNotes: { type: String, default: "" },
  status: { type: String, default: "pending_payment" },
  stripeSessionId: String,
  paymentStatus: { type: String, default: "unpaid" },
  pricing: Object,
  refundAmount: Number,
  cancellationReason: String,
  dispute: {
    active: { type: Boolean, default: false },
    reason: String,
    status: String
  },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

// Virtuals
bookingSchema.virtual('experience', {
  ref: 'Experience',
  localField: 'experienceId',
  foreignField: '_id',
  justOne: true
});
bookingSchema.virtual('user', {
  ref: 'User',
  localField: 'guestId',
  foreignField: '_id',
  justOne: true
});

const reviewSchema = new mongoose.Schema({
  experienceId: String,
  bookingId: String,
  authorId: String,
  authorName: String,
  targetId: String,
  type: { type: String, default: "guest_to_host" },
  rating: Number,
  comment: String,
  hostReply: String,
  date: { type: Date, default: Date.now }
}, schemaOpts);

const Bookmark = mongoose.model("Bookmark", new mongoose.Schema({
  userId: String,
  experienceId: String
}, schemaOpts));
const User = mongoose.model("User", userSchema);
const Experience = mongoose.model("Experience", experienceSchema);
const Booking = mongoose.model("Booking", bookingSchema);
const Review = mongoose.model("Review", reviewSchema);

// --- MIDDLEWARE ---
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
  } catch (err) {
    res.status(401).json({ message: "Invalid Token" });
  }
}
function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ message: "Access denied." });
    next();
  });
}

// NEW UTILITY: Function to determine if a user has any active experiences
async function isHost(userId) {
  const count = await Experience.countDocuments({ hostId: userId });
  return count > 0;
}

function sanitizeUser(u) {
  const obj = u.toObject({ virtuals: true });
  if (obj.payoutDetails) {
    obj.payoutDetails = {
      ...obj.payoutDetails,
      bsb: "***",
      accountNumber:
        "****" +
        (obj.payoutDetails.accountNumber
          ? obj.payoutDetails.accountNumber.slice(-4)
          : "0000")
    };
  }
  const { password, ...safe } = obj;
  return { ...safe, isHost: obj.isPremiumHost };
}

async function checkCapacity(experienceId, date, timeSlot, newGuests) {
  const existing = await Booking.find({
    experienceId,
    bookingDate: date,
    timeSlot,
    status: { $in: ['confirmed', 'paid'] }
  });
  const currentCount = existing.reduce((sum, b) => sum + b.numGuests, 0);
  const exp = await Experience.findById(experienceId);
  if (exp.isPaused) return { available: false, message: "Host is paused." };
  if (exp.blockedDates && exp.blockedDates.includes(date)) return { available: false, message: "Date blocked." };
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const searchDay = days[new Date(date).getUTCDay()];
  if (exp.availableDays && !exp.availableDays.includes(searchDay)) {
    return { available: false, message: `Closed on ${searchDay}s.` };
  }
  if (currentCount + newGuests > exp.maxGuests) {
    return {
      available: false,
      remaining: exp.maxGuests - currentCount,
      message: `Only ${exp.maxGuests - currentCount} spots left.`
    };
  }
  return { available: true };
}
function calculateRefund(booking, exp) {
  return { percent: 0, amount: 0, reason: "Manual payment - coordinate with host" };
}

// --- ROUTES ---

// 1. Upload
app.post("/api/upload", authMiddleware, upload.array("photos", 3), (req, res) => {
  if (!req.files) return res.status(400).json({ message: "No files" });
  res.json({ images: req.files.map(f => f.path) });
});

// 2. Auth & User (UPDATED: Records Legal Timestamp)
app.post("/api/auth/register", async (req, res) => {
  try {
    if (await User.findOne({ email: req.body.email }))
      return res.status(400).json({ message: "Taken" });
    
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    
    const user = new User({
      ...req.body,
      password: hashedPassword,
      role: "Guest",
      notifications: [{ message: "Welcome!", type: "success" }],
      // LEGAL TIMESTAMP (New)
      termsAgreedAt: new Date(),
      termsVersion: "1.0" 
    });

    await user.save();
    
    sendEmail({
      to: user.email,
      subject: `Welcome to The Shared Table Story 🌏`,
      html: `<p>Welcome ${user.name}!</p>`
    });

    res.status(201).json({
      token: `user-${user._id}`,
      user: sanitizeUser(user)
    });
  } catch (e) {
    res.status(500).json({ message: "Error" });
  }
});

// 3. Experience Routes

// CREATE EXPERIENCE – with category sanitization
app.post("/api/experiences", authMiddleware, async (req, res) => {
  try {
    const body = req.body || {};

    // Normalize and sanitize tags against CATEGORY_PILLARS
    let tags = [];
    if (Array.isArray(body.tags)) {
      tags = body.tags;
    } else if (body.tags) {
      tags = [body.tags];
    }
    tags = [...new Set(tags.filter(t => CATEGORY_PILLARS.includes(t)))];

    const images = Array.isArray(body.images) ? body.images : [];
    const imageUrl = images[0] || body.imageUrl || "";

    const exp = new Experience({
      hostId: req.user._id.toString(),
      hostName: req.user.name,
      hostPic: req.user.profilePic || "",
      isPaused: req.user.vacationMode || false,
      ...body,
      tags,
      imageUrl
    });

    await exp.save();
    res.status(201).json(exp);
  } catch (err) {
    console.error("Create experience error:", err);
    res.status(500).json({ message: "Failed to create experience" });
  }
});

// UPDATE EXPERIENCE – with category sanitization
app.put("/api/experiences/:id", authMiddleware, async (req, res) => {
  try {
    const exp = await Experience.findById(req.params.id);
    if (!exp || exp.hostId !== String(req.user._id))
      return res.status(403).json({ message: "No" });

    const body = req.body || {};
    const { images, tags, ...updates } = body;

    // Handle tags if provided
    if (typeof tags !== "undefined") {
      let newTags = [];
      if (Array.isArray(tags)) {
        newTags = tags;
      } else if (tags) {
        newTags = [tags];
      }
      newTags = [...new Set(newTags.filter(t => CATEGORY_PILLARS.includes(t)))];
      exp.tags = newTags;
    }

    // Apply other updates
    Object.assign(exp, updates);

    // Handle primary image from images array
    if (Array.isArray(images) && images.length > 0) {
      exp.images = images;
      exp.imageUrl = images[0];
    }

    await exp.save();
    res.json(exp);
  } catch (err) {
    console.error("Update experience error:", err);
    res.status(500).json({ message: "Failed to update experience" });
  }
});

app.delete("/api/experiences/:id", authMiddleware, async (req, res) => {
  const exp = await Experience.findById(req.params.id);
  if (!exp || (exp.hostId !== String(req.user._id) && !req.user.isAdmin))
    return res.status(403).json({ message: "No" });
  await Booking.updateMany(
    { experienceId: exp._id },
    { status: "cancelled_by_host" }
  );
  await Experience.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

// Search (Updated with Date & Filters + Category Pillars)
app.get("/api/experiences", async (req, res) => {
  const { city, q, sort, date, minPrice, maxPrice, category } = req.query;
  let query = { isPaused: false };

  if (city) query.city = { $regex: city, $options: "i" };
  if (q) query.title = { $regex: q, $options: "i" };

  // Multi-Category Filtering with validation
  if (category && CATEGORY_PILLARS.includes(category)) {
    // experiences where tags includes `category`
    query.tags = { $in: [category] };
  }

  if (minPrice || maxPrice) {
    query.price = {};
    if (minPrice) query.price.$gte = Number(minPrice);
    if (maxPrice) query.price.$lte = Number(maxPrice);
  }

  if (date) {
    query.startDate = { $lte: date };
    query.endDate = { $gte: date };
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    query.availableDays = { $in: [days[new Date(date).getUTCDay()]] };
  }

  let sortObj = {};
  if (sort === "price_asc") sortObj.price = 1;
  if (sort === "rating_desc") sortObj.averageRating = -1;

  const exps = await Experience.find(query).sort(sortObj);
  res.json(exps);
});

app.get("/api/experiences/:id", async (req, res) => {
  try {
    const exp = await Experience.findById(req.params.id);
    res.json(exp);
  } catch {
    res.status(404).json({ message: "Not found" });
  }
});

// NEW ROUTE: Recommendation Engine (Item #55)
app.get("/api/experiences/:id/similar", async (req, res) => {
  try {
    const currentExp = await Experience.findById(req.params.id);
    if (!currentExp) return res.status(404).json({ message: "Not found" });

    // Logic: Find experiences with matching Tags OR same City
    // Exclude the current experience
    const similar = await Experience.find({
      _id: { $ne: currentExp._id }, // Not the current one
      isPaused: false,
      $or: [
        { tags: { $in: currentExp.tags } }, // Same Category
        { city: currentExp.city }           // Same City
      ]
    })
    .limit(3) // Top 3 results
    .select('title price images imageUrl city averageRating'); // Optimization

    // Fallback: If no similar found, just show generic top rated
    if (similar.length === 0) {
       const fallback = await Experience.find({ 
           _id: { $ne: currentExp._id }, 
           isPaused: false 
       })
       .sort({ averageRating: -1 })
       .limit(3)
       .select('title price images imageUrl city averageRating');
       return res.json(fallback);
    }

    res.json(similar);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 4. Booking Routes (UPDATED with Item #62 & #54 Discount Logic)
app.post("/api/experiences/:id/book", authMiddleware, async (req, res) => {
  const exp = await Experience.findById(req.params.id);
  if (!exp) return res.status(404).json({ message: "Experience not found" });

  if (exp.hostId === String(req.user._id))
    return res.status(400).json({ message: "No self-booking." });

  const { numGuests, isPrivate, bookingDate, timeSlot, guestNotes } = req.body;
  const guests = parseInt(numGuests) || 1;

  // Check Capacity
  const cap = await checkCapacity(
    exp._id,
    bookingDate,
    timeSlot,
    guests
  );
  if (!cap.available) return res.status(400).json({ message: cap.message });

  // --- 🔴 PRICING LOGIC START (Zero Blind Spots) ---
  let unitPrice = exp.price;
  let total = unitPrice * guests;
  let description = `${guests} Guests`;

  // Apply 10% Discount for 3+ Guests
  if (guests >= 3) {
      total = total * 0.90; // Apply 10% off
      description += " (10% Group Discount Applied)";
  }

  // Handle Private Booking Override (if applicable)
  if (isPrivate && exp.privatePrice) {
      total = exp.privatePrice;
      description = "Private Booking";
  }
  // --- 🔴 PRICING LOGIC END ---

  const booking = new Booking({
    experienceId: exp._id,
    guestId: req.user._id,
    guestName: req.user.name,
    guestEmail: req.user.email,
    hostId: String(exp.hostId || req.user._id),
    numGuests: guests,
    bookingDate,
    timeSlot,
    guestNotes: guestNotes || "",
    pricing: { totalPrice: parseFloat(total.toFixed(2)) }
  });

  await booking.save();

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "aud",
            product_data: { 
                name: exp.title,
                description: description // Shows up on Stripe Checkout Page
            },
            unit_amount: Math.round(total * 100 / guests) // Stripe expects unit price, so we reverse-calc
          },
          quantity: guests
        }
      ],
      mode: "payment",
      success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}&booking_id=${booking._id}`,
      cancel_url: `${req.headers.origin}/experience.html?id=${exp._id}`
    });
    booking.stripeSessionId = session.id;
    await booking.save();
    res.json({ url: session.url });
  } catch (e) {
    console.error("Stripe Error:", e);
    res.status(500).json({ message: "Payment initialization failed" });
  }
});

app.post("/api/bookings/verify", authMiddleware, async (req, res) => {
  const { bookingId, sessionId } = req.body;
  const booking = await Booking.findById(bookingId);
  if (!booking || booking.status === "confirmed")
    return res.json({ status: booking ? booking.status : "not_found" });
  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status === "paid") {
      booking.status = "confirmed";
      booking.paymentStatus = "paid";
      await booking.save();

      sendEmail({
        to: req.user.email,
        subject: `Confirmed!`,
        html: `<p>Booking Confirmed</p>`
      });

      const exp = await Experience.findById(booking.experienceId);
      const host = await User.findById(exp.hostId);
      if (host) {
        const notesHtml = booking.guestNotes
          ? `<p><strong>Guest Note:</strong> ${booking.guestNotes}</p>`
          : "";
        host.notifications.push({
          message: `New Booking: ${req.user.name}`,
          type: "success"
        });
        await host.save();
        sendEmail({
          to: host.email,
          subject: `New Booking!`,
          html: `<p>${req.user.name} booked.</p>${notesHtml}`
        });
      }
      return res.json({ status: "confirmed" });
    }
    return res.status(400).json({ status: "unpaid" });
  } catch (e) {
    res.status(500).json({ message: "Verification failed" });
  }
});

// Host Dashboard Routes
app.get("/api/bookings/host-bookings", authMiddleware, async (req, res) => {
  try {
    const hostId = String(req.user._id);
    const bookings = await Booking.find({ hostId })
      .populate("experience", "title images price")
      .populate("guestId", "name email profilePic mobile")
      .populate("user", "name email profilePic mobile")
      .sort({ bookingDate: 1 });
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get(
  "/api/host/bookings/:experienceId",
  authMiddleware,
  async (req, res) => {
    try {
      const hostId = String(req.user._id);
      const experienceId = req.params.experienceId;
      const bookings = await Booking.find({ hostId, experienceId })
        .populate("experience", "title images price")
        .populate("guestId", "name email profilePic mobile")
        .sort({ bookingDate: 1 });
      res.json(bookings);
    } catch (err) {
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Guest Bookings Routes
app.get("/api/bookings/my-bookings", authMiddleware, async (req, res) => {
  const bookings = await Booking.find({ guestId: req.user._id })
    .populate("experience")
    .sort({ bookingDate: -1 });
  res.json(bookings);
});
app.get("/api/my/bookings", authMiddleware, async (req, res) => {
  const bookings = await Booking.find({ guestId: req.user._id })
    .populate("experience")
    .sort({ bookingDate: -1 });
  res.json(bookings);
});

// Cancel Booking
app.post("/api/bookings/:id/cancel", authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) return res.status(404).json({ message: "Booking not found" });
    if (String(booking.guestId) !== String(req.user._id))
      return res.status(403).json({ message: "Unauthorized" });
    if (
      booking.status === "cancelled" ||
      booking.status === "cancelled_by_host"
    )
      return res.status(400).json({ message: "Already cancelled" });
    booking.status = "cancelled";
    booking.refundAmount = 0;
    booking.cancellationReason = "User requested cancellation";
    await booking.save();
    res.json({
      message: "Booking cancelled.",
      refund: { amount: 0, reason: "Manual processing" }
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 5. Review & Bookmark Routes
app.post("/api/reviews", authMiddleware, async (req, res) => {
  const {
    experienceId,
    bookingId,
    rating,
    comment,
    type,
    targetId
  } = req.body;
  const reviewType = type || "guest_to_host";
  if (
    await Review.findOne({
      bookingId,
      authorId: req.user._id
    })
  )
    return res.status(400).json({ message: "Duplicate" });
  const review = new Review({
    experienceId,
    bookingId,
    authorId: req.user._id,
    authorName: req.user.name,
    targetId,
    type: reviewType,
    rating,
    comment
  });
  await review.save();
  if (reviewType === "guest_to_host") {
    const reviews = await Review.find({
      experienceId,
      type: "guest_to_host"
    });
    const avg =
      reviews.reduce((acc, r) => acc + r.rating, 0) / reviews.length;
    await Experience.findByIdAndUpdate(experienceId, {
      averageRating: avg,
      reviewCount: reviews.length
    });
  } else {
    const userReviews = await Review.find({
      targetId,
      type: "host_to_guest"
    });
    const avg =
      userReviews.reduce((acc, r) => acc + r.rating, 0) /
      userReviews.length;
    await User.findByIdAndUpdate(targetId, {
      guestRating: avg,
      guestReviewCount: userReviews.length
    });
  }
  res.json(review);
});

app.get("/api/experiences/:id/reviews", async (req, res) => {
  const reviews = await Review.find({
    experienceId: req.params.id,
    type: "guest_to_host"
  }).sort({ date: -1 });
  res.json(reviews);
});

app.post("/api/bookmarks/:experienceId", authMiddleware, async (req, res) => {
  const { experienceId } = req.params;
  const userId = req.user._id;
  const existing = await Bookmark.findOne({ userId, experienceId });
  if (existing) {
    await Bookmark.findByIdAndDelete(existing._id);
    return res.json({ message: "Removed" });
  }
  await Bookmark.create({ userId, experienceId });
  res.json({ message: "Added" });
});

app.get("/api/my/bookmarks/details", authMiddleware, async (req, res) => {
  const bms = await Bookmark.find({ userId: req.user._id });
  const exps = await Experience.find({
    _id: { $in: bms.map(b => b.experienceId) }
  });
  res.json(exps);
});

// 6. Admin & Utility Routes
app.get("/api/admin/stats", adminMiddleware, async (req, res) => {
  const revenueDocs = await Booking.find(
    { status: "confirmed" },
    "pricing"
  );
  res.json({
    userCount: await User.countDocuments(),
    expCount: await Experience.countDocuments(),
    bookingCount: await Booking.countDocuments(),
    totalRevenue: revenueDocs.reduce(
      (acc, b) => acc + (b.pricing.totalPrice || 0),
      0
    )
  });
});

app.get("/api/admin/bookings", adminMiddleware, async (req, res) => {
  const bookings = await Booking.find()
    .populate("experience")
    .populate("user")
    .sort({ createdAt: -1 })
    .limit(50);
  res.json(bookings);
});

app.get("/api/recommendations", authMiddleware, async (req, res) => {
  const exps = await Experience.find({ isPaused: false })
    .sort({ averageRating: -1 })
    .limit(4);
  if (exps.length > 0) return res.json(exps);
  const fallback = await Experience.find({ isPaused: false }).limit(4);
  res.json(fallback);
});

// --- NEW ADMIN ROUTES (Item #57) ---

// A. Get ALL Users (Admin Only)
app.get("/api/admin/users", adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// B. Ban/Delete User (Admin Only)
app.delete("/api/admin/users/:id", adminMiddleware, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    // Optional: Delete their bookings/experiences too? For MVP, just the user.
    res.json({ message: "User banned/deleted." });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// C. Get ALL Experiences (Including Paused) (Admin Only)
app.get("/api/admin/experiences", adminMiddleware, async (req, res) => {
  try {
    const exps = await Experience.find().sort({ createdAt: -1 });
    res.json(exps);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// D. Toggle Experience Status (Pause/Unpause) (Admin Only)
app.patch("/api/admin/experiences/:id/toggle", adminMiddleware, async (req, res) => {
  try {
    const exp = await Experience.findById(req.params.id);
    if (!exp) return res.status(404).json({ message: "Not found" });
    
    exp.isPaused = !exp.isPaused; // Toggle
    await exp.save();
    res.json(exp);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 7. Public/Host Profile Route (UPDATED: Fetches Reviews & Real Stats)
app.get("/api/users/:userId/profile", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Check if they are a host
    const isHostProfile = await isHost(user._id);

    let experiences = [];
    let reviews = [];
    let hostRating = 0;
    let hostReviewCount = 0;

    if (isHostProfile) {
      // 1. Get Active Experiences
      experiences = await Experience.find({
        hostId: user._id,
        isPaused: false
      }).sort({ averageRating: -1, createdAt: -1 });

      // 2. Get Recent Reviews for this Host's Experiences
      // We find all reviews where the experienceId belongs to this host
      const expIds = experiences.map(e => e._id.toString());
      reviews = await Review.find({ 
          experienceId: { $in: expIds }, 
          type: 'guest_to_host' 
      })
      .sort({ date: -1 })
      .limit(10); // Limit to 10 most recent

      // 3. Calculate Real Host Stats
      if (experiences.length > 0) {
          // Sum up review counts
          hostReviewCount = reviews.length; // Or aggregate total from experiences if fetching all
          
          // Calculate average rating across all rated experiences
          const ratedExps = experiences.filter(e => e.averageRating > 0);
          if (ratedExps.length > 0) {
              const totalRating = ratedExps.reduce((sum, e) => sum + e.averageRating, 0);
              hostRating = totalRating / ratedExps.length;
          }
      }
    }

    // Sanitize user data
    const publicUser = sanitizeUser(user);
    const {
      email, password, role, notifications, payoutDetails, ...safePublicUser
    } = publicUser;

    res.json({
      user: safePublicUser,
      isHost: isHostProfile,
      experiences: experiences,
      reviews: reviews, // Send reviews to frontend
      hostStats: {      // Send calculated stats
          rating: hostRating, 
          reviewCount: hostReviewCount 
      }
    });
  } catch (error) {
    console.error("Error fetching public profile:", error);
    res.status(500).json({ message: "Server error fetching profile." });
  }
});

// 🔴 NUCLEAR SEED ROUTE (Fixed Personas + Multi-Category)
app.get("/api/admin/seed-force", async (req, res) => {
  try {
    await User.deleteMany({});
    await Experience.deleteMany({});
    await Review.deleteMany({});
    await Booking.deleteMany({});

    const adminPass = await bcrypt.hash("admin", 10);
    const hostPass = await bcrypt.hash("123", 10);

    // GENERIC / SAFE USERS (No real names)
    await User.create({
      name: `Super Admin`,
      email: `admin@sharedtable.com`,
      password: adminPass,
      role: `Admin`,
      isAdmin: true
    });

    const host1 = await User.create({
      name: `Lucas`,
      email: `lucas@host.com`,
      password: hostPass,
      role: `Host`,
      isPremiumHost: true,
      bio: "Surfer & Chef.",
      profilePic:
        "https://images.unsplash.com/photo-1544005313-94ddf0286df2?auto=format&fit=crop&w=200&q=80"
    });
    const host2 = await User.create({
      name: `Elena`,
      email: `elena@host.com`,
      password: hostPass,
      role: `Host`,
      isPremiumHost: true,
      bio: "Sharing family recipes.",
      profilePic:
        "https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?auto=format&fit=crop&w=200&q=80"
    });
    const host3 = await User.create({
      name: `Sarah`,
      email: `sarah@host.com`,
      password: hostPass,
      role: `Host`,
      isPremiumHost: true,
      bio: "Nature guide.",
      profilePic:
        "https://images.unsplash.com/photo-1438761681033-6461ffad8d80?auto=format&fit=crop&w=200&q=80"
    });

    // Pillar 1: CULTURE + FOOD (Multi-Category!)
    await Experience.create({
      hostId: host1._id,
      hostName: host1.name,
      hostPic: host1.profilePic,
      title: `Aussie Christmas Eve Seafood Feast`,
      city: `Bondi Beach`,
      price: 120,
      maxGuests: 12,
      tags: ["Culture", "Food"], // <--- DUAL CATEGORY
      description:
        "Fresh prawns, oysters, and pavlova by the beach. Experience a true Australian summer Christmas tradition.",
      images: [
        "https://images.unsplash.com/photo-1606131731446-5568d87113aa?auto=format&fit=crop&w=800&q=80"
      ], // Seafood Platter
      availableDays: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      startDate: "2025-12-01",
      endDate: "2025-12-31"
    });

    // Pillar 2: FOOD
    await Experience.create({
      hostId: host2._id,
      hostName: host2.name,
      hostPic: host2.profilePic,
      title: `Sunday Gravy with Nonna`,
      city: `Melbourne`,
      price: 65,
      maxGuests: 6,
      tags: ["Food"],
      description:
        "A slow-cooked Italian feast using recipes passed down for 3 generations.",
      images: [
        "https://images.unsplash.com/photo-1543353071-873f17a7a088?auto=format&fit=crop&w=800&q=80"
      ],
      availableDays: ["Sat", "Sun"],
      startDate: "2025-01-01",
      endDate: "2025-12-31"
    });

    // Pillar 3: NATURE
    await Experience.create({
      hostId: host3._id,
      hostName: host3.name,
      hostPic: host3.profilePic,
      title: `Coastal Foraging & Picnic`,
      city: `Byron Bay`,
      price: 95,
      maxGuests: 8,
      tags: ["Nature"],
      description:
        "Walk the coast, learn about native ingredients, and share a picnic on the cliffs at sunset.",
      images: [
        "https://images.unsplash.com/photo-1469854523086-cc02fe5d8800?auto=format&fit=crop&w=800&q=80"
      ],
      availableDays: ["Sat", "Sun"],
      startDate: "2025-01-01",
      endDate: "2025-12-31"
    });

    res.send(
      "✅ DATABASE RESET: Multi-Category Listings Created (Culture+Food)."
    );
  } catch (e) {
    res.status(500).send(e.message);
  }
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);