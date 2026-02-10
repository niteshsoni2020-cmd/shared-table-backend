const YEAR = new Date().getFullYear();
const START_OF_YEAR = `${YEAR}-01-01`;
const END_OF_YEAR = `${YEAR}-12-31`;

// backend/seed.js

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const __IS_PROD = String(process.env.NODE_ENV || "").toLowerCase() === "production";
const __ALLOW_SEED_PROD = String(process.env.ALLOW_SEED_PROD || "").trim();
const __SEED_ADMIN_PASSWORD = String(process.env.SEED_ADMIN_PASSWORD || "").trim();
const __SEED_ADMIN_EMAIL = String(process.env.SEED_ADMIN_EMAIL || "").trim().toLowerCase();
const __SEED_ADMIN_NAME = String(process.env.SEED_ADMIN_NAME || "").trim();

if (__IS_PROD && __ALLOW_SEED_PROD !== "YES_I_KNOW_WHAT_I_AM_DOING") {
  console.error("SEED_BLOCKED_IN_PROD");
  process.exit(1);
}

if (!__SEED_ADMIN_PASSWORD) {
  console.error("SEED_ADMIN_PASSWORD_MISSING");
  process.exit(1);
}
if (!__SEED_ADMIN_EMAIL) {
  console.error("SEED_ADMIN_EMAIL_MISSING");
  process.exit(1);
}
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(__SEED_ADMIN_EMAIL)) {
  console.error("SEED_ADMIN_EMAIL_INVALID");
  process.exit(1);
}


// --- 1. CONFIG ---
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB for Seeding'))
  .catch((err) => console.error('❌ DB Error:', err));

// --- 2. SCHEMAS ---
const schemaOpts = { toJSON: { virtuals: true }, toObject: { virtuals: true } };

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'Guest' },
    profilePic: String,
    isPremiumHost: { type: Boolean, default: false },
    vacationMode: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false },
    bio: String,
    location: String,
    mobile: String,
    preferences: [String],
    guestRating: { type: Number, default: 0 },
    notifications: [
      {
        message: String,
        date: { type: Date, default: Date.now },
      },
    ],
  },
  schemaOpts
);

const experienceSchema = new mongoose.Schema(
  {
    hostId: String,
    hostName: String,
    hostPic: String,
    title: String,
    description: String,
    city: String,
    price: Number,
    maxGuests: Number,
    startDate: String,
    endDate: String,
    availableDays: [String],
    isPaused: { type: Boolean, default: false },
    tags: [String],
    timeSlots: [String],
    imageUrl: String,
    images: [String],
    lat: Number,
    lng: Number,
    averageRating: { type: Number, default: 0 },
    reviewCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
  },
  schemaOpts
);

const reviewSchema = new mongoose.Schema(
  {
    experienceId: String,
    bookingId: String,
    authorId: String,
    authorName: String,
    targetId: String,
    type: String,
    rating: Number,
    comment: String,
    date: { type: Date, default: Date.now },
  },
  schemaOpts
);

const User = mongoose.model('User', userSchema);
const Experience = mongoose.model('Experience', experienceSchema);
const Review = mongoose.model('Review', reviewSchema);

// --- 3. SEED DATA ---
const seed = async () => {
  try {
    console.log('🧹 Clearing old data...');
    console.log("SEED_MODE", { prod: __IS_PROD, allowProd: (__ALLOW_SEED_PROD === "YES_I_KNOW_WHAT_I_AM_DOING") });
    await User.deleteMany({});
    await Experience.deleteMany({});
    await Review.deleteMany({});

    console.log('🌱 Seeding Users...');

    const adminPass = await bcrypt.hash(__SEED_ADMIN_PASSWORD, 10);

    // Admin account (not shown as a host card)
    await User.create({
      name: __SEED_ADMIN_NAME || 'Super Admin',
      email: __SEED_ADMIN_EMAIL,
      password: adminPass,
      role: 'Admin',
      isAdmin: true,
      isPremiumHost: true,
      bio: 'Platform Manager',
      location: 'Sydney',
    });
    console.log('✅ SEEDING COMPLETE! Admin bootstrap only (no demo/test events or users).');
    process.exit(0);
  } catch (err) {
    console.error('❌ Seed Failed:', err);
    process.exit(1);
  }
};

seed();
