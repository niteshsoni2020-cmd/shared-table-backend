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
    const userPass = await bcrypt.hash('Test1234', 10);

    // Admin account (not shown as a host card)
    const admin = await User.create({
      name: __SEED_ADMIN_NAME || 'Super Admin',
      email: __SEED_ADMIN_EMAIL,
      password: adminPass,
      role: 'Admin',
      isAdmin: true,
      isPremiumHost: true,
      bio: 'Platform Manager',
      location: 'Sydney',
    });

    // 🔐 Demo Host — generic, no real person identity
    const host = await User.create({
      name: 'Shared Table Demo Host',
      email: 'demo-host@sharedtable.com',
      password: userPass,
      role: 'Host',
      isPremiumHost: true,
      bio: 'Demo host profile used only to showcase experiences on The Shared Table Story.',
      location: 'Melbourne',
      // Neutral table / food scene instead of a human face
      profilePic: '',  // No external dependency - use default avatar
    });

    const guests = [];
    const names = ['Sarah J.', 'Mike T.', 'Priya K.', 'David L.', 'Emma W.'];
    const emails = [
      'sarah@test.com',
      'mike@test.com',
      'priya@test.com',
      'david@test.com',
      'emma@test.com',
    ];

    for (let i = 0; i < names.length; i++) {
      const user = await User.create({
        name: names[i],
        email: emails[i],
        password: userPass,
        role: 'Guest',
        bio: 'Loves travel.',
      });
      guests.push(user);
    }

    console.log('🌱 Seeding Experiences...');

    const expData = [
      {
        title: 'Aussie Christmas Eve Feast',
        city: 'Melbourne',
        price: 85,
        // 🔹 Linked to 2 categories: Culture + Food
        tags: ['Culture', 'Food'],
        description:
          'Celebrate Christmas Eve like a local in Melbourne. Fresh prawns, roast pork with crackling, pavlova for dessert, and a relaxed summer evening around a shared table.',
        imageUrl: '',  // Uses experience-default.jpg fallback
        availableDays: ['Fri', 'Sat', 'Sun'],
        startDate: START_OF_YEAR,
        endDate: END_OF_YEAR,
      },
      {
        title: 'Secret Laneway Coffee Walk',
        city: 'Melbourne',
        price: 35,
        tags: ['Nature'],
        description:
          "Discover hidden laneway cafés, street art, and third-wave coffee spots. Perfect for solo travellers who want to explore Melbourne's coffee culture without a tour bus.",
        imageUrl: '',  // Uses experience-default.jpg fallback
        availableDays: ['Sat', 'Sun'],
        startDate: START_OF_YEAR,
        endDate: END_OF_YEAR,
      },
      {
        title: 'Sunset Pasta & Wine',
        city: 'Sydney',
        price: 90,
        tags: ['Food'],
        description:
          'Hand-rolled pasta, good wine, and golden-hour views. Share a slow, lingering dinner on a balcony overlooking the water in Sydney.',
        imageUrl: '',  // Uses experience-default.jpg fallback
        availableDays: ['Fri', 'Sat'],
        startDate: START_OF_YEAR,
        endDate: END_OF_YEAR,
      },
    ];

    const createdExps = [];
    for (const e of expData) {
      const exp = await Experience.create({
        hostId: host._id.toString(),
        hostName: host.name,
        hostPic: host.profilePic,
        maxGuests: 8,
        // this field wasn’t in schema originally but mongoose will still store it
        originalMaxGuests: 8,
        timeSlots: ['18:00-20:00'],
        images: [e.imageUrl, e.imageUrl, e.imageUrl],
        lat: -37.8136,
        lng: 144.9631,
        isPaused: false, // 🔹 visible in search/category filters
        ...e,
      });
      createdExps.push(exp);
    }

    console.log('🌱 Seeding Reviews...');

    const xmasExp = createdExps[0];
    const reviews = [
      'Being away from home for Christmas is hard, but this family made me feel so welcome.',
      'Fresh seafood, cold wine, and warm people. The perfect Aussie Christmas Eve.',
      'I came alone but left with 5 new friends. Highly recommend.',
      'The roast pork crackling was perfect! A truly generous evening.',
      'Better than any restaurant. It felt like visiting old friends.',
    ];

    for (let i = 0; i < reviews.length; i++) {
      await Review.create({
        experienceId: xmasExp._id.toString(),
        bookingId: `SEED-${i}`,
        authorId: guests[i]._id.toString(),
        authorName: guests[i].name,
        targetId: host._id.toString(),
        type: 'guest_to_host',
        rating: 5,
        comment: reviews[i],
        date: new Date(),
      });
    }

    xmasExp.averageRating = 5.0;
    xmasExp.reviewCount = reviews.length;
    await xmasExp.save();

    console.log('✅ SEEDING COMPLETE! Clean demo data only.');
    process.exit(0);
  } catch (err) {
    console.error('❌ Seed Failed:', err);
    process.exit(1);
  }
};

seed();
