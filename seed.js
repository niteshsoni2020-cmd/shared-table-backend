// backend/seed.js

require('dotenv').config();
const mongoose = require('mongoose');

// --- 1. CONFIG ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB for Seeding"))
  .catch(err => console.error("❌ DB Error:", err));

// --- 2. SCHEMAS (Matching server.js) ---
const schemaOpts = { toJSON: { virtuals: true }, toObject: { virtuals: true } };

const userSchema = new mongoose.Schema({
  name: String, email: { type: String, unique: true }, password: String,
  role: { type: String, default: "Guest" }, profilePic: String,
  isPremiumHost: { type: Boolean, default: false },
  vacationMode: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
  bio: String, location: String, mobile: String,
  preferences: [String],
  guestRating: { type: Number, default: 0 },
  notifications: [{ message: String, date: { type: Date, default: Date.now } }]
}, schemaOpts);

const experienceSchema = new mongoose.Schema({
  hostId: String, hostName: String, hostPic: String,
  title: String, description: String, city: String,
  price: Number, maxGuests: Number, 
  startDate: String, endDate: String,
  availableDays: [String], isPaused: Boolean,
  tags: [String], timeSlots: [String],
  imageUrl: String, images: [String],
  lat: Number, lng: Number,
  averageRating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}, schemaOpts);

const reviewSchema = new mongoose.Schema({
  experienceId: String, bookingId: String,
  authorId: String, authorName: String,
  targetId: String, type: String,
  rating: Number, comment: String,
  date: { type: Date, default: Date.now }
}, schemaOpts);

const User = mongoose.model("User", userSchema);
const Experience = mongoose.model("Experience", experienceSchema);
const Review = mongoose.model("Review", reviewSchema);

// --- 3. SEED DATA ---
const seed = async () => {
    try {
        console.log("🧹 Clearing old data...");
        // WARNING: Uncomment to wipe DB clean before seeding
        // await User.deleteMany({});
        // await Experience.deleteMany({});
        // await Review.deleteMany({});

        console.log("🌱 Seeding Users...");
        
        // 1. ADMIN
        let admin = await User.findOne({ email: "admin@sharedtable.com" });
        if (!admin) {
            admin = await User.create({
                name: "Super Admin", email: "admin@sharedtable.com", password: "admin",
                role: "Admin", isAdmin: true, isPremiumHost: true,
                bio: "Platform Manager", location: "Sydney"
            });
        }

        // 2. FOUNDER HOST
        let host = await User.findOne({ email: "founder@sharedtable.com" });
        if (!host) {
            host = await User.create({
                name: "Abhishek", email: "founder@sharedtable.com", password: "123",
                role: "Host", isPremiumHost: true,
                bio: "Founder, Traveller, Story Collector. I built this platform to share meals and memories.",
                location: "Melbourne",
                profilePic: "https://images.unsplash.com/photo-1599566150163-29194dcaad36?q=80&w=200&auto=format&fit=crop"
            });
        }

        // 3. MOCK GUESTS (For Reviews)
        const guestData = [
            { name: "Sarah J.", email: "sarah@test.com" },
            { name: "Mike T.", email: "mike@test.com" },
            { name: "Priya K.", email: "priya@test.com" },
            { name: "David L.", email: "david@test.com" },
            { name: "Emma W.", email: "emma@test.com" }
        ];
        
        const guests = [];
        for (const g of guestData) {
            let user = await User.findOne({ email: g.email });
            if (!user) {
                user = await User.create({ 
                    name: g.name, email: g.email, password: "123", 
                    role: "Guest", bio: "Loves travel & food." 
                });
            }
            guests.push(user);
        }

        console.log("🌱 Seeding Experiences...");

        // 4. EXPERIENCES (Localized for Australia)
        const expData = [
            {
                title: "Aussie Christmas Eve Feast",
                city: "Melbourne",
                price: 85,
                tags: ["Culture & Festivals", "Family Tables"],
                description: "Experience a classic Australian Summer Christmas. We'll start with fresh prawns and oysters, move to roast pork with crackling, and finish with my grandmother's pavlova recipe. Come for the food, stay for the cricket stories.",
                imageUrl: "https://images.unsplash.com/photo-1576402187878-974f70c890a5?q=80&w=800&auto=format&fit=crop", // Festive dinner table
                availableDays: ["Fri", "Sat", "Sun"],
                startDate: "2025-12-01", endDate: "2025-12-31"
            },
            {
                title: "Secret Laneway Coffee Walk",
                city: "Melbourne",
                price: 35,
                tags: ["Nature & Tours", "Solo Friendly", "Budget Eats"],
                description: "Discover the hidden cafes tourists miss. Perfect for solo travellers wanting to meet locals.",
                imageUrl: "https://images.unsplash.com/photo-1497935586351-b67a49e012bf",
                availableDays: ["Sat", "Sun"],
                startDate: "2025-01-01", endDate: "2025-12-31"
            },
            {
                title: "Sunset Pasta & Wine",
                city: "Sydney",
                price: 90,
                tags: ["Food & Dining", "Date Night"],
                description: "Hand-rolled pasta on a balcony overlooking the harbour. Wine included. Perfect for couples or intimate conversations.",
                imageUrl: "https://images.unsplash.com/photo-1556910103-1c02745a30bf",
                availableDays: ["Fri", "Sat"],
                startDate: "2025-01-01", endDate: "2025-12-31"
            }
        ];

        const createdExps = [];
        for (const e of expData) {
            let exp = await Experience.findOne({ title: e.title });
            if (!exp) {
                exp = await Experience.create({
                    hostId: host._id, hostName: host.name, hostPic: host.profilePic,
                    maxGuests: 8, originalMaxGuests: 8,
                    timeSlots: ["18:00-20:00"],
                    images: [e.imageUrl, e.imageUrl, e.imageUrl],
                    lat: -37.8136, lng: 144.9631,
                    ...e
                });
            }
            createdExps.push(exp);
        }

        console.log("🌱 Seeding Reviews (The Soul)...");

        // 5. REVIEWS (Christmas Themed)
        const xmasExp = createdExps[0]; 
        if (xmasExp) {
            const reviews = [
                "Being away from home for Christmas is hard, but this family made me feel so welcome. The pavlova was incredible!",
                "Fresh seafood, cold wine, and warm people. The perfect Aussie Christmas Eve. I didn't want to leave.",
                "I came alone but left with 5 new friends. The host explains the traditions beautifully. Highly recommend.",
                "The roast pork crackling was perfect! A truly generous and heartwarming evening.",
                "Better than any restaurant. It felt like I was visiting old friends for the holidays."
            ];

            for (let i = 0; i < reviews.length; i++) {
                await Review.create({
                    experienceId: xmasExp._id,
                    bookingId: `SEED-${i}`,
                    authorId: guests[i]._id,
                    authorName: guests[i].name,
                    targetId: host._id,
                    type: "guest_to_host",
                    rating: 5,
                    comment: reviews[i],
                    date: new Date()
                });
            }
            
            // Update Experience Stats
            xmasExp.averageRating = 5.0;
            xmasExp.reviewCount = 5;
            await xmasExp.save();
        }

        console.log("✅ SEEDING COMPLETE! The database has soul.");
        process.exit(0);

    } catch (err) {
        console.error("❌ Seed Failed:", err);
        process.exit(1);
    }
};

seed();