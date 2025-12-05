// backend/seed.js

require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 

// --- 1. CONFIG ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB for Seeding"))
  .catch(err => console.error("❌ DB Error:", err));

// --- 2. SCHEMAS ---
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
        await User.deleteMany({});
        await Experience.deleteMany({});
        await Review.deleteMany({});

        console.log("🌱 Seeding Users...");
        
        const adminPass = await bcrypt.hash("admin", 10);
        const userPass = await bcrypt.hash("123", 10);

        let admin = await User.create({
            name: "Super Admin", email: "admin@sharedtable.com", password: adminPass,
            role: "Admin", isAdmin: true, isPremiumHost: true,
            bio: "Platform Manager", location: "Sydney"
        });

        let host = await User.create({
            name: "Abhishek", email: "founder@sharedtable.com", password: userPass,
            role: "Host", isPremiumHost: true,
            bio: "Founder, Traveller, Story Collector.",
            location: "Melbourne",
            profilePic: "https://images.unsplash.com/photo-1599566150163-29194dcaad36?q=80&w=200&auto=format&fit=crop"
        });

        const guests = [];
        const names = ["Sarah J.", "Mike T.", "Priya K.", "David L.", "Emma W."];
        const emails = ["sarah@test.com", "mike@test.com", "priya@test.com", "david@test.com", "emma@test.com"];

        for (let i = 0; i < names.length; i++) {
            const user = await User.create({ 
                name: names[i], email: emails[i], password: userPass, 
                role: "Guest", bio: "Loves travel." 
            });
            guests.push(user);
        }

        console.log("🌱 Seeding Experiences...");

        const expData = [
            {
                title: "Aussie Christmas Eve Feast",
                city: "Melbourne",
                price: 85,
                tags: ["Culture & Festivals", "Family Tables"],
                description: "Experience a classic Australian Summer Christmas. Fresh prawns, roast pork, and pavlova.",
                imageUrl: "https://images.unsplash.com/photo-1576402187878-974f70c890a5?q=80&w=800&auto=format&fit=crop",
                availableDays: ["Fri", "Sat", "Sun"],
                startDate: "2025-12-01", endDate: "2025-12-31"
            },
            {
                title: "Secret Laneway Coffee Walk",
                city: "Melbourne",
                price: 35,
                tags: ["Nature & Tours", "Solo Friendly", "Budget Eats"],
                description: "Discover hidden cafes. Perfect for solo travellers.",
                imageUrl: "https://images.unsplash.com/photo-1497935586351-b67a49e012bf",
                availableDays: ["Sat", "Sun"],
                startDate: "2025-01-01", endDate: "2025-12-31"
            },
            {
                title: "Sunset Pasta & Wine",
                city: "Sydney",
                price: 90,
                tags: ["Food & Dining", "Date Night"],
                description: "Hand-rolled pasta on a balcony overlooking the harbour.",
                imageUrl: "https://images.unsplash.com/photo-1556910103-1c02745a30bf",
                availableDays: ["Fri", "Sat"],
                startDate: "2025-01-01", endDate: "2025-12-31"
            }
        ];

        const createdExps = [];
        for (const e of expData) {
            const exp = await Experience.create({
                hostId: host._id, hostName: host.name, hostPic: host.profilePic,
                maxGuests: 8, originalMaxGuests: 8,
                timeSlots: ["18:00-20:00"],
                images: [e.imageUrl, e.imageUrl, e.imageUrl],
                lat: -37.8136, lng: 144.9631,
                ...e
            });
            createdExps.push(exp);
        }

        console.log("🌱 Seeding Reviews...");
        
        const xmasExp = createdExps[0]; 
        const reviews = [
            "Being away from home for Christmas is hard, but this family made me feel so welcome.",
            "Fresh seafood, cold wine, and warm people. The perfect Aussie Christmas Eve.",
            "I came alone but left with 5 new friends. Highly recommend.",
            "The roast pork crackling was perfect! A truly generous evening.",
            "Better than any restaurant. It felt like visiting old friends."
        ];

        for (let i = 0; i < reviews.length; i++) {
            await Review.create({
                experienceId: xmasExp._id, bookingId: `SEED-${i}`,
                authorId: guests[i]._id, authorName: guests[i].name,
                targetId: host._id, type: "guest_to_host",
                rating: 5, comment: reviews[i], date: new Date()
            });
        }
        
        xmasExp.averageRating = 5.0;
        xmasExp.reviewCount = 5;
        await xmasExp.save();

        console.log("✅ SEEDING COMPLETE! Passwords encrypted.");
        process.exit(0);

    } catch (err) {
        console.error("❌ Seed Failed:", err);
        process.exit(1);
    }
};
seed();