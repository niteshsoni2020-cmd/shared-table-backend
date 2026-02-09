#!/usr/bin/env node
"use strict";

require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

function exitWith(code, payload) {
  try { console.log(JSON.stringify(payload)); } catch (_) {}
  process.exit(code);
}

function env(name) {
  return String(process.env[name] || "").trim();
}

function isEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || "").trim());
}

const MONGO_URI = env("MONGO_URI");
const ADMIN_EMAIL = env("ADMIN_EMAIL").toLowerCase();
const ADMIN_PASSWORD = env("ADMIN_PASSWORD");
const ADMIN_NAME = env("ADMIN_NAME");
const ADMIN_CURRENT_EMAIL = env("ADMIN_CURRENT_EMAIL").toLowerCase();
const ALLOW_CREATE = String(env("ADMIN_ROTATE_ALLOW_CREATE")).toLowerCase() === "true";

if (!MONGO_URI) exitWith(1, { ok: false, error: "MONGO_URI_MISSING" });
if (!ADMIN_EMAIL) exitWith(1, { ok: false, error: "ADMIN_EMAIL_MISSING" });
if (!isEmail(ADMIN_EMAIL)) exitWith(1, { ok: false, error: "ADMIN_EMAIL_INVALID" });
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  exitWith(1, { ok: false, error: "ADMIN_PASSWORD_TOO_WEAK", minLength: 12 });
}
if (ADMIN_CURRENT_EMAIL && !isEmail(ADMIN_CURRENT_EMAIL)) {
  exitWith(1, { ok: false, error: "ADMIN_CURRENT_EMAIL_INVALID" });
}

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: "Guest" },
    isAdmin: { type: Boolean, default: false },
    emailVerified: { type: Boolean, default: false },
    accountStatus: { type: String, default: "active" },
    accountStatusChangedAt: { type: Date, default: null },
    accountStatusReason: { type: String, default: "" },
    tokenVersion: { type: Number, default: 0 }
  },
  { strict: false, collection: "users" }
);

const User = mongoose.models.UserRotateAdmin || mongoose.model("UserRotateAdmin", userSchema);

async function run() {
  await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 });

  const lookup = Array.from(new Set(
    [ADMIN_CURRENT_EMAIL, ADMIN_EMAIL].filter(Boolean).map((v) => String(v).toLowerCase())
  ));

  let user = null;
  if (lookup.length > 0) {
    user = await User.findOne({ email: { $in: lookup } }).exec();
  }
  if (!user) {
    user = await User.findOne({ isAdmin: true }).sort({ _id: 1 }).exec();
  }

  if (!user) {
    if (!ALLOW_CREATE) {
      exitWith(1, { ok: false, error: "ADMIN_USER_NOT_FOUND", hint: "Set ADMIN_ROTATE_ALLOW_CREATE=true to bootstrap." });
    }
    user = new User();
  }

  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const before = {
    id: user._id ? String(user._id) : "",
    email: String(user.email || ""),
    role: String(user.role || ""),
    isAdmin: !!user.isAdmin,
    tokenVersion: Number(user.tokenVersion || 0)
  };

  user.email = ADMIN_EMAIL;
  user.name = ADMIN_NAME || user.name || "Super Admin";
  user.password = hash;
  user.role = "Admin";
  user.isAdmin = true;
  user.emailVerified = true;
  user.accountStatus = "active";
  user.accountStatusChangedAt = new Date();
  user.accountStatusReason = "admin_credentials_rotated";
  user.tokenVersion = Number(user.tokenVersion || 0) + 1;
  await user.save();

  const after = {
    id: String(user._id),
    email: String(user.email || ""),
    role: String(user.role || ""),
    isAdmin: !!user.isAdmin,
    tokenVersion: Number(user.tokenVersion || 0)
  };

  exitWith(0, {
    ok: true,
    data: {
      created: !before.id,
      before,
      after
    }
  });
}

run()
  .catch((err) => {
    exitWith(1, {
      ok: false,
      error: "ADMIN_ROTATE_FAILED",
      message: String((err && err.message) || err)
    });
  })
  .finally(async () => {
    try { await mongoose.disconnect(); } catch (_) {}
  });
