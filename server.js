// server.js - FULL VERSION (Privacy-first attendee discovery + Like/Comment + Public profile hardening)

require("dotenv").config();

// ENV_ALIAS_SMTP_FROM_EMAIL_KEYS
// Accept legacy EMAIL_USER/EMAIL_PASS while code expects SMTP_USER/SMTP_PASS.
// Provide safe defaults for SMTP_* if not set.
(() => {
  const env = process.env;
  const norm = (v) => String(v || "").trim();

  const smtpUser = norm(env.SMTP_USER);
  const emailUser = norm(env.EMAIL_USER);
  if (smtpUser.length === 0) {
    if (emailUser.length > 0) env.SMTP_USER = env.EMAIL_USER;
  }

  const smtpPass = norm(env.SMTP_PASS);
  const emailPass = norm(env.EMAIL_PASS);
  if (smtpPass.length === 0) {
    if (emailPass.length > 0) env.SMTP_PASS = env.EMAIL_PASS;
  }

  if (norm(env.SMTP_HOST).length === 0) env.SMTP_HOST = "smtp.gmail.com";
  if (norm(env.SMTP_PORT).length === 0) env.SMTP_PORT = "587";
  if (norm(env.SMTP_SECURE).length === 0) env.SMTP_SECURE = "false";
})();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { start: startJobs, registerInterval } = require("./src/jobs");

// CLOUDINARY_CONFIG_TSTS
// Cloudinary v2 does NOT auto-configure from CLOUDINARY_CLOUD_NAME/API_KEY/API_SECRET.
// Configure explicitly (production-safe). If missing, uploads will fail.
(() => {
  const name = String(process.env.CLOUDINARY_CLOUD_NAME || "").trim();
  const key = String(process.env.CLOUDINARY_API_KEY || "").trim();
  const secret = String(process.env.CLOUDINARY_API_SECRET || "").trim();
  const ok = (name.length > 0) && (key.length > 0) && (secret.length > 0);
  if (ok === true) {
    cloudinary.config({ cloud_name: name, api_key: key, api_secret: secret });
  }
})();

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const STRIPE_WEBHOOK_SECRET = String(process.env.STRIPE_WEBHOOK_SECRET || "");
const nodemailer = require("nodemailer");
const { sendEventEmail } = require("./src/email");

function __fireAndForgetEmail(payload) {
  try {
    const p = __sendEventEmailTracked(payload, { rid: "" });
    if (p && typeof p.catch === "function") {
      p.catch(function(e) {
        try {
          const msg = (e && e.message) ? e.message : String(e);
          console.error("EMAIL_ASYNC_ERR", msg);
        } catch (_) {}
      });
    }
  } catch (e) {
    try {
      const msg = (e && e.message) ? e.message : String(e);
      console.error("EMAIL_DISPATCH_ERR", msg);
    } catch (_) {}
  }
}

const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// EMAIL_DELIVERY_TRACKING_TSTS (Batch6 D5)
// Persist delivery attempts (privacy-preserving) and retry failures in a bounded way.
// Controlled via env: EMAIL_RETRY_MAX (default 1), EMAIL_RETRY_DELAY_MS (default 30000), EMAIL_TIMEOUT_MS (default 6000).

function __maskEmail(x) {
  try {
    const s = String(x || "").trim();
    const at = s.indexOf("@");
    if (at <= 0) return "";
    const local = s.slice(0, at);
    const dom = s.slice(at + 1);
    const pre = local.slice(0, 2);
    return pre + "***@" + dom;
  } catch (_) {
    return "";
  }
}

function __hashEmail(x) {
  try {
    const s = String(x || "").trim().toLowerCase();
    if (!s) return "";
    return crypto.createHash("sha256").update(s).digest("hex");
  } catch (_) {
    return "";
  }
}

const commDeliverySchema = new mongoose.Schema({
  rid: { type: String, default: "" },
  eventName: { type: String, default: "" },
  category: { type: String, default: "" },
  templateId: { type: String, default: "" },
  toMasked: { type: String, default: "" },
  toHash: { type: String, default: "" },
  ok: { type: Boolean, default: false },
  provider: { type: String, default: "" },
  providerMessageId: { type: String, default: "" },
  ms: { type: Number, default: 0 },
  error: { type: String, default: "" },
  attempt: { type: Number, default: 1 },
  parentId: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
}, { minimize: false });
commDeliverySchema.index({ createdAt: -1 });
commDeliverySchema.index({ eventName: 1, createdAt: -1 });
commDeliverySchema.index({ toHash: 1, createdAt: -1 });

const CommDelivery = mongoose.models.CommDelivery || mongoose.model("CommDelivery", commDeliverySchema);

function __emailTimeoutMs() {
  const v = Number.parseInt(String(process.env.EMAIL_TIMEOUT_MS || "6000"), 10);
  return (Number.isFinite(v) && v > 1000) ? v : 6000;
}
function __emailRetryMax() {
  const v = Number.parseInt(String(process.env.EMAIL_RETRY_MAX || "1"), 10);
  return (Number.isFinite(v) && v >= 0 && v <= 3) ? v : 1;
}
function __emailRetryDelayMs() {
  const v = Number.parseInt(String(process.env.EMAIL_RETRY_DELAY_MS || "30000"), 10);
  return (Number.isFinite(v) && v >= 1000 && v <= 10 * 60 * 1000) ? v : 30000;
}

async function __sendEventEmailTracked(payload, meta) {
  const p = (payload && typeof payload === "object") ? payload : {};
  const m = (meta && typeof meta === "object") ? meta : {};

  const rid = String(m.rid || "");
  const toRaw = String(p.to || "");
  const eventName = String(p.eventName || "");
  const category = String(p.category || "");
  const templateId = String(p.templateId || "");

  const toMasked = __maskEmail(toRaw);
  const toHash = __hashEmail(toRaw);

const providerGuess = String(
  (p && (p.provider || p.emailProvider)) ||
  (m && (m.provider || m.emailProvider)) ||
  process.env.EMAIL_PROVIDER ||
  process.env.MAIL_PROVIDER ||
  process.env.EMAIL_TRANSPORT ||
  ""
);

function __pickStatusCode(x) {
  try {
    const v = (x && (x.statusCode || x.responseCode || x.status)) || "";
    const n = Number.parseInt(String(v), 10);
    return Number.isFinite(n) ? n : null;
  } catch (_) { return null; }
}

function __pickMessageId(x) {
  try {
    return String(
      (x && (x.providerMessageId || x.messageId || x.messageID)) ||
      (x && x.info && (x.info.messageId || x.info.messageID)) ||
      (x && x.response && (x.response.messageId || x.response.messageID)) ||
      ""
    );
  } catch (_) { return ""; }
}

function __errDetails(e) {
  try {
    const msg = String((e && e.message) || e || "");
    const code = String((e && (e.code || e.errno)) || "");
    const syscall = String((e && e.syscall) || "");
    const hostname = String((e && e.hostname) || "");
    const command = String((e && e.command) || "");
    const response = String((e && (e.response || e.responseText)) || "");
    const __msgLower = msg.toLowerCase();
    const __msgHasBody = (__msgLower.indexOf(" body=") >= 0);
    const __msgHasStatus = (__msgLower.indexOf("statuscode=") >= 0);
    const status = __pickStatusCode(e);
    const parts = [];
    if (msg) parts.push(msg);
    if (status !== null) parts.push("statusCode=" + String(status));
    if (code) parts.push("code=" + code);
    if (syscall) parts.push("syscall=" + syscall);
    if (hostname) parts.push("host=" + hostname);
    if (command) parts.push("cmd=" + command);
    if (response && !(__msgHasBody && __msgHasStatus)) /* resp suppressed: message already contains body/statusCode */;
    const out = parts.join(" | ").trim();
    return out || "send_failed";
  } catch (_) {
    return "send_failed";
  }
}


  let doc = null;
  try {
    doc = await CommDelivery.create({
      rid: rid,
      eventName: eventName,
      category: category,
      templateId: templateId,
      toMasked: toMasked,
      toHash: toHash,
      ok: false,
      provider: providerGuess || "",
      providerMessageId: "",
      ms: 0,
      error: "",
      attempt: Number.parseInt(String(m.attempt || "1"), 10) || 1,
      parentId: String(m.parentId || "")
    });
  } catch (_) {}

  const t0 = Date.now();
  const timeoutMs = __emailTimeoutMs();

  try {
    const t = new Promise(function(_, rej) { setTimeout(function() { rej(new Error("EMAIL_TIMEOUT_MS_EXCEEDED ms=" + String(timeoutMs))); }, timeoutMs); });
    const r = await Promise.race([ Promise.resolve(sendEventEmail(p)), t ]);

    const ms = Date.now() - t0;
    const ok = (r === true) || (Boolean(r && r.ok === true));
    const provider = String((r && r.provider) || providerGuess || "");
    const mid = String((r && (r.providerMessageId || r.id || r.messageId || r.messageID)) || "");
const statusCode = __pickStatusCode(r);
    const err = ok ? "" : __errDetails((r && (r.error || r.err || r.message)) ? { message: String((r.error || r.err || r.message)) } : r);

    if (doc) {
      try {
        doc.ok = ok;
        doc.provider = provider;
        doc.providerMessageId = mid;
          if (statusCode !== null) doc.statusCode = statusCode;
        doc.ms = ms;
        doc.error = err.slice(0, 800);
                // COMMDELIVERY_OUTCOME_PATCH_TSTS_FINAL
        await doc.save();
      } catch (_) {}
    }

    if (!ok) throw new Error(err || "send_failed");
    return r;
  } catch (e) {
    const ms = Date.now() - t0;
    const emsg = __errDetails(e);
      const mid2 = __pickMessageId(e);
      const statusCode2 = __pickStatusCode(e);
      const provider2 = String((e && e.provider) || providerGuess || "");
    if (doc) {
      try {
        doc.ok = false;
          if (!doc.provider) doc.provider = provider2;
          if (!doc.providerMessageId && mid2) doc.providerMessageId = mid2;
          if (statusCode2 !== null) doc.statusCode = statusCode2;
        doc.ms = ms;
        doc.error = emsg.slice(0, 800);
        await doc.save();
      } catch (_) {}
    }

    // bounded retry (non-blocking)
    const attempt = Number.parseInt(String(m.attempt || "1"), 10) || 1;
    const maxRetry = __emailRetryMax();
    if (attempt <= maxRetry) {
      const delay = __emailRetryDelayMs();
      setTimeout(function() {
        try {
          __sendEventEmailTracked(p, { rid: rid, attempt: attempt + 1, parentId: doc ? String(doc._id || "") : String(m.parentId || "") })
            .catch(function() {});
        } catch (_) {}
      }, delay);
    }

    throw e;
  }
}



// WINSTON_LOGGER_TSTS
const winston = require("winston");
const __winstonLogger = (() => {
  try {
    const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";
    return winston.createLogger({
      level: isProd ? "info" : "debug",
      format: winston.format.json(),
      defaultMeta: { service: "tsts-backend" },
      transports: [new winston.transports.Console()]
    });
  } catch (_) {
    return null;
  }
})();

// Single Source of Truth for Categories (3 Pillars)
const CATEGORY_PILLARS = ["Culture", "Food", "Nature"];

// 1. Initialize App
const app = express();

let __dbReady = false;

function __classifyPaymentOutcome(stripeStatus, piStatus, sessionStatus) {
  const ss = String(stripeStatus || "").toLowerCase();
  const ps = String(piStatus || "").toLowerCase();
  const st = String(sessionStatus || "").toLowerCase();
  if (ss === "paid") return "paid";
  if (st === "expired") return "abandoned";
  if (["canceled","cancelled","requires_payment_method"].includes(ps)) return "failed";
  return "unpaid";
}

function __shouldRunJobs() {
  const v = String(process.env.RUN_JOBS || "").toLowerCase().trim();
  return (v === "1" || v === "true" || v === "yes");
}



// REQUEST_ID_MIDDLEWARE_TSTS
// Structured logging + request correlation + redaction (audit-grade)
function __rid() {
  try {
    return crypto.randomBytes(12).toString("hex");
  } catch (_) {
    return String(Date.now());
  }
}

function __isPlainObj(x) {
  const isObj = (x === null) ? false : (typeof x === "object");
  const isArr = Array.isArray(x) === true;
  return (isObj === true) && (isArr === false);
}

function __redact(x, depth) {
  const d = Number.isFinite(depth) ? Number(depth) : 0;
  if (d > 3) return "[redacted]";
  if (__isPlainObj(x) === false) return x;

  const out = {};
  const keys = Object.keys(x || {});
  for (const k of keys) {
    const ks = String(k || "").toLowerCase();
    const v = x[k];

    const isSensitive =
      (ks.indexOf("pass") >= 0) ||
      (ks.indexOf("password") >= 0) ||
      (ks.indexOf("secret") >= 0) ||
      (ks.indexOf("token") >= 0) ||
      (ks.indexOf("authorization") >= 0) ||
      (ks.indexOf("email") >= 0) ||
      (ks.indexOf("phone") >= 0) ||
      (ks.indexOf("mobile") >= 0);

    if (isSensitive) {
      out[k] = "[redacted]";
    } else {
      if (__isPlainObj(v) === true) out[k] = __redact(v, d + 1);
      else out[k] = v;
    }
  }
  return out;
}

function __log(level, event, meta) {
  try {
    const lvl = String(level || "info").toLowerCase();
    const ev = String(event || "event");
    const m = (meta && typeof meta === "object") ? meta : {};
    const payload = { ts: new Date().toISOString(), level: lvl, event: ev, meta: m };
    if (__winstonLogger) {
      const fn = (__winstonLogger[lvl] && typeof __winstonLogger[lvl] === "function") ? __winstonLogger[lvl] : __winstonLogger.info;
      fn.call(__winstonLogger, payload);
      return;
    }
    const line = JSON.stringify(payload);
    if (lvl === "error") {
      try { console.error(line); } catch (_) {}
      return;
    }
    try { console.log(line); } catch (_) {}
  } catch (_) {
    try { console.error("LOG_FAIL"); } catch (_) {}
  }
}

function __ridFromReq(req) {
  try {
    const r = (req && req.requestId) ? String(req.requestId) : "";
    if (r.length > 0) return r;
    return undefined;
  } catch (_) {
    return undefined;
  }
}

// attach requestId + access logs
app.use((req, res, next) => {
  const rid = __rid();
  req.requestId = rid;
  try { res.set("X-Request-Id", rid); } catch (_) {}

  const start = Date.now();
  res.on("finish", () => {
    __log("info", "http_access", {
      rid: rid,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start,
      ip: req.ip
    });
  });

  return next();
});





// ROOT_SERVICE_MARKER_TSTS
app.get("/", (req, res) => {
  res.status(200).json({ service: "shared-table-api", status: "ok" });
});

app.set("trust proxy", 1);
const PORT = process.env.PORT || 4000;

function __isProdEnv() {
  return String(process.env.NODE_ENV || "").toLowerCase() === "production";
}

// PUBLIC_URL is required in production so redirects never default to localhost.
// In dev/test we allow fallback to localhost:<PORT>.
function __requirePublicUrl() {
  const raw = String(process.env.PUBLIC_URL || "").trim().replace(/\/$/, "");
  const isProd = __isProdEnv();
  const hasRaw = raw.length > 0;

  if (isProd) {
    if (hasRaw === false) throw new Error("PUBLIC_URL_REQUIRED_IN_PROD");
    if (/^https:\/\//i.test(raw) === false) throw new Error("PUBLIC_URL_MUST_BE_HTTPS_IN_PROD");
  }

  if (hasRaw) return raw;

  const p = String(process.env.PORT || 4000);
  return "http://localhost:" + p;
}


// Security headers (baseline hardening)
app.disable("x-powered-by");
app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

// Rate limiting (basic abuse protection)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// CORS (locked allowlist)
// Set CORS_ORIGINS as comma-separated list
// Example: "https://thesharedtablestory.com,https://www.thesharedtablestory.com,http://localhost:3000"
const DEFAULT_CORS_ORIGINS = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "https://shared-table-frontend.onrender.com",
  "https://thesharedtablestory.com",
  "https://www.thesharedtablestory.com"
];

const ENV_CORS_ORIGINS = String(process.env.CORS_ORIGINS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);

const __urlToOrigin = (u) => {
  try {
    const x = new URL(String(u || "").trim());
    if (!x.protocol || !x.host) return "";
    return x.protocol + "//" + x.host;
  } catch (_) {
    return "";
  }
};

// Auto-allow the frontend origin used for reset links (keeps CORS + reset URL in sync)
const FRONTEND_ORIGIN_FOR_CORS = __urlToOrigin(process.env.FRONTEND_BASE_URL || "");
const ENV_EXTRA_ORIGINS = [FRONTEND_ORIGIN_FOR_CORS].filter(Boolean);

const CORS_ORIGINS = Array.from(new Set([...DEFAULT_CORS_ORIGINS, ...ENV_CORS_ORIGINS, ...ENV_EXTRA_ORIGINS]));

const corsOptions = {
  origin: function (origin, cb) {
    // allow non-browser requests (curl/postman) with no Origin header
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS blocked: origin not allowed"), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.post(
  "/api/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      __log("info", "stripe_webhook_hit", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
      if (!STRIPE_WEBHOOK_SECRET)
        return res.status(500).send("Missing STRIPE_WEBHOOK_SECRET");

      const sig = req.headers["stripe-signature"];
      let event;
      try {
        event = stripe.webhooks.constructEvent(
          req.body,
          sig,
          STRIPE_WEBHOOK_SECRET
        );
        __log("info", "stripe_webhook_verified", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
      } catch (err) {
        __log("error", "stripe_webhook_sig_fail", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
          return res.status(400).send("Webhook signature verification failed");
      }

      // Require DB for idempotency + booking state updates.
      // If DB is not connected, fail so Stripe retries (do not ACK when we cannot process).
      if (mongoose == null || mongoose.connection == null || mongoose.connection.readyState !== 1) {
        return res.status(500).send("DB not ready");
      }

      // Event-level idempotency: insert Stripe event.id first
      const eventId = String((event && event.id) ? event.id : "");
      if (eventId.length === 0) return res.json({ received: true });

      try { await __ensureStripeWebhookIndex(); } catch (_) {}

      const evCol = mongoose.connection.db.collection("stripe_webhook_events");
      try {
        await evCol.insertOne({
          eventId,
          type: String(event.type || ""),
          livemode: Boolean(event.livemode),
          createdAt: (event && event.created) ? new Date(Number(event.created) * 1000) : null,
          receivedAt: new Date(),
          processingAt: new Date(),
          processedAt: null,
          attempts: 1,
          error: "",
          data: (event && event.data) ? event.data : null,
        });
        __log("info", "stripe_webhook_event_inserted", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
        // Force-persist raw Stripe payload (bypass mongoose strict schema)
        try {
          await evCol.updateOne(
            { eventId },
            { $set: { data: (event && event.data) ? event.data : null } }
          );
        } catch (_) {}
      } catch (e) {
        if (__isDuplicateKeyError(e)) {
          // Duplicate eventId: claim processing only if not processed yet.
          try {
            const claimed = await evCol.findOneAndUpdate(
              { eventId, processedAt: null, $or: [{ processingAt: null }, { processingAt: { $exists: false } }, { processingAt: { $lte: new Date(Date.now() - 10 * 60 * 1000) } }] },
              { $set: { processingAt: new Date(), error: "", type: String(event.type || ""), livemode: Boolean(event.livemode), createdAt: (event && event.created) ? new Date(Number(event.created) * 1000) : null, receivedAt: new Date() }, $inc: { attempts: 1 } },
              { returnDocument: "after" }
            );
            if (!claimed || !claimed.value) {
              // Someone else is processing or already processed; ACK to stop retries.
              return res.json({ received: true, duplicate: true });
            }
          } catch (_) {
            // If claim fails, do not ACK; force retry.
            throw e;
          }
        } else {
          throw e;
        }
      }


      if (event.type === "checkout.session.completed") {
        const session = (event && event.data && event.data.object) ? event.data.object : {};
        const bookingId = session.client_reference_id || (session.metadata && session.metadata.bookingId);
        if (!bookingId) {
          try {
            await mongoose.connection
              .collection("stripe_webhook_events")
              .updateOne(
                { eventId },
                { $set: { processedAt: new Date(), processingAt: null, error: "missing_booking_id" } }
              );
          } catch (_) {}
          return res.json({ received: true });
        }

        // models are registered later during file load, so by runtime this exists
        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findById(bookingId);
        if (!booking) return res.json({ received: true });

        booking.stripeSessionId = String(
          session.id || booking.stripeSessionId || ""
        );

        try {
          if (session.id) {
            const full = await stripe.checkout.sessions.retrieve(
              String(session.id),
              {
                expand: ["payment_intent", "line_items"],
              }
            );

            if (!booking.currency)
              booking.currency = String(
                (full.currency ||
                  session.currency ||
                  (booking.pricing && booking.pricing.currency) ||
                  "aud")
              ).toLowerCase();

            const amt =
              (Number.isFinite(full.amount_total) && Number(full.amount_total)) ||
              (Number.isFinite(session.amount_total) && Number(session.amount_total)) ||
              (booking.pricing &&
                Number.isFinite(booking.pricing.totalCents) &&
                Number(booking.pricing.totalCents)) ||
              null;

            if (amt !== null) booking.amountCents = amt;

            const piObj = full.payment_intent;
            const pi =
              (piObj && (piObj.id || piObj)) ||
              session.payment_intent ||
              null;

            if (pi) booking.stripePaymentIntentId = String(pi);
          } else {
            if (session.payment_intent)
              booking.stripePaymentIntentId = String(session.payment_intent);
            if (Number.isFinite(session.amount_total))
              booking.amountCents = Number(session.amount_total);
            if (session.currency)
              booking.currency = String(session.currency).toLowerCase();
          }
        } catch (e) {
          if (session.payment_intent)
            booking.stripePaymentIntentId = String(session.payment_intent);
          if (Number.isFinite(session.amount_total))
            booking.amountCents = Number(session.amount_total);
          if (session.currency) booking.currency = String(session.currency).toLowerCase();
        }

        booking.currency = String(booking.currency || "aud").toLowerCase();

        await booking.save();

        try {
          if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
          const __when = new Date();
          const __gate = await Booking.findOneAndUpdate(
            { _id: booking._id, $or: [ { "comms.invoiceReceiptGuestSentAt": { $exists: false } }, { "comms.invoiceReceiptGuestSentAt": null } ] },
            { $set: { "comms.invoiceReceiptGuestSentAt": __when } },
            { new: true }
          );
          if (__gate) {
            const __to = booking.guestEmail ? String(booking.guestEmail).trim() : "";
            const __nm = booking.guestName ? String(booking.guestName).trim() : "";
            const __date = booking.bookingDate ? String(booking.bookingDate).trim() : "";
            const __title = booking.experienceTitle ? String(booking.experienceTitle).trim() : (booking.title ? String(booking.title).trim() : "" );
            const __cur = booking.currency ? String(booking.currency).trim().toUpperCase() : "AUD";
            let __cents = null;
            if (Number.isFinite(Number(booking.amountCents))) __cents = Number(booking.amountCents);
            else if (booking.pricing && Number.isFinite(Number(booking.pricing.totalCents))) __cents = Number(booking.pricing.totalCents);
            const __amt = (__cents === null) ? "" : (__cur + " " + (Number(__cents) / 100).toFixed(2));
            if (__to) {
              __fireAndForgetEmail({
                to: __to,
                eventName: "INVOICE_RECEIPT_GUEST",
                category: "PAYMENTS",
                vars: {
                  DASHBOARD_URL: __dashboardUrl(),
                  Name: __nm,
                  DATE: __date,
                  EXPERIENCE_TITLE: __title,
                  AMOUNT: __amt
                }
              });
            }
          }
        } catch (_) {}


      }


      
      if (event.type === "checkout.session.async_payment_failed" || event.type === "checkout.session.expired") {
        const session = (event && event.data && event.data.object) ? event.data.object : {};
        const bookingId = session.client_reference_id || (session.metadata && session.metadata.bookingId);
        if (!bookingId) {
          try {
            await mongoose.connection
              .collection("stripe_webhook_events")
              .updateOne(
                { eventId },
                { $set: { processedAt: new Date(), processingAt: null, error: "missing_booking_id" } }
              );
          } catch (_) {}
          return res.json({ received: true });
        }

        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findById(String(bookingId));
        if (!booking) return res.json({ received: true });

        // Try to expand session -> payment_intent so we can classify true failures
        let full = null;
        try {
          if (session && session.id) {
            full = await stripe.checkout.sessions.retrieve(String(session.id), { expand: ["payment_intent"] });
          }
        } catch (_) {}

        const stripeStatus = String((session && session.payment_status) ? session.payment_status : "unpaid");
        const piObj = (full && full.payment_intent) ? full.payment_intent : (session && session.payment_intent ? session.payment_intent : null);
        const piStatus = String((piObj && piObj.status) ? piObj.status : "");

        booking.paymentLastStripeStatus = stripeStatus;
        booking.paymentLastPiStatus = piStatus;
        booking.stripeSessionId = String(session.id || booking.stripeSessionId || "");

        // PAYMENT_ATTEMPT_POLICY_V1 (webhook mirror): count only real failures
        // Do NOT count requires_action as failure attempt
        const now = new Date();
        const lockedUntil = booking.paymentLockedUntil ? new Date(booking.paymentLockedUntil) : null;
        if (lockedUntil && lockedUntil.getTime() > now.getTime()) {
          // Already locked: do not keep incrementing attempts from webhook retries.
          await booking.save();
          return res.json({ received: true });
        }
        const isFail = (piStatus === "requires_payment_method" || piStatus === "canceled" || piStatus === "cancelled");
        if (stripeStatus !== "paid" && isFail) {
          booking.paymentAttemptCount = Number.isFinite(Number(booking.paymentAttemptCount)) ? Number(booking.paymentAttemptCount) + 1 : 1;
          booking.paymentAttemptFirstAt = booking.paymentAttemptFirstAt || now;
          booking.paymentAttemptLastAt = now;

          const firstAt = booking.paymentAttemptFirstAt ? new Date(booking.paymentAttemptFirstAt) : now;
          const within30m = (now.getTime() - firstAt.getTime()) <= (30 * 60 * 1000);
          const attempts = Number(booking.paymentAttemptCount || 0);
          if (within30m && attempts >= 5) {
            booking.paymentLockedUntil = new Date(now.getTime() + (30 * 60 * 1000));
          }
        }

        // Keep paymentStatus as unpaid unless already paid/confirmed
        if (String(booking.paymentStatus || "unpaid") !== "paid") {
          const __sessionStatus = String((session && session.status) ? session.status : "");
          const __outcome = __classifyPaymentOutcome(stripeStatus, (piObj && piObj.status) ? String(piObj.status) : "", __sessionStatus);
          booking.paymentStatus = __outcome;
        }

        try {
          if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
          const __isExpired = (event.type === "checkout.session.expired");
          const __isFail = (piStatus === "requires_payment_method" || piStatus === "canceled" || piStatus === "cancelled");
          if (__isExpired || (__isFail && stripeStatus !== "paid")) {
            const __when = new Date();
            const __gate = await Booking.findOneAndUpdate(
              { _id: booking._id, $or: [ { "comms.paymentFailedSentAt": { $exists: false } }, { "comms.paymentFailedSentAt": null } ] },
              { $set: { "comms.paymentFailedSentAt": __when } },
              { new: true }
            );
            if (__gate) {
              const __to = booking.guestEmail ? String(booking.guestEmail).trim() : "";
              const __nm = booking.guestName ? String(booking.guestName).trim() : "";
              if (__to) {
                __fireAndForgetEmail({
                  to: __to,
                  eventName: "PAYMENT_FAILED",
                  category: "PAYMENTS",
                  vars: {
                    DASHBOARD_URL: __dashboardUrl(),
                    Name: __nm
                  }
                });
              }
            }
          }
        } catch (_) {}

        await booking.save();
        return res.json({ received: true });
      }

      if (event.type === "refund.updated" || event.type === "refund.created") {
        const refund = event.data.object || {};
        const __refundAmt = (refund && Number.isFinite(Number(refund.amount))) ? Number(refund.amount) : null;
        const __refundCur = refund && refund.currency ? String(refund.currency).toLowerCase() : "";

        const pi = String(refund.payment_intent || "");
        const refundId = String(refund.id || "");
        const refundStatus = String(refund.status || "");
        if (!pi) return res.json({ received: true });

        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findOne({ stripePaymentIntentId: pi });
        if (!booking) return res.json({ received: true });

        if (!booking.refundDecision || typeof booking.refundDecision !== "object") booking.refundDecision = {};
        if (__refundAmt !== null) booking.refundDecision.amountCents = __refundAmt;
        if (__refundCur) booking.refundDecision.currency = __refundCur;

        if (refundId) booking.refundDecision.stripeRefundId = refundId;
        if (refundStatus) booking.refundDecision.stripeRefundStatus = refundStatus;

        if (refundStatus === "succeeded") {
          booking.refundDecision.status = "refunded";
          await transitionBooking(booking, "refunded");
        } else if (refundStatus === "failed" || refundStatus === "canceled" || refundStatus === "cancelled") {
          booking.refundDecision.status = "refund_failed";
        }
        await booking.save();
      }

      if (event.type === "charge.refunded") {
        const charge = event.data.object || {};
        const pi = String(charge.payment_intent || "");
        if (!pi) return res.json({ received: true });

        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findOne({ stripePaymentIntentId: pi });
        if (!booking) return res.json({ received: true });

        if (!booking.refundDecision || typeof booking.refundDecision !== "object") booking.refundDecision = {};
        booking.refundDecision.stripeRefundStatus = "succeeded";
        booking.refundDecision.status = "refunded";
        await transitionBooking(booking, "refunded");
        await booking.save();
      }

      // Mark processed only after successful handling
      try {
        await mongoose.connection
          .collection("stripe_webhook_events")
          .updateOne(
            { eventId },
            { $set: { processedAt: new Date(), processingAt: null, error: "" } }
          );
      } catch (_) {}

      return res.json({ received: true });
    } catch (e) {
      try {
        if (mongoose && mongoose.connection && mongoose.connection.readyState === 1) {
          const evCol2 = mongoose.connection.db.collection("stripe_webhook_events");
          if (typeof eventId === "string" && eventId.length > 0) {
            await evCol2.updateOne(
              { eventId },
              { $set: { error: String((e && e.message) ? e.message : "webhook_error"), processingAt: null } }
            );
          }
        }
      } catch (_) {}
      __log("error", "stripe_webhook_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
        return res.status(500).send("Webhook handler error");
    }
  }
);

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));

// Baseline request validation (no external deps):
// - Reject non-object JSON bodies for write endpoints.
// - Parser limits above protect payload size.
function __isPlainObject(x) {
  if (x === null || typeof x !== "object") return false;
  if (Array.isArray(x)) return false;
  const proto = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
}
function __cleanId(x, maxLen) {
  const v = String((x === null || x === undefined) ? "" : x).trim();
  if (v.length === 0) return "";
  if (v.length > (maxLen || 128)) return "";
  return v;
}
app.use("/api", (req, res, next) => {
  try {
    const m = String(req.method || "").toUpperCase();
    const isWrite = (m === "POST" || m === "PUT" || m === "PATCH");
    if (isWrite === false) return next();

    const ct = String(req.headers["content-type"] || "").toLowerCase();
    const isJson = ct.indexOf("application/json") >= 0;

    if (isJson) {
      if (__isPlainObject(req.body) === false) {
        return res.status(400).json({ error: "invalid_json_body" });
      }
    }
    return next();
  } catch (_) {
    return res.status(400).json({ error: "invalid_request" });
  }
});

// JSON parse / body size errors (clean response)
app.use((err, req, res, next) => {
  const msg = String((err && err.message) ? err.message : "").toLowerCase();
  const typeStr = String((err && err.type) ? err.type : "");
  const tooLarge = (typeStr === "entity.too.large") || (msg.indexOf("request entity too large") >= 0);

  if (tooLarge) {
    return res.status(413).json({ error: "payload_too_large" });
  }

  const looksJson = (msg.indexOf("unexpected token") >= 0) || (msg.indexOf("json") >= 0);
  if (looksJson) {
    return res.status(400).json({ error: "invalid_json" });
  }

  return next(err);
});


app.use("/api", apiLimiter);
app.use("/api/auth", authLimiter);
app.use("/api/admin", adminLimiter);

// CORS error handler (clean response)
app.use((err, req, res, next) => {
  if (err && String(err.message || "").startsWith("CORS blocked")) {
    return res.status(403).json({ error: "CORS blocked" });
  }
  return next(err);
});

// HTTP_ERROR_MIDDLEWARE_TSTS
app.use((err, req, res, next) => {
  try {
    const sent = Boolean(res && (res.headersSent === true));
    if (sent) {
      return next(err);
    }

    const rid = __ridFromReq(req);
    const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";
    const msg = (err && err.message) ? String(err.message) : "server_error";
    const name = (err && err.name) ? String(err.name) : undefined;
    const stack = (isProd === true) ? undefined : ((err && err.stack) ? String(err.stack) : undefined);

    __log("error", "http_error", {
      rid: rid,
      path: (req && req.originalUrl) ? String(req.originalUrl) : undefined,
      method: (req && req.method) ? String(req.method) : undefined,
      status: 500,
      errorName: name,
      errorMessage: msg,
      errorStack: stack
    });

    return res.status(500).json({ error: "server_error", rid: rid });
  } catch (_) {
    return res.status(500).json({ error: "server_error" });
  }
});



// Stripe webhook idempotency: dedupe by Stripe event.id
let __stripeWebhookIndexPromise = null;
async function __ensureStripeWebhookIndex() {
  try {
    if (__stripeWebhookIndexPromise) return __stripeWebhookIndexPromise;
    if (mongoose == null) return null;
    if (mongoose.connection == null) return null;
    __stripeWebhookIndexPromise = mongoose.connection
      .collection("stripe_webhook_events")
      .createIndex({ eventId: 1 }, { unique: true, background: true });
    return __stripeWebhookIndexPromise;
  } catch (_) {
    return null;
  }
}
function __isDuplicateKeyError(e) {
  try {
    if (e == null) return false;
    if (e.code === 11000) return true;
    return String(e.message || '').includes('E11000');
  } catch (_) {
    return false;
  }
}

// IMPORTANT: webhook must be registered BEFORE express.json()




function reTest(r, v){ try { return r.test(String(v||"")); } catch(_) { return false; } }


// 2. CONNECT TO MONGODB
mongoose
  .connect(process.env.MONGO_URI)
  .then(async () => {
  try { await ensureDefaultPolicyExists(); } catch (_) {}
  try { await __ensureStripeWebhookIndex(); } catch (_) {}
__dbReady = true;
  __log("info", "db_connected", { rid: undefined, path: undefined });
  try { global.__tsts_db_connected = true; } catch (_) {}
  try { startUnpaidBookingExpiryCleanupLoop_V1(); } catch (_) {}
  try { startPaymentReconciliationLoop_V1(); } catch (_) {}


})
  .catch((err) => { __log("error", "db_connect_error", { rid: undefined, path: undefined }); });

// 3. SETUP CLOUDINARY
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

function __isAllowedImageMime(t) {
  try {
    const mt = String(t || "").toLowerCase().trim();
    if (mt === "image/jpeg") return true;
    if (mt === "image/jpg") return true;
    if (mt === "image/png") return true;
    return false;
  } catch (_) {
    return false;
  }
}

function __uploadBufferToCloudinary(buf, originalName) {
  return new Promise((resolve, reject) => {
    try {
      const name = String(originalName || "").trim();
      const opts = { folder: "shared-table-uploads", resource_type: "image" };
      if (name.length > 0) opts.context = "filename=" + name;
      const stream = cloudinary.uploader.upload_stream(opts, (err, result) => {
        if (err) return reject(err);
        if (result == null) return reject(new Error("cloudinary_no_result"));
        return resolve(result);
      });
      stream.end(buf);
    } catch (e) {
      return reject(e);
    }
  });
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 6 * 1024 * 1024, files: 3 },
  fileFilter: (req, file, cb) => {
    const ok = __isAllowedImageMime(file && file.mimetype);
    if (ok === true) return cb(null, true);
    return cb(new Error("invalid_file_type"), false);
  }
});


// 4. EMAIL (single contract: SMTP_* + optional FROM_EMAIL)
// Env contract:
//   SMTP_HOST, SMTP_USER, SMTP_PASS are required to send email
//   SMTP_PORT (default 587), SMTP_SECURE ("true"/"false"), FROM_EMAIL (optional)
let __mailer = null;
function getMailer() {
  const host = String(process.env.SMTP_HOST || "");
  const user = String(process.env.SMTP_USER || "");
  const pass = String(process.env.SMTP_PASS || "");
  if (!host || !user || !pass) return null;

  if (__mailer) return __mailer;

  __mailer = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    auth: { user, pass },
  });
  return __mailer;
}

async function sendEmail({ to, subject, html, text }) {
  const mailer = getMailer();
  if (!mailer) return false;

  const from = String(process.env.FROM_EMAIL || process.env.SMTP_USER || "");
  try {
    await mailer.sendMail({
      from,
      to,
      subject,
      ...(html ? { html } : {}),
      ...(text ? { text } : {}),
    });
    return true;
  } catch (err) {
    __log("error", "email_send_failed", { rid: undefined, path: undefined });
    return false;
  }
}

function __frontendBaseUrl() {
  const raw = String(process.env.FRONTEND_BASE_URL || "http://localhost:3000");
  return raw.replace(/\/$/, "");
}
function __dashboardUrl() {
  return __frontendBaseUrl() + "/dashboard";
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function emailLayout(title, bodyHtml, cta) {
  const safeTitle = escapeHtml(title);
  const href = cta && cta.href ? String(cta.href) : "";
  const hasCta = href.trim().length > 0;

  const DOCTYPE = "<" + "!" + "doctype html>";

  const ctaHtml = hasCta
    ? `<div style="margin:20px 0 0">
         <a href="${escapeHtml(href)}"
            style="display:inline-block;padding:12px 16px;border-radius:10px;background:#111827;color:#ffffff;text-decoration:none;font-weight:600">
           ${escapeHtml(cta.text || "Open")}
         </a>
       </div>`
    : "";

  return `${DOCTYPE}
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safeTitle}</title>
</head>
<body style="margin:0;background:#f6f7fb;font-family:system-ui">
  <div style="max-width:560px;margin:0 auto;padding:24px">
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:22px">
      <h1 style="margin:0 0 12px 0;font-size:18px">${safeTitle}</h1>
      <div style="font-size:14px;line-height:1.6">
        ${bodyHtml || ""}
        ${ctaHtml}
      </div>
    </div>
    <div style="font-size:12px;color:#6b7280;margin-top:12px">
      The Shared Table Story
    </div>
  </div>
</body>
</html>`;
}

function welcomeEmailHtml(name) {
  const who = escapeHtml(String(name || "").trim());
  const hi = who.length > 0 ? ("Hi " + who + ",") : "Hi,";

  return emailLayout(
    "Welcome",
    `<p style="margin:0 0 12px 0">${hi}</p>
     <p style="margin:0 0 12px 0">Welcome to The Shared Table Story.</p>
     <p style="margin:0 0 12px 0">The Shared Table Story is a curated marketplace for local experiences across Culture, Food, and Nature.</p>
     <p style="margin:0 0 12px 0">It is built for people who value depth, presence, and genuine connection over mass tourism.</p>
     <p style="margin:0 0 12px 0">Each experience is hosted by individuals who share a table, a trail, a tradition, or a craft with a small group, thoughtfully and intentionally.</p>
     <p style="margin:0">If you did not create this account, you can ignore this email.</p>`,
    null
  );
}
function resetPasswordEmailHtml(resetUrl) {
  const href = String(resetUrl || "").trim();
  return emailLayout(
    "Reset your password",
    `<p style="margin:0 0 12px 0">Use the button below to reset your password. The link is valid for 30 minutes.</p>
     <p style="margin:0">If you did not request this, you can ignore this email.</p>`,
    { text: "Reset password", href }
  );
}


function bookingConfirmedGuestEmailHtml(booking, guest, host) {
  const g = guest || {};
  const b = booking || {};
  const h = host || {};
  const title = "Booking confirmed";

  const name = escapeHtml(String(g.name || "").trim());
  const exp = escapeHtml(String(b.experienceTitle || b.title || "").trim());
  const date = escapeHtml(String(b.bookingDate || "").trim());
  const time = escapeHtml(String(b.timeSlot || "").trim());
  const hostName = escapeHtml(String(h.name || b.hostName || "").trim());

  const body =
    "<p style=\"margin:0 0 12px 0\">Hi " + name + ",</p>" +
    "<p style=\"margin:0 0 12px 0\">Your booking is confirmed.</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Experience</b>: " + exp + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Date</b>: " + date + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Time</b>: " + time + "</p>" +
    "<p style=\"margin:0\"><b>Host</b>: " + hostName + "</p>";

  return emailLayout(title, body, null);
}

function bookingConfirmedHostEmailHtml(booking, guest, host) {
  const g = guest || {};
  const b = booking || {};
  const h = host || {};
  const title = "New booking received";

  const hostName = escapeHtml(String(h.name || b.hostName || "").trim());
  const guestName = escapeHtml(String(g.name || b.guestName || "").trim());
  const exp = escapeHtml(String(b.experienceTitle || b.title || "").trim());
  const date = escapeHtml(String(b.bookingDate || "").trim());
  const time = escapeHtml(String(b.timeSlot || "").trim());

  const body =
    "<p style=\"margin:0 0 12px 0\">Hi " + hostName + ",</p>" +
    "<p style=\"margin:0 0 12px 0\">A guest has a confirmed booking.</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Guest</b>: " + guestName + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Experience</b>: " + exp + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Date</b>: " + date + "</p>" +
    "<p style=\"margin:0\"><b>Time</b>: " + time + "</p>";

  return emailLayout(title, body, null);
}

function bookingCancelledGuestEmailHtml(booking, guest, host) {
  const g = guest || {};
  const b = booking || {};
  const h = host || {};
  const title = "Booking cancelled";

  const name = escapeHtml(String(g.name || "").trim());
  const exp = escapeHtml(String(b.experienceTitle || b.title || "").trim());
  const date = escapeHtml(String(b.bookingDate || "").trim());
  const time = escapeHtml(String(b.timeSlot || "").trim());
  const hostName = escapeHtml(String(h.name || b.hostName || "").trim());

  const body =
    "<p style=\"margin:0 0 12px 0\">Hi " + name + ",</p>" +
    "<p style=\"margin:0 0 12px 0\">This booking was cancelled.</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Experience</b>: " + exp + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Date</b>: " + date + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Time</b>: " + time + "</p>" +
    "<p style=\"margin:0\"><b>Host</b>: " + hostName + "</p>";

  return emailLayout(title, body, null);
}

function bookingCancelledHostEmailHtml(booking, guest, host) {
  const g = guest || {};
  const b = booking || {};
  const h = host || {};
  const title = "Booking cancelled";

  const hostName = escapeHtml(String(h.name || b.hostName || "").trim());
  const guestName = escapeHtml(String(g.name || b.guestName || "").trim());
  const exp = escapeHtml(String(b.experienceTitle || b.title || "").trim());
  const date = escapeHtml(String(b.bookingDate || "").trim());
  const time = escapeHtml(String(b.timeSlot || "").trim());

  const body =
    "<p style=\"margin:0 0 12px 0\">Hi " + hostName + ",</p>" +
    "<p style=\"margin:0 0 12px 0\">A booking was cancelled.</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Guest</b>: " + guestName + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Experience</b>: " + exp + "</p>" +
    "<p style=\"margin:0 0 8px 0\"><b>Date</b>: " + date + "</p>" +
    "<p style=\"margin:0\"><b>Time</b>: " + time + "</p>";

  return emailLayout(title, body, null);
}






// 5. SCHEMAS
const schemaOpts = { toJSON: { virtuals: true }, toObject: { virtuals: true } };

const notificationSchema = new mongoose.Schema(
  {
    message: String,
    type: { type: String, default: "info" },
    date: { type: Date, default: Date.now },
  },
  schemaOpts
);

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: "Guest" },
    profilePic: { type: String, default: "" },
    isPremiumHost: { type: Boolean, default: false },
    vacationMode: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false },
    bio: { type: String, default: "" },
    location: { type: String, default: "" },
    mobile: { type: String, default: "" },
    preferences: [String],
    payoutDetails: Object,
    notifications: [notificationSchema],
    guestRating: { type: Number, default: 0 },
    guestReviewCount: { type: Number, default: 0 },

    // Legal / Consent
    termsAgreedAt: { type: Date, default: null },
    termsVersion: { type: String, default: "" },

    // Password reset (email-optional; token stored as hash)
    passwordResetTokenHash: { type: String, default: "" },
    emailVerified: { type: Boolean, default: false },
    accountStatus: { type: String, default: "active" }, // active|disabled|suspended|banned|locked|deleted
    accountStatusChangedAt: { type: Date, default: null },
    accountStatusReason: { type: String, default: "" },
    tokenVersion: { type: Number, default: 0 },
    emailVerificationTokenHash: { type: String, default: "" },
    emailVerificationRequestedAt: { type: Date, default: null },
    emailVerificationExpiresAt: { type: Date, default: null },
    passwordResetExpiresAt: { type: Date, default: null },
    passwordResetRequestedAt: { type: Date, default: null },

    // Social foundation (privacy-preserving)
    handle: { type: String, unique: true, sparse: true }, // exact-match lookup only
    allowHandleSearch: { type: Boolean, default: false }, // opt-in
    showExperiencesToFriends: { type: Boolean, default: false }, // opt-in visibility

    // Public profile (privacy-first)
    publicProfile: { type: Boolean, default: false }, // opt-in: bio/pic shown
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
    suburb: { type: String, default: "" },
    postcode: { type: String, default: "" },
    addressLine: { type: String, default: "" },
    addressNotes: { type: String, default: "" },

    price: Number,
    maxGuests: Number,
    originalMaxGuests: Number,
    startDate: String,
    endDate: String,
    blockedDates: [String],
    availableDays: { type: [String], default: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] },
    isPaused: { type: Boolean, default: false },
    tags: [String],
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
    createdAt: { type: Date, default: Date.now },
  },
  schemaOpts
);

const bookingSchema = new mongoose.Schema(
  {
    experienceId: String,
    guestId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    hostId: { type: String, required: false },
    guestName: String,
    guestEmail: String,
    numGuests: Number,
    bookingDate: String,
    timeSlot: String,
    guestNotes: { type: String, default: "" },
    status: { type: String, default: "pending_payment" },
    stripeSessionId: String,
    paymentStatus: { type: String, enum: ["unpaid","paid","failed","abandoned"], default: "unpaid" },

    expiresAt: { type: Date, default: null },
    pricing: Object,
    comms: { type: Object, default: {} },

    // Payment reconciliation
    // Payment attempt governance (anti-abuse / user protection)
    paymentAttemptCount: { type: Number, default: 0 },
    paymentAttemptFirstAt: { type: Date, default: null },
    paymentAttemptLastAt: { type: Date, default: null },
    paymentLockedUntil: { type: Date, default: null },
    paymentLastStripeStatus: { type: String, default: "" },
    paymentLastPiStatus: { type: String, default: "" },

    amountCents: Number,
    currency: String,
    stripePaymentIntentId: String,
    paidAt: Date,

    // Booking comms idempotency markers
    guestConfirmedAt: { type: Date, default: null },
    hostConfirmedAt: { type: Date, default: null },
    guestCancelledAt: { type: Date, default: null },
    hostCancelledAt: { type: Date, default: null },


    // Social visibility (opt-in by guest)
    visibilityToFriends: { type: Boolean, default: false },


    // Immutable policy + terms snapshots (write-once per booking)
    policySnapshot: { type: Object, default: {} },
    policyVersion: { type: String, default: "" },
    policyEffectiveFrom: { type: Date, default: null },
    policyVersionId: { type: String, default: "" },
    policyPublishedAt: { type: Date, default: null },
    policyAcceptedAt: { type: Date, default: null },
    termsVersionAccepted: { type: String, default: "" },
    termsAcceptedAt: { type: Date, default: null },

    termsSnapshot: { type: Object, default: null },
    // Cancellation + refund decision (computed from snapshot; idempotent)
    cancellation: {
      by: { type: String, default: "" }, // guest|host|admin
      at: { type: Date, default: null },
      reasonCode: { type: String, default: "" },
      note: { type: String, default: "" },
    },
    refundDecision: {
      status: { type: String, default: "none" }, // none|manual|computed|refunded
      amountCents: { type: Number, default: 0 },
      currency: { type: String, default: "aud" },
      percent: { type: Number, default: 0 },
      computedAt: { type: Date, default: null },
      stripeRefundId: { type: String, default: "" },
      stripeRefundStatus: { type: String, default: "" },
      attemptCount: { type: Number, default: 0 },
      lastAttemptAt: { type: Date, default: null },
      lastError: { type: String, default: "" },
    },
    refundAmount: Number,
    cancellationReason: String,
    dispute: {
      active: { type: Boolean, default: false },
      reason: String,
      status: String,
    },
    createdAt: { type: Date, default: Date.now },
  },
  schemaOpts
);

// --- Capacity reservations (race-safe) ---
// Tracks reserved guests per experience/date/slot to prevent overbooking.
const capacitySlotSchema = new mongoose.Schema(
  {
    experienceId: { type: String, required: true },
    bookingDate: { type: String, required: true },   // YYYY-MM-DD
    timeSlot: { type: String, required: true },
    reservedGuests: { type: Number, default: 0 },
    maxGuests: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  schemaOpts
);

capacitySlotSchema.index({ experienceId: 1, bookingDate: 1, timeSlot: 1 }, { unique: true });

const CapacitySlot = mongoose.models.CapacitySlot || mongoose.model("CapacitySlot", capacitySlotSchema);


// Virtuals
bookingSchema.virtual("experience", {
  ref: "Experience",
  localField: "experienceId",
  foreignField: "_id",
  justOne: true,
});
bookingSchema.virtual("user", {
  ref: "User",
  localField: "guestId",
  foreignField: "_id",
  justOne: true,
});

// --- Policy (AU cancellation/refund rules) ---
// Draft -> Publish -> Active, with effectiveFrom. Bookings store immutable snapshots.
const policySchema = new mongoose.Schema(
  {
    version: { type: String, required: true },
    status: { type: String, default: "draft" },     // draft|published
    active: { type: Boolean, default: false },
    effectiveFrom: { type: Date, required: true },
    publishedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },

    rules: {
      currency: { type: String, default: "aud" },
      guestMaxRefundPercent: { type: Number, default: 0.95 }, // cap at 95%
      hostRefundPercent: { type: Number, default: 1.0 },      // 100% reversal
      guestFreeCancelHours: { type: Number, default: 0 },
      absoluteMaxGuestRefundPercent: { type: Number, default: 0.95 },
    },
  },
  schemaOpts
);
policySchema.index({ active: 1, effectiveFrom: -1 });

const Policy = mongoose.models.Policy || mongoose.model("Policy", policySchema);

async function getActivePolicyDoc() {
  const now = new Date();
  return await Policy.findOne({ active: true, effectiveFrom: { $lte: now } })
    .sort({ effectiveFrom: -1 })
    .lean();
}

function policySnapshotFromDoc(doc) {
  if (!doc) return null;
  return {
    version: String(doc.version || ""),
    effectiveFrom: doc.effectiveFrom || null,
    publishedAt: doc.publishedAt || null,
    rules: doc.rules || {},
  };
}

async function ensureDefaultPolicyExists() {
  const any = await Policy.findOne({}).select("_id").lean();
  if (any) return;
  const now = new Date();
  const ver = now.toISOString();
  await Policy.create({
    version: ver,
    status: "published",
    active: true,
    effectiveFrom: now,
    publishedAt: now,
    rules: {
      currency: "aud",
      guestMaxRefundPercent: 0.95,
      hostRefundPercent: 1.0,
      guestFreeCancelHours: 0,
      absoluteMaxGuestRefundPercent: 0.95,
    },
  });
}

const reviewSchema = new mongoose.Schema(
  {
    experienceId: String,
    bookingId: String,
    authorId: String,
    authorName: String,
    targetId: String,
    type: { type: String, default: "guest_to_host" },
    rating: Number,
    comment: String,
    hostReply: String,
    date: { type: Date, default: Date.now },
  },
  schemaOpts
);

// Likes (experience-level)
const experienceLikeSchema = new mongoose.Schema(
  {
    experienceId: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    createdAt: { type: Date, default: Date.now },
  },
  schemaOpts
);
experienceLikeSchema.index({ experienceId: 1, userId: 1 }, { unique: true });

// Comments (experience-level)
const experienceCommentSchema = new mongoose.Schema(
  {
    experienceId: { type: String, required: true },
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  schemaOpts
);

const Bookmark = mongoose.model(
  "Bookmark",
  new mongoose.Schema(
    {
      userId: String,
      experienceId: String,
    },
    schemaOpts
  )
);

const User = mongoose.model("User", userSchema);
const Experience = mongoose.model("Experience", experienceSchema);


function stripExperiencePrivateFields(expObj) {
  if (!expObj || typeof expObj !== "object") return expObj;

  // Always return a NEW object (do not mutate mongoose docs or shared refs)
  const o = (expObj && typeof expObj.toObject === "function") ? expObj.toObject() : expObj;
  const safe = { ...o };

  // Remove private location/contact details from public surfaces
  delete safe.addressLine;
  delete safe.addressNotes;

  return safe;
}

async function canSeeExperiencePrivate(req, exp) {
  try {
    if (!req || !req.user || !exp) return false;
    const userId = String(req.user._id || "");
    if (!userId) return false;

    // host/admin can always see
    if (String(exp.hostId || "") === userId) return true;
    if (req.user && req.user.isAdmin) return true;

    // paid/confirmed booking can see
    const b = await Booking.findOne({
      experienceId: String(exp._id),
      guestId: req.user._id,
      $or: [{ paymentStatus: "paid" }, { status: "confirmed" }],
    }).lean();
    return !!b;
  } catch (_) {
    return false;
  }
}

const Booking = mongoose.model("Booking", bookingSchema);
const Review = mongoose.model("Review", reviewSchema);
const ExperienceLike = mongoose.model("ExperienceLike", experienceLikeSchema);
const ExperienceComment = mongoose.model("ExperienceComment", experienceCommentSchema);

// Social: privacy-preserving connections
const connectionSchema = new mongoose.Schema(
  {
    requesterId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    addresseeId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    status: {
      type: String,
      enum: ["pending", "accepted", "rejected", "blocked"],
      default: "pending",
    },
    createdAt: { type: Date, default: Date.now },
    respondedAt: { type: Date, default: null },
  },
  schemaOpts
);
connectionSchema.index({ requesterId: 1, addresseeId: 1 }, { unique: true });
const Connection = mongoose.models.Connection || mongoose.model("Connection", connectionSchema);

// --- MIDDLEWARE ---

async function maybeSendBookingConfirmedComms(booking) {
  try {
    if (!booking) return;
    if (booking.guestConfirmedAt) return;

    const b = booking || {};
    const guestEmail = String(b.guestEmail || "").trim();
    const guestName = String(b.guestName || "").trim();

    const hostId = String(b.hostId || "").trim();
    let hostDoc = null;
    if (hostId.length > 0) hostDoc = await User.findById(hostId);
    if ((hostDoc == null) && String(b.experienceId || "").trim().length > 0) {
      const expDoc = await Experience.findById(String(b.experienceId || "").trim());
      const expHostId = (expDoc && expDoc.hostId) ? String(expDoc.hostId).trim() : "";
      if (expHostId.length > 0) hostDoc = await User.findById(expHostId);
    }

    const hostEmail = String((hostDoc && hostDoc.email) || "").trim();
    const hostName = String((hostDoc && hostDoc.name) || "").trim();

    const expTitle = String(b.experienceTitle || b.title || "").trim();
    const bookingDate = String(b.bookingDate || "").trim();
    const timeSlot = String(b.timeSlot || "").trim();
    const guestNameSafe = (guestName.length > 0 ? guestName : "there");
    const hostNameSafe = (hostName.length > 0 ? hostName : "there");
    const __ctx = {
      Name: guestNameSafe,
      GUEST_NAME: guestNameSafe,
      HOST_NAME: hostNameSafe,
      EXPERIENCE_TITLE: expTitle,
      BOOKING_DATE: bookingDate,
      TIME_SLOT: timeSlot,
      DATE: bookingDate,
      TIME: timeSlot,
      DASHBOARD_URL: __dashboardUrl()
    };

    var __need = ['DASHBOARD_URL', 'DATE', 'EXPERIENCE_TITLE', 'HOST_NAME', 'Name', 'TIME'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx, k) && String(__ctx[k] || "").trim().length > 0) __vars[k] = String(__ctx[k]).trim();
      else __vars[k] = "—";
    }
    if (guestEmail.length > 0) {
      await sendEventEmail({
        eventName: "BOOKING_CONFIRMED_GUEST",
        category: "NOTIFICATIONS",
        to: guestEmail,
        vars: { DASHBOARD_URL: __vars["DASHBOARD_URL"], DATE: __vars["DATE"], EXPERIENCE_TITLE: __vars["EXPERIENCE_TITLE"], HOST_NAME: __vars["HOST_NAME"], Name: __vars["Name"], TIME: __vars["TIME"] }
      });
    }

    const __ctx2 = Object.assign({}, __ctx);
    __ctx2.Name = (hostName.length > 0 ? hostName : "there");
    var __need = ['DASHBOARD_URL', 'DATE', 'EXPERIENCE_TITLE', 'GUEST_NAME', 'HOST_NAME', 'TIME'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx2, k) && String(__ctx2[k] || "").trim().length > 0) __vars[k] = String(__ctx2[k]).trim();
      else __vars[k] = "—";
    }
    if (hostEmail.length > 0) {
      await sendEventEmail({
        eventName: "BOOKING_CONFIRMED_HOST",
        category: "NOTIFICATIONS",
        to: hostEmail,
        vars: { DASHBOARD_URL: __vars["DASHBOARD_URL"], DATE: __vars["DATE"], EXPERIENCE_TITLE: __vars["EXPERIENCE_TITLE"], GUEST_NAME: __vars["GUEST_NAME"], HOST_NAME: __vars["HOST_NAME"], TIME: __vars["TIME"] }
      });
    }

    const now = new Date();
    if (guestEmail.length > 0) booking.guestConfirmedAt = booking.guestConfirmedAt || now;
    if (hostEmail.length > 0) booking.hostConfirmedAt = booking.hostConfirmedAt || now;
    await booking.save();
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    console.error("COMMS_CONFIRM_ERR", msg);
  }
}


async function maybeSendBookingCancelledComms(booking) {
  try {
    if (!booking) return;
    if (booking.guestCancelledAt) return;

    const b = booking || {};
    const guestEmail = String(b.guestEmail || "").trim();
    const guestName = String(b.guestName || "").trim();

    const hostId = String(b.hostId || "").trim();
    let hostDoc = null;
    if (hostId.length > 0) hostDoc = await User.findById(hostId);
    if ((hostDoc == null) && String(b.experienceId || "").trim().length > 0) {
      const expDoc = await Experience.findById(String(b.experienceId || "").trim());
      const expHostId = (expDoc && expDoc.hostId) ? String(expDoc.hostId).trim() : "";
      if (expHostId.length > 0) hostDoc = await User.findById(expHostId);
    }

    const hostEmail = String((hostDoc && hostDoc.email) || "").trim();
    const hostName = String((hostDoc && hostDoc.name) || "").trim();

    const expTitle = String(b.experienceTitle || b.title || "").trim();
    const bookingDate = String(b.bookingDate || "").trim();
    const timeSlot = String(b.timeSlot || "").trim();
    const guestNameSafe = (guestName.length > 0 ? guestName : "there");
    const hostNameSafe = (hostName.length > 0 ? hostName : "there");
    const __ctx = {
      Name: guestNameSafe,
      GUEST_NAME: guestNameSafe,
      HOST_NAME: hostNameSafe,
      EXPERIENCE_TITLE: expTitle,
      BOOKING_DATE: bookingDate,
      TIME_SLOT: timeSlot,
      DATE: bookingDate,
      TIME: timeSlot,
      DASHBOARD_URL: __dashboardUrl()
    };

    var __need = ['DASHBOARD_URL', 'DATE', 'EXPERIENCE_TITLE', 'Name', 'TIME'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx, k) && String(__ctx[k] || "").trim().length > 0) __vars[k] = String(__ctx[k]).trim();
      else __vars[k] = "—";
    }
    if (guestEmail.length > 0) {
      await sendEventEmail({
        eventName: "BOOKING_CANCELLED_BY_GUEST_GUEST",
        category: "NOTIFICATIONS",
        to: guestEmail,
        vars: { DASHBOARD_URL: __vars["DASHBOARD_URL"], DATE: __vars["DATE"], EXPERIENCE_TITLE: __vars["EXPERIENCE_TITLE"], Name: __vars["Name"], TIME: __vars["TIME"] }
      });
    }

    const __ctx2 = Object.assign({}, __ctx);
    __ctx2.Name = (hostName.length > 0 ? hostName : "there");
    var __need = ['DASHBOARD_URL', 'DATE', 'EXPERIENCE_TITLE', 'HOST_NAME', 'TIME'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx2, k) && String(__ctx2[k] || "").trim().length > 0) __vars[k] = String(__ctx2[k]).trim();
      else __vars[k] = "—";
    }
    if (hostEmail.length > 0) {
      await sendEventEmail({
        eventName: "BOOKING_CANCELLED_BY_GUEST_HOST",
        category: "NOTIFICATIONS",
        to: hostEmail,
        vars: { DASHBOARD_URL: __vars["DASHBOARD_URL"], DATE: __vars["DATE"], EXPERIENCE_TITLE: __vars["EXPERIENCE_TITLE"], HOST_NAME: __vars["HOST_NAME"], TIME: __vars["TIME"] }
      });
    }
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    console.error("COMMS_CANCEL_ERR", msg);
  }
}


async function maybeSendBookingExpiredComms(booking) {
  // claim-before-send enabled
  try {
    if (!booking) return;
    try {
      if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
    } catch (_) {}

    let __expiredGuestAlready = false;
    let __expiredHostAlready = false;
    try {
      __expiredGuestAlready = Boolean(booking.comms.bookingExpiredGuestSentAt);
      __expiredHostAlready = Boolean(booking.comms.bookingExpiredHostSentAt);
    } catch (_) {}

    const b = booking || {};
    const guestEmail = String(b.guestEmail || "").trim();
    const guestName = String(b.guestName || "").trim();

    const hostId = String(b.hostId || "").trim();
    let hostDoc = null;
    try {
      if (hostId.length > 0) hostDoc = await User.findById(hostId);
      if ((hostDoc == null) && String(b.experienceId || "").trim().length > 0) {
        const expDoc = await Experience.findById(String(b.experienceId || "").trim());
        const expHostId = (expDoc && expDoc.hostId) ? String(expDoc.hostId).trim() : "";
        if (expHostId.length > 0) hostDoc = await User.findById(expHostId);
      }
    } catch (_) {}

    const hostEmail = String((hostDoc && hostDoc.email) || "").trim();
    const hostName = String((hostDoc && hostDoc.name) || "").trim();

    const expTitle = String(b.experienceTitle || b.title || "").trim();
    const bookingDate = String(b.bookingDate || "").trim();
    const timeSlot = String(b.timeSlot || "").trim();
    const guestNameSafe = (guestName.length > 0 ? guestName : "there");
    const hostNameSafe = (hostName.length > 0 ? hostName : "there");
    const __ctx = {
      Name: guestNameSafe,
      GUEST_NAME: guestNameSafe,
      HOST_NAME: hostNameSafe,
      EXPERIENCE_TITLE: expTitle,
      BOOKING_DATE: bookingDate,
      TIME_SLOT: timeSlot,
      DATE: bookingDate,
      TIME: timeSlot,
      DASHBOARD_URL: __dashboardUrl()
    };

    var __need = ['DASHBOARD_URL', 'Name'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx, k) && String(__ctx[k] || "").trim().length > 0) __vars[k] = String(__ctx[k]).trim();
      else __vars[k] = "—";
    }
    // claim-before-send (prevents duplicates under concurrent runners)
    if (guestEmail.length > 0 && __expiredGuestAlready == false) {
      let __claimed = false;
      try {
        const D = String.fromCharCode(36);
        const EXISTS = D + "exists";
        const SET = D + "set";
        const q = { _id: booking._id };
        q["comms.bookingExpiredGuestSentAt"] = {};
        q["comms.bookingExpiredGuestSentAt"][EXISTS] = false;
        const upd = {};
        upd[SET] = { "comms.bookingExpiredGuestSentAt": new Date() };
        const r = await Booking.updateOne(q, upd);
        __claimed = Boolean((r && (r.modifiedCount == 1)) || (r && (r.nModified == 1)));
      } catch (_) {}
      if (__claimed) {
        await sendEventEmail({
          eventName: "BOOKING_EXPIRED",
          category: "NOTIFICATIONS",
          to: guestEmail,
          vars: { DASHBOARD_URL: __vars["DASHBOARD_URL"], Name: __vars["Name"] }
        });
      }
    }

    const __ctx2 = Object.assign({}, __ctx);
    __ctx2.Name = (hostName.length > 0 ? hostName : "there");
    var __need = ['BOOKING_DATE', 'DASHBOARD_URL', 'EXPERIENCE_TITLE', 'GUEST_NAME', 'HOST_NAME', 'TIME_SLOT'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx2, k) && String(__ctx2[k] || "").trim().length > 0) __vars[k] = String(__ctx2[k]).trim();
      else __vars[k] = "—";
    }
    // claim-before-send (prevents duplicates under concurrent runners)
    if (hostEmail.length > 0 && __expiredHostAlready == false) {
      let __claimed2 = false;
      try {
        const D = String.fromCharCode(36);
        const EXISTS = D + "exists";
        const SET = D + "set";
        const q = { _id: booking._id };
        q["comms.bookingExpiredHostSentAt"] = {};
        q["comms.bookingExpiredHostSentAt"][EXISTS] = false;
        const upd = {};
        upd[SET] = { "comms.bookingExpiredHostSentAt": new Date() };
        const r = await Booking.updateOne(q, upd);
        __claimed2 = Boolean((r && (r.modifiedCount == 1)) || (r && (r.nModified == 1)));
      } catch (_) {}
      if (__claimed2) {
        await sendEventEmail({
          eventName: "BOOKING_EXPIRED_HOST",
          category: "NOTIFICATIONS",
          to: hostEmail,
          vars: { BOOKING_DATE: __vars["BOOKING_DATE"], DASHBOARD_URL: __vars["DASHBOARD_URL"], EXPERIENCE_TITLE: __vars["EXPERIENCE_TITLE"], GUEST_NAME: __vars["GUEST_NAME"], HOST_NAME: __vars["HOST_NAME"], TIME_SLOT: __vars["TIME_SLOT"] }
        });
      }
    }
  } catch (e) {
    console.error("COMMS_EXPIRED_ERR", (e && e.message) ? e.message : String(e));
  }
}

async function maybeSendRefundProcessedComms(booking) {
  try {
    if (!booking) return;
    try {
      if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
      const already = booking.comms.refundProcessedGuestSentAt ? new Date(booking.comms.refundProcessedGuestSentAt) : null;
      if (already) return;
    } catch (_) {}

    const b = booking || {};
    const guestEmail = String(b.guestEmail || "").trim();
    const guestName = String(b.guestName || "").trim();

    const hostId = String(b.hostId || "").trim();
    let hostDoc = null;
    if (hostId.length > 0) hostDoc = await User.findById(hostId);
    if ((hostDoc == null) && String(b.experienceId || "").trim().length > 0) {
      const expDoc = await Experience.findById(String(b.experienceId || "").trim());
      const expHostId = (expDoc && expDoc.hostId) ? String(expDoc.hostId).trim() : "";
      if (expHostId.length > 0) hostDoc = await User.findById(expHostId);
    }

    const hostEmail = String((hostDoc && hostDoc.email) || "").trim();
    const hostName = String((hostDoc && hostDoc.name) || "").trim();

    const expTitle = String(b.experienceTitle || b.title || "").trim();
    const bookingDate = String(b.bookingDate || "").trim();
    const timeSlot = String(b.timeSlot || "").trim();
    const guestNameSafe = (guestName.length > 0 ? guestName : "there");
    const hostNameSafe = (hostName.length > 0 ? hostName : "there");
    const __ctx = {
      Name: guestNameSafe,
      GUEST_NAME: guestNameSafe,
      HOST_NAME: hostNameSafe,
      EXPERIENCE_TITLE: expTitle,
      BOOKING_DATE: bookingDate,
      TIME_SLOT: timeSlot,
      DATE: bookingDate,
      TIME: timeSlot,
      AMOUNT: (function() {
        try {
          const cur = String((b && b.currency) || "aud").trim().toUpperCase() || "AUD";
          let cents = null;
          const cands = [
            (b && (b.refundAmountCents)),
            (b && (b.refundAmount)),
            (b && (b.amountRefunded)),
            (b && (b.amountCents)),
            (b && (b.amount)),
            (b && (b.totalAmount)),
            (b && (b.total)),
            (b && b.pricing && b.pricing.totalCents)
          ];
          for (const v of cands) {
            const n = Number(v);
            if (Number.isFinite(n) && n > 0) { cents = n; break; }
          }
          if (cents === null) return "";
          // If it looks like dollars (small number), treat as dollars; else treat as cents.
          const isDollars = cents > 0 && cents < 1000;
          const amt = isDollars ? Number(cents).toFixed(2) : (Number(cents) / 100).toFixed(2);
          return cur + " " + amt;
        } catch (_) {
          return "";
        }
      })(),
      DASHBOARD_URL: __dashboardUrl()
    };

    const __need = ['AMOUNT', 'DASHBOARD_URL', 'Name'];
    const __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx, k) && String(__ctx[k] || "").trim().length > 0) __vars[k] = String(__ctx[k]).trim();
      else __vars[k] = "—";
    }
    if (guestEmail.length > 0) {
      await sendEventEmail({
        eventName: "REFUND_PROCESSED",
        category: "PAYMENTS",
        to: guestEmail,
        vars: { AMOUNT: __vars["AMOUNT"], DASHBOARD_URL: __vars["DASHBOARD_URL"], Name: __vars["Name"] }
      });
      try {
        if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
        booking.comms.refundProcessedGuestSentAt = new Date();
        await booking.save();
      } catch (_) {}
    }

    void hostEmail;
    void hostName;
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    console.error("COMMS_REFUND_ERR", msg);
  }
}


async function maybeSendBookingCancelledByHostComms(booking) {
  try {
    if (!booking) return;
    if (booking.hostCancelledAt) return;

    const b = booking || {};
    const guestEmail = String(b.guestEmail || "").trim();
    const guestName = String(b.guestName || "").trim();

    const hostId = String(b.hostId || "").trim();
    let hostDoc = null;
    if (hostId.length > 0) hostDoc = await User.findById(hostId);
    if ((hostDoc == null) && String(b.experienceId || "").trim().length > 0) {
      const expDoc = await Experience.findById(String(b.experienceId || "").trim());
      const expHostId = (expDoc && expDoc.hostId) ? String(expDoc.hostId).trim() : "";
      if (expHostId.length > 0) hostDoc = await User.findById(expHostId);
    }

    const hostEmail = String((hostDoc && hostDoc.email) || "").trim();
    const hostName = String((hostDoc && hostDoc.name) || "").trim();

    const expTitle = String(b.experienceTitle || b.title || "").trim();
    const bookingDate = String(b.bookingDate || "").trim();
    const timeSlot = String(b.timeSlot || "").trim();
    const guestNameSafe = (guestName.length > 0 ? guestName : "there");
    const hostNameSafe = (hostName.length > 0 ? hostName : "there");
    const __ctx = {
      Name: guestNameSafe,
      GUEST_NAME: guestNameSafe,
      HOST_NAME: hostNameSafe,
      EXPERIENCE_TITLE: expTitle,
      BOOKING_DATE: bookingDate,
      TIME_SLOT: timeSlot,
      DATE: bookingDate,
      TIME: timeSlot,
      DASHBOARD_URL: __dashboardUrl()
    };

    var __need = ['DASHBOARD_URL', 'DATE', 'EXPERIENCE_TITLE', 'Name', 'TIME'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx, k) && String(__ctx[k] || "").trim().length > 0) __vars[k] = String(__ctx[k]).trim();
      else __vars[k] = "—";
    }
    if (guestEmail.length > 0) {
      await sendEventEmail({
        eventName: "BOOKING_CANCELLED_BY_HOST_GUEST",
        category: "NOTIFICATIONS",
        to: guestEmail,
        vars: { DASHBOARD_URL: __vars["DASHBOARD_URL"], DATE: __vars["DATE"], EXPERIENCE_TITLE: __vars["EXPERIENCE_TITLE"], Name: __vars["Name"], TIME: __vars["TIME"] }
      });
    }

    const __ctx2 = Object.assign({}, __ctx);
    __ctx2.Name = (hostName.length > 0 ? hostName : "there");
    var __need = ['DASHBOARD_URL', 'DATE', 'EXPERIENCE_TITLE', 'HOST_NAME', 'TIME'];
    var __vars = {};
    for (const k of __need) {
      if (Object.prototype.hasOwnProperty.call(__ctx2, k) && String(__ctx2[k] || "").trim().length > 0) __vars[k] = String(__ctx2[k]).trim();
      else __vars[k] = "—";
    }
    if (hostEmail.length > 0) {
      await sendEventEmail({
        eventName: "BOOKING_CANCELLED_BY_HOST_HOST",
        category: "NOTIFICATIONS",
        to: hostEmail,
        vars: { DASHBOARD_URL: __vars["DASHBOARD_URL"], DATE: __vars["DATE"], EXPERIENCE_TITLE: __vars["EXPERIENCE_TITLE"], HOST_NAME: __vars["HOST_NAME"], TIME: __vars["TIME"] }
      });
    }
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    console.error("COMMS_CANCEL_HOST_ERR", msg);
  }
}




const JWT_SECRET = String(process.env.JWT_SECRET || "");
function __passwordPolicyOk(pw) {
  const p = String(pw || "");
  if (p.length < 8) return { ok: false, reason: "Password must be at least 8 characters." };
  if (!/[a-z]/.test(p)) return { ok: false, reason: "Password must include a lowercase letter." };
  if (!/[A-Z]/.test(p)) return { ok: false, reason: "Password must include an uppercase letter." };
  if (!/[0-9]/.test(p)) return { ok: false, reason: "Password must include a number." };
  return { ok: true };
}


function signToken(user) {
  if (!JWT_SECRET) throw new Error("Missing JWT_SECRET");
  return jwt.sign({ userId: String(user._id), isAdmin: !!user.isAdmin, tv: Number(user.tokenVersion || 0) }, JWT_SECRET, {
    expiresIn: "30d",
  });
}

async function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Missing header" });

  const parts = String(authHeader).split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ message: "Invalid auth header" });
  }

  const token = parts[1];
  try {
    if (!JWT_SECRET) return res.status(500).json({ message: "Server missing JWT_SECRET" });
    const payload = jwt.verify(token, JWT_SECRET);
    const userId = String(payload.userId || "");
    if (!userId) return res.status(401).json({ message: "Invalid token" });

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ message: "User not found" });

    if (user.emailVerified !== true) {
      return res.status(403).json({ message: "Email not verified" });
    }

    const st = String(user.accountStatus || "active");
    if (st && st !== "active") {
      return res.status(403).json({ message: "Account not active" });
    }

    const tv = Number.isFinite(Number(user.tokenVersion)) ? Number(user.tokenVersion) : 0;
    const ptv = Number.isFinite(Number(payload.tv)) ? Number(payload.tv) : 0;
    if (ptv != tv) {
      return res.status(401).json({ message: "Session revoked" });
    }

    req.user = user;
    req.auth = { userId };
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid Token" });
  }
}


function adminSafeUser(u) {
  if (!u || typeof u !== "object") return u;
  const o = (typeof u.toObject === "function") ? u.toObject() : { ...u };

  // Always strip secrets / PII from admin surfaces unless explicitly required
  delete o.password;
  delete o.email;
  delete o.mobile;

  delete o.passwordResetTokenHash;
  delete o.passwordResetExpiresAt;
  delete o.passwordResetRequestedAt;

  delete o.notifications;
  delete o.payoutDetails;
  delete o.__v;

  return o;
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ message: "Access denied." });
    next();
  });
}


// --- AUTH SESSION CONTROL (REVOCATION) ---
app.post("/api/auth/logout", authMiddleware, async (req, res) => {
  try {
    const cur = Number.isFinite(Number(req.user.tokenVersion)) ? Number(req.user.tokenVersion) : 0;
    req.user.tokenVersion = cur + 1;
    await req.user.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/logout-all", authMiddleware, async (req, res) => {
  try {
    const cur = Number.isFinite(Number(req.user.tokenVersion)) ? Number(req.user.tokenVersion) : 0;
    req.user.tokenVersion = cur + 1;
    await req.user.save();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// --- POLICY ROUTES ---
app.get("/api/policy/active", async (req, res) => {
  try {
    const doc = await getActivePolicyDoc();
    if (!doc) return res.status(404).json({ message: "No active policy" });
    return res.json({ ok: true, policy: policySnapshotFromDoc(doc) });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/policy/draft", adminMiddleware, async (req, res) => {
  try {
    const body = req.body || {};
    const rules = (body.rules && typeof body.rules === "object") ? body.rules : {};
    const effectiveFrom = body.effectiveFrom ? new Date(body.effectiveFrom) : new Date();
    if (Number.isNaN(effectiveFrom.getTime())) return res.status(400).json({ message: "Invalid effectiveFrom" });

    const ver = new Date().toISOString();
    const doc = await Policy.create({
      version: ver,
      status: "draft",
      active: false,
      effectiveFrom,
      publishedAt: null,
      rules: {
        currency: String(rules.currency || "aud").toLowerCase(),
        guestMaxRefundPercent: Number.isFinite(rules.guestMaxRefundPercent) ? Number(rules.guestMaxRefundPercent) : 0.95,
        hostRefundPercent: Number.isFinite(rules.hostRefundPercent) ? Number(rules.hostRefundPercent) : 1.0,
        guestFreeCancelHours: Number.isFinite(rules.guestFreeCancelHours) ? Number(rules.guestFreeCancelHours) : 0,
        absoluteMaxGuestRefundPercent: Number.isFinite(rules.absoluteMaxGuestRefundPercent) ? Number(rules.absoluteMaxGuestRefundPercent) : 0.95,
      },
    });

    const snap = policySnapshotFromDoc(doc.toObject ? doc.toObject() : doc);
    return res.json({ ok: true, draft: snap, draftId: String(doc._id) });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/policy/publish", adminMiddleware, async (req, res) => {
  try {
    const draftId = String((req.body && req.body.draftId) || "").trim();
    if (!draftId) return res.status(400).json({ message: "draftId required" });

    const draft = await Policy.findById(draftId);
    if (!draft) return res.status(404).json({ message: "Draft not found" });
    if (String(draft.status || "") !== "draft") return res.status(400).json({ message: "Not a draft" });

    const now = new Date();

    // Publish is allowed even for future-effective policies, but MUST NOT create an active-policy gap.
    draft.status = "published";
    draft.publishedAt = now;

    const eff = draft.effectiveFrom ? new Date(draft.effectiveFrom) : null;
    const effOk = (eff && !Number.isNaN(eff.getTime()));
    const shouldActivate = Boolean(effOk && (eff.getTime() <= now.getTime()));

    if (shouldActivate) {
      await Policy.updateMany({ active: true }, { $set: { active: false } });
      draft.active = true;
    } else {
      draft.active = false;
    }

    await draft.save();

    const activeDoc = shouldActivate ? (draft.toObject ? draft.toObject() : draft) : await getActivePolicyDoc();

    return res.json({ ok: true, active: policySnapshotFromDoc(activeDoc) });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Determine if a user has any experiences (host profile allowed)
async function isHost(userId) {
  const count = await Experience.countDocuments({ hostId: String(userId) });
  return count > 0;
}

// Auth-safe user (for /me) — still includes email/mobile (PRIVATE)
function sanitizeUser(u) {
  const obj = (u && typeof u.toObject === "function") ? u.toObject({ virtuals: true }) : (u || {});
  const role = String(obj.role || "");
  const roleIsHost = role.toLowerCase() === "host";

  // SELF DTO ONLY (PRIVATE): allowlist fields; DO NOT leak internal/security fields
  return {
    _id: obj._id,
    id: obj.id || (obj._id ? String(obj._id) : ""),

    name: String(obj.name || ""),
    email: String(obj.email || ""),     // PRIVATE (self only)
    mobile: String(obj.mobile || ""),   // PRIVATE (self only)

    role,
    isHost: roleIsHost,
    isPremiumHost: !!obj.isPremiumHost,
    vacationMode: !!obj.vacationMode,

    profilePic: String(obj.profilePic || ""),
    bio: String(obj.bio || ""),
    location: String(obj.location || ""),

    handle: String(obj.handle || ""),
    allowHandleSearch: !!obj.allowHandleSearch,
    showExperiencesToFriends: !!obj.showExperiencesToFriends,
    publicProfile: !!obj.publicProfile,

    preferences: Array.isArray(obj.preferences) ? obj.preferences : [],
    termsAgreedAt: (typeof obj.termsAgreedAt === "undefined" ? null : obj.termsAgreedAt),
    termsVersion: String(obj.termsVersion || ""),

    guestRating: Number.isFinite(Number(obj.guestRating)) ? Number(obj.guestRating) : 0,
    guestReviewCount: Number.isFinite(Number(obj.guestReviewCount)) ? Number(obj.guestReviewCount) : 0,
  };
}


// Public-safe card (NO email/mobile)
function publicUserCardFromDoc(u) {
  if (!u) return null;
  return {
    _id: u._id,
    name: String(u.name || ""),
    profilePic: String(u.profilePic || ""),
    bio: u.publicProfile ? String(u.bio || "") : "",
    handle: String(u.handle || ""),
    publicProfile: !!u.publicProfile,
  };
}

function normalizeHandle(h) {
  return String(h || "").trim().toLowerCase();
}

async function minimalUserCard(userId) {
  const u = await User.findById(userId).select("name profilePic bio handle publicProfile");
  return publicUserCardFromDoc(u);
}

async function viewerCanSeeAttendees(expId, viewerId) {
  const exp = await Experience.findById(expId);
  if (!exp) return { ok: false, reason: "Experience not found" };

  const isHostViewer = String(exp.hostId) === String(viewerId);
  if (isHostViewer) return { ok: true, exp, role: "host" };

  const attendee = await Booking.findOne({
    experienceId: String(exp._id),
    guestId: viewerId,
    $or: [{ status: "confirmed" }, { paymentStatus: "paid" }],
  });

  if (attendee) return { ok: true, exp, role: "attendee" };
  return { ok: false, reason: "Not allowed" };
}

async function computeConnectionStatuses(meId, otherIds) {
  const me = String(meId);
  if (!otherIds || otherIds.length === 0) return new Map();

  const conns = await Connection.find({
    status: { $in: ["pending", "accepted", "blocked"] },
    $or: [
      { requesterId: meId, addresseeId: { $in: otherIds } },
      { addresseeId: meId, requesterId: { $in: otherIds } },
    ],
  }).select("requesterId addresseeId status");

  const m = new Map();
  for (const oid of otherIds.map(String)) m.set(oid, "none");

  for (const c of conns) {
    const reqId = String(c.requesterId);
    const addId = String(c.addresseeId);
    const status = String(c.status);

    const other = reqId === me ? addId : reqId;
    if (!m.has(other)) continue;

    if (status === "accepted") m.set(other, "friends");
    else if (status === "blocked") m.set(other, "blocked");
    else if (status === "pending") m.set(other, reqId === me ? "pending_outgoing" : "pending_incoming");
  }
  return m;
}



async function reserveCapacitySlot(experienceId, dateStr, timeSlot, guests) {
  const expId = String(experienceId || "").trim();
  const d = String(dateStr || "").trim();
  const slot = String(timeSlot || "").trim();
  const g = Number.parseInt(String(guests || "0"), 10) || 0;

  const ok = Boolean(expId.length > 0 && d.length > 0 && slot.length > 0 && g > 0);
  if (ok == false) return { ok: false, message: "Invalid capacity reservation request." };

  const exp = await Experience.findById(expId).lean();
  if (exp == null) return { ok: false, message: "Experience not found." };

  const maxGuests = Number(exp.maxGuests) || 0;
  if (maxGuests <= 0) return { ok: true, maxGuests: 0 };


  // HARD GUARD: cannot reserve more guests than maxGuests
  if (g > maxGuests) {
    return { ok: false, remaining: maxGuests, message: "Only " + String(maxGuests) + " spots left." };
  }

  const limit = maxGuests - g;

  const OR = String.fromCharCode(36) + "or";
  const EXISTS = String.fromCharCode(36) + "exists";
  const LTE = String.fromCharCode(36) + "lte";
  const INC = String.fromCharCode(36) + "inc";
  const SET = String.fromCharCode(36) + "set";
  const SET_ON_INSERT = String.fromCharCode(36) + "setOnInsert";

  const q = { experienceId: String(expId), bookingDate: d, timeSlot: slot };
  q[OR] = [
    { reservedGuests: (function(){ const x={}; x[EXISTS]=false; return x; })() },
    { reservedGuests: (function(){ const x={}; x[LTE]=limit; return x; })() }
  ];

  const upd = {};
  upd[INC] = { reservedGuests: g };
  upd[SET] = { updatedAt: new Date() };
  upd[SET_ON_INSERT] = { maxGuests: maxGuests, createdAt: new Date() };

  let r;
  try {
    r = await CapacitySlot.updateOne(q, upd, { upsert: true });
  } catch (err) {
    const code = (err && (err.code || err.errorCode)) || 0;
    const msg = String(err && err.message ? err.message : "");
    if (code === 11000 || code === 11001 || msg.indexOf("E11000") >= 0) {
      // Another request upserted the same slot key concurrently. Retry once without upsert.
      r = await CapacitySlot.updateOne(q, upd, { upsert: false });
    } else {
      throw err;
    }
  }

  const matched = Number(r && r.matchedCount) || 0;
  const upserted = Number(r && r.upsertedCount) || 0;
  const did = Boolean(matched > 0 || upserted > 0);

  if (did) return { ok: true, maxGuests: maxGuests };

  const cur = await CapacitySlot.findOne({ experienceId: String(expId), bookingDate: d, timeSlot: slot }).lean();
  const curReserved = cur && (typeof cur.reservedGuests === "number") ? Number(cur.reservedGuests) : 0;
  const remaining = maxGuests - curReserved;
  return { ok: false, remaining: remaining, message: remaining > 0 ? ("Only " + String(remaining) + " spots left.") : "Fully booked." };
}

async function releaseCapacitySlot(experienceId, dateStr, timeSlot, guests) {
  const expId = String(experienceId || "").trim();
  const d = String(dateStr || "").trim();
  const slot = String(timeSlot || "").trim();
  const g = Number.parseInt(String(guests || "0"), 10) || 0;

  const ok = Boolean(expId.length > 0 && d.length > 0 && slot.length > 0 && g > 0);
  if (ok == false) return;

  const OR = String.fromCharCode(36) + "or";
  const EXISTS = String.fromCharCode(36) + "exists";
  const GTE = String.fromCharCode(36) + "gte";
  const INC = String.fromCharCode(36) + "inc";
  const SET = String.fromCharCode(36) + "set";
  const LT  = String.fromCharCode(36) + "lt";

  const q = { experienceId: String(expId), bookingDate: d, timeSlot: slot };
  q[OR] = [
    { reservedGuests: (function(){ const x={}; x[EXISTS]=true; x[GTE]=g; return x; })() },
    { reservedGuests: (function(){ const x={}; x[EXISTS]=true; return x; })() }
  ];

  const upd = {};
  upd[INC] = { reservedGuests: (0 - g) };
  upd[SET] = { updatedAt: new Date() };

  await CapacitySlot.updateOne(q, upd);

  const q2 = { experienceId: String(expId), bookingDate: d, timeSlot: slot, reservedGuests: (function(){ const x={}; x[LT]=0; return x; })() };
  const upd2 = {};
  upd2[SET] = { reservedGuests: 0, updatedAt: new Date() };
  await CapacitySlot.updateOne(q2, upd2);
}

async function checkCapacity(experienceId, date, timeSlot, newGuests) {
  const dateStr = String(date || "").trim();
  const slot = String(timeSlot || "").trim();

  const isoOk = /^\d{4}-\d{2}-\d{2}$/.test(dateStr);
  if (!isoOk) return { available: false, message: "Invalid bookingDate (YYYY-MM-DD required)." };
  if (!slot) return { available: false, message: "timeSlot is required." };

  const exp = await Experience.findById(experienceId);
  if (!exp) return { available: false, message: "Experience not found." };

  if (exp.isPaused) return { available: false, message: "Host is paused." };
  if (exp.blockedDates && exp.blockedDates.includes(dateStr)) return { available: false, message: "Date blocked." };

  if (Array.isArray(exp.timeSlots) && exp.timeSlots.length > 0 && !exp.timeSlots.includes(slot)) {
    return { available: false, message: "Invalid time slot." };
  }

  const d = new Date(dateStr + "T00:00:00Z");
  if (Number.isNaN(d.getTime())) return { available: false, message: "Invalid bookingDate." };
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const searchDay = days[d.getUTCDay()];

  if (Array.isArray(exp.availableDays) && exp.availableDays.length > 0 && !exp.availableDays.includes(searchDay)) {
    return { available: false, message: `Closed on ${searchDay}.` };
  }

  const startOk = !exp.startDate || String(exp.startDate) <= dateStr;
  const endOk = !exp.endDate || String(exp.endDate) >= dateStr;
  if (!startOk || !endOk) return { available: false, message: "Date outside experience availability." };

  const existing = await Booking.find({
    experienceId: String(exp._id),
    bookingDate: dateStr,
    timeSlot: slot,
    $or: [{ status: "confirmed" }, { paymentStatus: "paid" }],
  });

  const currentCount = existing.reduce((sum, b) => sum + (Number(b.numGuests) || 0), 0);
  const incoming = Number(newGuests) || 1;

  if ((Number(exp.maxGuests) || 0) > 0 && currentCount + incoming > Number(exp.maxGuests)) {
    const remaining = Number(exp.maxGuests) - currentCount;
    return { available: false, remaining, message: `Only ${remaining} spots left.` };
  }

  return { available: true };
}

// --- ROUTES ---

// Upload
function __uploadLimits() {
  return { maxFiles: 3, maxFileSizeMB: 6, formats: ["jpg", "jpeg", "png"] };
}

function __uploadReject(res, httpCode, code, message, detail) {
  return res.status(Number(httpCode)).json({
    code: String(code || "UPLOAD_REJECTED"),
    message: String(message || "We could not upload that file."),
    detail: String(detail || "Please try again."),
    limits: __uploadLimits()
  });
}

function __uploadMulterWrap(req, res, next) {
  upload.array("photos", 3)(req, res, (err) => {
    if (err) {
      const msg = String((err && err.message) ? err.message : "upload_error");
      const isMulter = Boolean(err && (err.name == "MulterError"));
      const ecode = String((err && err.code) ? err.code : "");
      const isTooLarge = Boolean(isMulter && (ecode == "LIMIT_FILE_SIZE"));
      const isTooMany = Boolean(isMulter && (ecode == "LIMIT_FILE_COUNT"));
      const isBadType = Boolean(msg == "invalid_file_type");
      if (isTooLarge) {
        return __uploadReject(res, 413, "UPLOAD_FILE_TOO_LARGE", "This photo is larger than allowed.", "Max 6MB per photo. Please compress to 6MB or less (recommended: 5MB). If exporting, set longest side to 1920px or less and JPEG quality around 80%, then try again.");
      }
      if (isTooMany) {
        return __uploadReject(res, 400, "UPLOAD_TOO_MANY_FILES", "You can upload up to 3 photos per upload.", "Please remove extra photos and upload in batches of 3 or fewer.");
      }
      if (isBadType) {
        return __uploadReject(res, 400, "UPLOAD_UNSUPPORTED_FORMAT", "Unsupported image format.", "Allowed: JPG/JPEG/PNG. Please convert your image to JPG or PNG and try again.");
      }
      return __uploadReject(res, 400, "UPLOAD_REJECTED", "Upload could not be processed.", "Please try again.");
    }
    return next();
  });
}

app.post("/api/upload", authMiddleware, __uploadMulterWrap, async (req, res) => {
  try {
    const files = Array.isArray(req.files) ? req.files : [];
    if (files.length === 0) {
      return __uploadReject(res, 400, "UPLOAD_NO_FILES", "No photos received.", "Attach up to 3 JPG/PNG photos (max 6MB each) and try again.");
    }
    const out = [];
    for (const f of files) {
      const buf = (f && f.buffer) ? f.buffer : null;
      if (buf == null) {
        return __uploadReject(res, 400, "UPLOAD_INVALID_FILE", "We could not read that photo.", "Please choose a different JPG/PNG photo (max 6MB) and try again.");
      }
      const r = await __uploadBufferToCloudinary(buf, (f && f.originalname) ? String(f.originalname) : "");
      const url = (r && r.secure_url) ? String(r.secure_url) : "";
      if (url.length > 0) out.push(url);
    }
    __log("info", "upload_ok", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
    return res.json({ images: out });
  } catch (e) {
    __log("error", "upload_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
    return __uploadReject(res, 500, "UPLOAD_FAILED", "Upload failed.", "Please try again. If it keeps failing, try 1 photo first, then add more (up to 3).");
  }
});


// Auth: Register
app.post("/api/auth/register", registerLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    if (typeof body.handle !== "undefined") body.handle = String(body.handle || "").trim().toLowerCase();
    if (typeof body.email !== "undefined") body.email = String(body.email).toLowerCase().trim();



    const __isPlainObject = (v) => {
      if (!v || typeof v !== "object") return false;
      const proto = Object.getPrototypeOf(v);
      return proto === Object.prototype || proto === null;
    };

    if (!__isPlainObject(body)) return res.status(400).json({ message: "Invalid payload" });
    const protoKeys = ["__proto__", "constructor", "prototype"]; 
    for (const k of Object.keys(body)) {
      if (protoKeys.includes(String(k))) return res.status(400).json({ message: "Invalid payload" });
    }

    const allowedFields = ["name", "email", "handle", "mobile", "profilePic"]; 
    const clean = {};
    for (const k of allowedFields) {
      if (Object.prototype.hasOwnProperty.call(body, k) && typeof body[k] !== "undefined") clean[k] = body[k];
    }
    if (typeof clean.handle !== "undefined") clean.handle = String(clean.handle || "").trim().toLowerCase();
    if (typeof clean.email !== "undefined") clean.email = String(clean.email).toLowerCase().trim();
    const emailNorm = String(body.email || "").toLowerCase().trim();
    const pwRaw = (typeof body.password === "undefined") ? "" : String(body.password || "");
    const pwConf = (typeof body.confirmPassword === "undefined") ? "" : String(body.confirmPassword || "");
    if (!emailNorm || !pwRaw || !pwConf) return res.status(400).json({ message: "Email, password and confirmPassword required" });
    if (pwRaw !== pwConf) return res.status(400).json({ message: "Passwords do not match", code: "password_confirm_register" });
    const __pp = __passwordPolicyOk(pwRaw);
    if (!__pp.ok) return res.status(400).json({ message: __pp.reason, code: "password_policy_register" });
    if (await User.findOne({ email: emailNorm })) return res.status(400).json({ message: "Taken" });

    const hashedPassword = await bcrypt.hash(String(pwRaw), 10);
    clean.email = emailNorm;

    const user = new User({
      ...clean,
      password: hashedPassword,
      role: "Guest",
      notifications: [{ message: "Welcome", type: "success" }],
      termsAgreedAt: new Date(),
      termsVersion: "1.0",
    });

    // Email verification (required before welcome/login)
    const vtoken = crypto.randomBytes(32).toString("hex");
    const vhash = crypto.createHash("sha256").update(vtoken).digest("hex");
    user.emailVerified = false;
    user.emailVerificationTokenHash = vhash;
    user.emailVerificationRequestedAt = new Date();
    user.emailVerificationExpiresAt = new Date(Date.now() + 30 * 60 * 1000);

    await user.save();

    let __verifyUrl = "";

    let __emailVerificationEmail = "";
    // Send verification email via templates (non-blocking)
    try {
      const __apiBase = (() => {
        try {
          const env1 = (process && process.env && (process.env.BACKEND_BASE_URL || process.env.BASE_URL)) ? String(process.env.BACKEND_BASE_URL || process.env.BASE_URL) : "";
          const envBase = env1.replace(/\/$/, "");
          if (envBase) return envBase;
          const proto = (req && (req.headers && (req.headers["x-forwarded-proto"] || req.headers["X-Forwarded-Proto"]))) ? String(req.headers["x-forwarded-proto"] || req.headers["X-Forwarded-Proto"]) : "";
          const p2 = proto ? proto.split(",")[0].trim() : "";
          const scheme = p2 || (req && req.protocol ? String(req.protocol) : "https");
          const host = (req && req.get) ? String(req.get("host") || "") : "";
          if (!host) return "";
          return scheme + "://" + host;
        } catch (_) { return ""; }
      })();
      const verifyUrlBackend = (__apiBase || "") + "/api/auth/verify-email?email=" + encodeURIComponent(String(user.email || "")) + "&token=" + encodeURIComponent(String(vtoken || ""));
      const verifyUrlFrontend = __frontendBaseUrl() + "/verify-email?email=" + encodeURIComponent(String(user.email || "")) + "&token=" + encodeURIComponent(String(vtoken || ""));
      __verifyUrl = String(verifyUrlFrontend || "");

      const __need = ["Name", "VERIFY_EMAIL_URL"];
      const __p = __sendEventEmailTracked({
        eventName: "EMAIL_VERIFICATION",
        category: "SECURITY",
        to: String(user.email || ""),
        vars: { Name: String(user.name || "there"), VERIFY_EMAIL_URL: String(verifyUrlFrontend || "") }
      }, { rid: __ridFromReq(req), source: "auth_register" });
      const __t = new Promise((_, rej) => setTimeout(() => rej(new Error("email_timeout")), 6000));

      const __vdbgSecretPre = String(process.env.VERIFY_DEBUG_SECRET || "").trim();
      const __vdbgHeaderPre = String((req.headers && (req.headers["x-verify-debug-secret"] || req.headers["X-Verify-Debug-Secret"])) || "").trim();
      const __wantDbg = (__vdbgSecretPre.length >= 24 && !!__vdbgHeaderPre);

      if (__wantDbg) {
        try {
          await Promise.race([__p, __t]);
          __emailVerificationEmail = "EMAIL_SEND_OK";
        } catch (_) {
          __emailVerificationEmail = "EMAIL_SEND_FAIL";
        }
      } else {
        Promise.race([__p, __t]).catch(() => {});
      }
    } catch (_) {}

    const __resp = { success: true, token: signToken(user), user: sanitizeUser(user) };

    const __vdbgSecret = String(process.env.VERIFY_DEBUG_SECRET || "").trim();
    const __vdbgHeader = String((req.headers && (req.headers["x-verify-debug-secret"] || req.headers["X-Verify-Debug-Secret"])) || "").trim();

    if (__vdbgSecret.length >= 24 && __vdbgHeader) {
      const a = __vdbgSecret;
      const b = __vdbgHeader;
      const n = (a.length > b.length) ? a.length : b.length;
      let acc = 0;
      for (let idx = 0; idx < n; idx++) {
        const ca = (idx < a.length) ? a.charCodeAt(idx) : 0;
        const cb = (idx < b.length) ? b.charCodeAt(idx) : 0;
        acc = acc | (ca ^ cb);
      }
      if (acc === 0 && __verifyUrl) {
        __resp.dev = { verifyUrl: String(__verifyUrl), emailVerificationEmail: String(__emailVerificationEmail || "") };
      }
    }

    return res.status(201).json(__resp);
  } catch (e) {
    __log("error", "auth_register_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    res.status(500).json({ message: "Error" });
  }
});

// Auth: Login

// Auth: Verify Email
app.get("/api/auth/verify-email", async (req, res) => {
  try {
    const emailRaw = (req.query && req.query.email) ? String(req.query.email) : "";
    const tokenRaw = (req.query && req.query.token) ? String(req.query.token) : "";
    const email = emailRaw.toLowerCase().trim();
    const token = tokenRaw.trim();
    if (!email || !token) return res.status(400).json({ message: "Invalid or expired token" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid or expired token" });
    const exp = user.emailVerificationExpiresAt;
    if (!user.emailVerificationTokenHash || !exp || Date.now() > new Date(exp).getTime()) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }
    const th = crypto.createHash("sha256").update(token).digest("hex");
    const __stored = String(user.emailVerificationTokenHash || "");
    const __th = String(th || "");
    const __tok = String(token || "");
    const __ok = (!!__stored && !!__th && (__th === __stored));
    if (!__ok) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    user.emailVerified = true;
    user.tokenVersion = Number(user.tokenVersion || 0) + 1;

    user.emailVerificationTokenHash = "";
    user.emailVerificationRequestedAt = null;
    user.emailVerificationExpiresAt = null;
    await user.save();

    let __welcomeEmail = "";
    try {
      const __need = ["Name", "DASHBOARD_URL"];
      const __p = __sendEventEmailTracked({
        eventName: "WELCOME_POST_VERIFICATION",
        category: "NOTIFICATIONS",
        to: String(user.email || ""),
        vars: { Name: String(user.name || "there"), DASHBOARD_URL: __dashboardUrl() }
      }, { rid: __ridFromReq(req), source: "auth_verify_email" });
      const __t = new Promise((_, rej) => setTimeout(() => rej(new Error("email_timeout")), 6000));

      const __vdbgSecret = String(process.env.VERIFY_DEBUG_SECRET || "").trim();
      const __vdbgHeader = String((req.headers && (req.headers["x-verify-debug-secret"] || req.headers["X-Verify-Debug-Secret"])) || "").trim();
      let __dbgOk = false;
      if (__vdbgSecret.length >= 24 && __vdbgHeader) {
        const a = __vdbgSecret;
        const b = __vdbgHeader;
        const n = (a.length > b.length) ? a.length : b.length;
        let acc = 0;
        for (let idx = 0; idx < n; idx++) {
          const ca = (idx < a.length) ? a.charCodeAt(idx) : 0;
          const cb = (idx < b.length) ? b.charCodeAt(idx) : 0;
          acc = acc | (ca ^ cb);
        }
        __dbgOk = (acc === 0);
      }

      if (__dbgOk) {
        try {
          await Promise.race([__p, __t]);
          __welcomeEmail = "EMAIL_SEND_OK";
        } catch (_) {
          __welcomeEmail = "EMAIL_SEND_FAIL";
        }
      } else {
        Promise.race([__p, __t]).catch(() => {});
      }

      if (__dbgOk) {
        return res.json({ ok: true, dev: { welcomeEmail: String(__welcomeEmail || "") } });
      }
    } catch (_) {}

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
      if (user.emailVerified !== true) {
        return res.status(403).json({ message: "Email not verified" });

      const st = String(user.accountStatus || "active");
      if (st && st !== "active") {
        return res.status(403).json({ message: "Account not active" });
      }
      }

    if (user && user.emailVerified !== true) {
      return res.status(403).json({ message: "Please verify your email.", code: "email_not_verified" });
    }

    const ok = await bcrypt.compare(String(password), String(user.password || ""));
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    return res.json({ token: signToken(user), user: sanitizeUser(user) });
  } catch (e) {
    __log("error", "auth_login_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    return res.status(500).json({ message: "Login failed" });
  }
});

// Auth: Current user

// Auth: Forgot Password (privacy-safe)
app.post("/api/auth/forgot-password", forgotPasswordLimiter, async (req, res) => {
  try {
    const emailRaw = (req.body && req.body.email) ? String(req.body.email) : "";
    const email = emailRaw.toLowerCase().trim();

    // Always respond OK (do not leak account existence)
    if (!email) return res.json({ ok: true, message: "If an account exists, you will receive instructions." });

    const user = await User.findOne({ email });
    if (user) {
      const token = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

      user.passwordResetTokenHash = tokenHash;
      user.passwordResetRequestedAt = new Date();
      user.passwordResetExpiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 min
      await user.save();

      // Email is optional (backend-ready even before official email is configured)
      const canEmail = !!process.env.SMTP_HOST && !!process.env.SMTP_USER && !!process.env.SMTP_PASS;
      const frontendBase = String(process.env.FRONTEND_BASE_URL || "http://localhost:3000").replace(/\/$/, "");
      const resetUrl = `${frontendBase}/reset-password?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
      if (canEmail) {
        // Do not block the HTTP response on email delivery (email can hang on misconfig)
        try {
          const __need = ["Name", "RESET_PASSWORD_URL"];
          const __p = sendEventEmail({
            eventName: "PASSWORD_RESET_REQUEST",
            category: "SECURITY",
            to: email,
            vars: {
              Name: String((user && user.name) || "there"),
              RESET_PASSWORD_URL: String(resetUrl || "")
            }
          });
          const __t = new Promise((_, rej) => setTimeout(() => rej(new Error("email_timeout")), 6000));
          Promise.race([__p, __t]).catch(() => {});
        } catch (e) {
        }
      }

      // DEV-only escape hatch (no official email yet)
      // Controlled debug escape hatch (operators only)
      // Enable by setting RESET_DEBUG_SECRET (>=24 chars) and sending header X-Reset-Debug-Secret
      // Normal clients never receive tokens/links.
      const __dbgSecret = String(process.env.RESET_DEBUG_SECRET || "").trim();
      const __dbgHeader = String((req.headers && (req.headers["x-reset-debug-secret"] || req.headers["X-Reset-Debug-Secret"])) || "").trim();
      if (__dbgSecret.length >= 24 && __dbgHeader) {
        const a = __dbgSecret;
        const b = __dbgHeader;
        const n = (a.length > b.length) ? a.length : b.length;
        let acc = 0;
        for (let idx = 0; idx < n; idx++) {
          const ca = (idx < a.length) ? a.charCodeAt(idx) : 0;
          const cb = (idx < b.length) ? b.charCodeAt(idx) : 0;
          acc = acc | (ca ^ cb);
        }
        if (a.length === b.length && acc === 0) {
          return res.json({ ok: true, message: "If an account exists, you will receive instructions.", dev: { resetUrl } });
        }
      }
    }

      // Operator diagnostics (non-sensitive): only emitted if X-Reset-Debug-Secret header is present
      // Helps verify Render env + header wiring without leaking secrets.
      try {
        const __hdrPresent = !!(req.headers && (req.headers["x-reset-debug-secret"] || req.headers["X-Reset-Debug-Secret"]));
        if (__hdrPresent) {
          const __s0 = String(process.env.RESET_DEBUG_SECRET || "").trim();
          const __h0 = String((req.headers && (req.headers["x-reset-debug-secret"] || req.headers["X-Reset-Debug-Secret"])) || "").trim();
          const __minLenOk = (__s0.length >= 24);
          const a = __s0;
          const b = __h0;
          const n = (a.length > b.length) ? a.length : b.length;
          let acc = 0;
          for (let idx = 0; idx < n; idx++) {
            const ca = (idx < a.length) ? a.charCodeAt(idx) : 0;
            const cb = (idx < b.length) ? b.charCodeAt(idx) : 0;
            acc = acc | (ca ^ cb);
          }
          const __match = (a.length === b.length && acc === 0);
          return res.json({ ok: true, message: "If an account exists, you will receive instructions.", dbg: { hdrPresent: true, envPresent: (__s0.length > 0), minLenOk: __minLenOk, match: __match } });
        }
      } catch (e) {}

    return res.json({ ok: true, message: "If an account exists, you will receive instructions." });
  } catch (e) {
    return res.json({ ok: true, message: "If an account exists, you will receive instructions." });
  }
});

// Auth: Reset Password
app.post("/api/auth/reset-password", resetPasswordLimiter, async (req, res) => {
  try {
    const emailRaw = (req.body && req.body.email) ? String(req.body.email) : "";
    const tokenRaw = (req.body && req.body.token) ? String(req.body.token) : "";
    const newPasswordRaw = (req.body && req.body.newPassword) ? String(req.body.newPassword) : "";

    const email = emailRaw.toLowerCase().trim();
    const token = tokenRaw.trim();

    if (!email || !token || !newPasswordRaw) return res.status(400).json({ message: "Missing fields" });
    if (newPasswordRaw.length < 8) return res.status(400).json({ message: "Password too short" });
    const confRaw = String(((req.body && (typeof req.body.confirmPassword !== "undefined" ? req.body.confirmPassword : req.body.confirmNewPassword)) ) || "");
    if (!confRaw) return res.status(400).json({ message: "confirmPassword required" });
    if (String(newPasswordRaw) != String(confRaw)) return res.status(400).json({ message: "Passwords do not match", code: "password_confirm_reset" });
    const __pp2 = __passwordPolicyOk(newPasswordRaw);
    if (!__pp2.ok) return res.status(400).json({ message: __pp2.reason, code: "password_policy_reset" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    const exp = user.passwordResetExpiresAt;
    if (!user.passwordResetTokenHash || !exp || Date.now() > new Date(exp).getTime()) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    if (String(tokenHash) !== String(user.passwordResetTokenHash)) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    user.password = await bcrypt.hash(newPasswordRaw, 10);
    user.passwordResetTokenHash = "";
    user.passwordResetExpiresAt = null;
    user.passwordResetRequestedAt = null;
    await user.save();

    // Comms: password changed confirmation
    try {
      const __to = (user && user.email) ? String(user.email).trim() : "";
      const __nm = (user && user.name) ? String(user.name).trim() : "";
      if (__to) {
        sendEventEmail({
          to: __to,
          eventName: "PASSWORD_CHANGED_CONFIRMATION",
          category: "SECURITY",
          vars: {
            DASHBOARD_URL: __dashboardUrl(),
            Name: __nm
          }
        });
      }
    } catch (_) {}

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    return res.json({ user: sanitizeUser(req.user) });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Auth: Update profile (allowlist)
app.put("/api/auth/update", authMiddleware, async (req, res) => {
  try {
    const body = req.body || {};
    if (__isPlainObject(body) === false) return res.status(400).json({ message: "Invalid payload" });
    const allowed = [
      "name",
      "bio",
      "location",
      "mobile",
      "profilePic",
      "preferences",
      "handle",
      "allowHandleSearch",
      "showExperiencesToFriends",
      "publicProfile",
    ];

    const updates = {};
    for (const k of allowed) if (Object.prototype.hasOwnProperty.call(body, k)) updates[k] = body[k];

    const __toBool = (v) => {
      if (typeof v === "boolean") return v;
      const x = String(v || "").toLowerCase().trim();
      if (x === "true" || x === "1" || x === "yes" || x === "y") return true;
      if (x === "false" || x === "0" || x === "no" || x === "n") return false;
      return !!v;
    };

    const __toStrSafe = (v) => {
      if (typeof v === "string") return v.trim();
      if (typeof v === "number" || typeof v === "boolean") return String(v).trim();
      return "";
    };

    const __scrubMongoKeys = (val, depth) => {
      const d = typeof depth === "number" ? depth : 0;
      if (d > 6) return null;
      if (val === null || typeof val === "undefined") return val;
      if (typeof val !== "object") return val;
      if (Array.isArray(val)) return val.map((x) => __scrubMongoKeys(x, d + 1));
      if (__isPlainObject(val) === false) return null;
      const out = {};
      for (const k of Object.keys(val)) {
        if (!k) continue;
        if (k[0] === "$") continue;
        if (k.indexOf(".") !== -1) continue;
        if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
        out[k] = __scrubMongoKeys(val[k], d + 1);
      }
      return out;
    };

    if (typeof updates.name !== "undefined") updates.name = __toStrSafe(updates.name);
    if (typeof updates.bio !== "undefined") updates.bio = __toStrSafe(updates.bio);
    if (typeof updates.location !== "undefined") updates.location = __toStrSafe(updates.location);
    if (typeof updates.mobile !== "undefined") updates.mobile = __toStrSafe(updates.mobile);
    if (typeof updates.profilePic !== "undefined") updates.profilePic = __toStrSafe(updates.profilePic);

    if (typeof updates.allowHandleSearch !== "undefined") updates.allowHandleSearch = __toBool(updates.allowHandleSearch);
    if (typeof updates.showExperiencesToFriends !== "undefined") updates.showExperiencesToFriends = __toBool(updates.showExperiencesToFriends);
    if (typeof updates.publicProfile !== "undefined") updates.publicProfile = __toBool(updates.publicProfile);


    if (typeof updates.dynamicDiscounts !== "undefined") {
      updates.dynamicDiscounts = __scrubMongoKeys(updates.dynamicDiscounts, 0);
      if (__isPlainObject(updates.dynamicDiscounts) === false) delete updates.dynamicDiscounts;
    }
    if (typeof updates.preferences !== "undefined") {
      updates.preferences = __scrubMongoKeys(updates.preferences, 0);
      if (__isPlainObject(updates.preferences) === false) delete updates.preferences;
    }

    if (typeof updates.handle !== "undefined") {
      updates.handle = normalizeHandle(updates.handle);
      if (!updates.handle) delete updates.handle;
    }

    // never allow privilege changes
    delete updates.isAdmin;
    delete updates.role;
    delete updates.isPremiumHost;
    delete updates.vacationMode;
    delete updates.payoutDetails;
    delete updates.email;
    delete updates.password;

    const user = await User.findByIdAndUpdate(req.user._id, { $set: updates }, { new: true });
    return res.json({ user: sanitizeUser(user) });
  } catch (e) {
    __log("error", "auth_update_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    return res.status(500).json({ message: "Update failed" });
  }
});

// Experiences: Create (category sanitize)
app.post("/api/experiences", authMiddleware, async (req, res) => {
  try {
    const { suburb, postcode, addressLine, addressNotes } = req.body || {};
    if (!String(suburb || "").trim()) return res.status(400).json({ message: "Suburb / Area is required." });
    const pc = String(postcode || "").trim();
    if (!reTest(/^[0-9]{4}$/, pc)) return res.status(400).json({ message: "Postcode must be 4 digits." });
    if (!String(addressLine || "").trim()) return res.status(400).json({ message: "Street address is required." });
  } catch (_) {}

  try {
    const body = req.body || {};

    // Business rules (mirror UPDATE route hardening)
    const __toNum = (v) => { const n = Number(v); return Number.isFinite(n) ? n : NaN; };
    const __toInt = (v) => { const n = parseInt(String(v), 10); return Number.isFinite(n) ? n : NaN; };
    const __dateRe = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
    
    if (Object.prototype.hasOwnProperty.call(body, "price")) {
      const n = __toNum(body.price);
      if (!Number.isFinite(n) || n <= 0) return res.status(400).json({ message: "Invalid price" });
      body.price = n;
    }
    if (Object.prototype.hasOwnProperty.call(body, "capacity")) {
      const n = __toInt(body.capacity);
      if (!Number.isFinite(n) || n < 1) return res.status(400).json({ message: "Invalid capacity" });
      body.capacity = n;
    }
    if (Object.prototype.hasOwnProperty.call(body, "startDate")) {
      const sd = String(body.startDate || "").trim();
      if (!__dateRe.test(sd)) return res.status(400).json({ message: "Invalid startDate" });
      body.startDate = sd;
    }
    if (Object.prototype.hasOwnProperty.call(body, "endDate")) {
      const ed = String(body.endDate || "").trim();
      if (!__dateRe.test(ed)) return res.status(400).json({ message: "Invalid endDate" });
      body.endDate = ed;
    }
    
    if (__isPlainObject(body) === false) return res.status(400).json({ message: "Invalid payload" });
    const protoKeys = ["__proto__", "constructor", "prototype"];
    for (const k of Object.keys(body)) {
      if (protoKeys.includes(String(k))) return res.status(400).json({ message: "Invalid payload" });
    }


    const __scrubMongoKeys = (val, depth) => {
      const d = typeof depth === "number" ? depth : 0;
      if (d > 6) return null;
      if (val === null || typeof val === "undefined") return val;
      if (typeof val !== "object") return val;
      if (Array.isArray(val)) return val.map((x) => __scrubMongoKeys(x, d + 1));
      if (__isPlainObject(val) === false) return null;
      const out = {};
      for (const kk of Object.keys(val)) {
        if (!kk) continue;
        if (kk[0] === "$" ) continue;
        if (kk.indexOf(".") !== -1) continue;
        if (kk === "__proto__" || kk === "constructor" || kk === "prototype") continue;
        out[kk] = __scrubMongoKeys(val[kk], d + 1);
      }
      return out;
    };

    if (Object.prototype.hasOwnProperty.call(body, "dynamicDiscounts")) {
      body.dynamicDiscounts = __scrubMongoKeys(body.dynamicDiscounts, 0);
      if (__isPlainObject(body.dynamicDiscounts) === false) return res.status(400).json({ message: "Invalid dynamicDiscounts" });
    }
    const __toStr = (v) => String(v || "").trim();

    let tags = [];
    if (Array.isArray(body.tags)) tags = body.tags;
    else if (body.tags) tags = [body.tags];
    tags = tags.map((t) => __toStr(t)).filter((t) => t);
    tags = [...new Set(tags.filter((t) => CATEGORY_PILLARS.includes(t)))];

    let images = Array.isArray(body.images) ? body.images : [];
    images = images.map((u) => __toStr(u)).filter((u) => u);
    const imageUrl = images[0] || __toStr(body.imageUrl) || "";

    const allowed = [
      "title",
      "description",
      "city",
      "state",
      "country",
      "suburb",
      "postcode",
      "addressLine",
      "addressNotes",
      "price",
      "capacity",
      "duration",
      "language",
      "inclusions",
      "exclusions",
      "meetingPoint",
      "startDate",
      "endDate",
      "startTime",
      "endTime",
      "availableDays",
      "itinerary",
      "requirements",
      "cancellationPolicy",
    ];

    const expData = {};
    for (const k of allowed) {
      if (Object.prototype.hasOwnProperty.call(body, k)) expData[k] = body[k];
    }

    expData.suburb = String((body.suburb) || "").trim();
    expData.postcode = String((body.postcode) || "").trim();
    expData.addressLine = String((body.addressLine) || "").trim();
    expData.addressNotes = String((body.addressNotes) || "").trim();

    expData.images = images;
    expData.imageUrl = imageUrl;
    expData.tags = tags;

    expData.hostId = String(req.user._id);
    expData.hostName = req.user.name;
    expData.hostPic = req.user.profilePic || "";
    expData.isPaused = !!req.user.vacationMode;


    // Capacity mapping: booking enforcement uses maxGuests
    if (typeof expData.capacity !== "undefined") {
      const c = parseInt(String(expData.capacity), 10);
      if (Number.isFinite(c) && c > 0) {
        expData.maxGuests = c;
        if (typeof expData.originalMaxGuests === "undefined") expData.originalMaxGuests = c;
      }
    }
    const exp = new Experience(expData);

    await exp.save();
    res.status(201).json(exp);
  } catch (err) {
    __log("error", "experience_create_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    res.status(500).json({ message: "Failed to create experience" });
  }
});

// Experiences: Update (category sanitize)
app.put("/api/experiences/:id", authMiddleware, async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const exp = await Experience.findById(expId);
    if (!exp) return res.status(404).json({ message: "Not found" });
    const isOwner = (String(exp.hostId || "") === String(req.user._id || ""));
    const isAdmin = Boolean(req.user && req.user.isAdmin);
    if (!(isOwner || isAdmin)) return res.status(403).json({ message: "No" });

    const body = req.body || {};
    if (__isPlainObject(body) === false) return res.status(400).json({ message: "Invalid payload" });
    const { images, tags } = body;

    const allowed = [
      "title",
      "description",
      "city",
      "state",
      "country",
      "suburb",
      "postcode",
      "addressLine",
      "addressNotes",
      "price",
      "dynamicDiscounts",
      "capacity",
      "duration",
      "language",
      "inclusions",
      "exclusions",
      "meetingPoint",
      "startDate",
      "endDate",
      "startTime",
      "endTime",
      "availableDays",
      "itinerary",
      "requirements",
      "cancellationPolicy",
    ];

    const updates = {};
    for (const k of allowed) {
      if (Object.prototype.hasOwnProperty.call(body, k)) updates[k] = body[k];
    }

    const __toStr = (v) => String(v || "").trim();
    const __toNum = (v) => {
      const n = Number(v);
      return Number.isFinite(n) ? n : null;
    };
    const __toInt = (v) => {
      const n = Number.parseInt(String(v), 10);
      return Number.isFinite(n) ? n : null;
    };
    const __toArrStr = (v) => {
      let a = [];
      if (Array.isArray(v)) a = v;
      else if (typeof v !== "undefined" && v !== null) a = [v];
      return a.map((x) => __toStr(x)).filter((x) => x);
    };
    const __scrubMongoKeys = (val, depth) => {
      const d = typeof depth === "number" ? depth : 0;
      if (d > 6) return null;
      if (val === null || typeof val === "undefined") return val;
      if (typeof val !== "object") return val;
      if (Array.isArray(val)) return val.map((x) => __scrubMongoKeys(x, d + 1));
      if (__isPlainObject(val) === false) return null;
      const out = {};
      for (const k of Object.keys(val)) {
        if (!k) continue;
        if (k[0] === "$") continue;
        if (k.indexOf(".") !== -1) continue;
        if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
        out[k] = __scrubMongoKeys(val[k], d + 1);
      }
      return out;
    };

    if (typeof updates.title !== "undefined") updates.title = __toStr(updates.title);
    if (typeof updates.description !== "undefined") updates.description = __toStr(updates.description);
    if (typeof updates.city !== "undefined") updates.city = __toStr(updates.city);
    if (typeof updates.state !== "undefined") updates.state = __toStr(updates.state);
    if (typeof updates.country !== "undefined") updates.country = __toStr(updates.country);
    if (typeof updates.suburb !== "undefined") updates.suburb = __toStr(updates.suburb);
    if (typeof updates.postcode !== "undefined") {
      const pc = __toStr(updates.postcode);
      if (!/^[0-9]{4}$/.test(pc)) delete updates.postcode;
      else updates.postcode = pc;
    }
    if (typeof updates.addressLine !== "undefined") updates.addressLine = __toStr(updates.addressLine);
    if (typeof updates.addressNotes !== "undefined") updates.addressNotes = __toStr(updates.addressNotes);

    if (typeof updates.language !== "undefined") updates.language = __toStr(updates.language);
    if (typeof updates.meetingPoint !== "undefined") updates.meetingPoint = __toStr(updates.meetingPoint);
    if (typeof updates.cancellationPolicy !== "undefined") updates.cancellationPolicy = __toStr(updates.cancellationPolicy);

    if (typeof updates.inclusions !== "undefined") updates.inclusions = __toArrStr(updates.inclusions);
    if (typeof updates.exclusions !== "undefined") updates.exclusions = __toArrStr(updates.exclusions);
    if (typeof updates.availableDays !== "undefined") {
      const allowedDays = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
      const days = __toArrStr(updates.availableDays);
      updates.availableDays = days.filter((d) => allowedDays.includes(d));
    }

    if (typeof updates.itinerary !== "undefined") updates.itinerary = __toStr(updates.itinerary);
    if (typeof updates.requirements !== "undefined") updates.requirements = __toStr(updates.requirements);

    if (typeof updates.price !== "undefined") {
      const n = __toNum(updates.price);
      if (n === null || n < 0) delete updates.price;
      else updates.price = n;
    }
    if (typeof updates.capacity !== "undefined") {
      const n = __toInt(updates.capacity);
      if (n === null || n < 1) delete updates.capacity;
      else updates.capacity = n;
    }


    // Capacity mapping: booking enforcement uses maxGuests
    if (typeof updates.capacity !== "undefined") {
      const c = __toInt(updates.capacity);
      if (c !== null && c > 0) updates.maxGuests = c;
    }
    if (typeof updates.duration !== "undefined") updates.duration = __toStr(updates.duration);

    if (typeof updates.startDate !== "undefined") {
      const d = __toStr(updates.startDate);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) delete updates.startDate;
      else updates.startDate = d;
    }
    if (typeof updates.endDate !== "undefined") {
      const d = __toStr(updates.endDate);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) delete updates.endDate;
      else updates.endDate = d;
    }
    if (typeof updates.startTime !== "undefined") {
      const t = __toStr(updates.startTime);
      if (t && !/^\d{2}:\d{2}$/.test(t)) delete updates.startTime;
      else updates.startTime = t;
    }
    if (typeof updates.endTime !== "undefined") {
      const t = __toStr(updates.endTime);
      if (t && !/^\d{2}:\d{2}$/.test(t)) delete updates.endTime;
      else updates.endTime = t;
    }

    if (typeof updates.preferences !== "undefined") {
      updates.preferences = __scrubMongoKeys(updates.preferences, 0);
      if (__isPlainObject(updates.preferences) === false) delete updates.preferences;
    }

    if (typeof tags !== "undefined") {
      let newTags = [];
      if (Array.isArray(tags)) newTags = tags;
      else if (tags) newTags = [tags];
      newTags = newTags.map((t) => __toStr(t)).filter((t) => t);
      newTags = [...new Set(newTags.filter((t) => CATEGORY_PILLARS.includes(t)))];
      exp.tags = newTags;
    }

    Object.assign(exp, updates);

    if (typeof images !== "undefined") {
      let newImages = [];
      if (Array.isArray(images)) newImages = images;
      else if (images) newImages = [images];
      newImages = newImages.map((u) => __toStr(u)).filter((u) => u);
      exp.images = newImages;
      exp.imageUrl = newImages[0] || "";
    }

    await exp.save();
    return res.json(exp);
  } catch (err) {
    __log("error", "experience_update_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    res.status(500).json({ message: "Failed to update experience" });
  }
});

// Experiences: Delete
app.delete("/api/experiences/:id", authMiddleware, async (req, res) => {
  const expId = __cleanId(req.params.id, 64);
  if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
  const exp = await Experience.findById(expId);
  if (!exp || (exp.hostId !== String(req.user._id) && !req.user.isAdmin)) return res.status(403).json({ message: "No" });

  // Cancel all related bookings via canonical transition (timestamps/comms stay consistent)
  try {
    const bs = await Booking.find({ experienceId: String(exp._id) });
    for (const b of bs) {
      try { await transitionBooking(b, "cancelled_by_host"); } catch (_) {}
    }
  } catch (_) {}

  await Experience.findByIdAndDelete(expId);
  res.json({ message: "Deleted" });
});

// Experiences: Search (filters + pillars)
app.get("/api/experiences", async (req, res) => {
  const { city, q, sort, date, minPrice, maxPrice, category } = req.query;
  let query = { isPaused: false };

  if (city) query.city = { $regex: city, $options: "i" };
  if (q) query.title = { $regex: q, $options: "i" };

  if (category && CATEGORY_PILLARS.includes(category)) query.tags = { $in: [category] };

  if (minPrice || maxPrice) {
    query.price = {};
    if (minPrice) query.price.$gte = Number(minPrice);
    if (maxPrice) query.price.$lte = Number(maxPrice);
  }

  if (date) {
    const dateStr = String(date).trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return res.status(400).json({ message: "Invalid date filter (YYYY-MM-DD)." });

    query.startDate = { $lte: dateStr };
    query.endDate = { $gte: dateStr };

    const d = new Date(dateStr + "T00:00:00Z");
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    query.availableDays = { $in: [days[d.getUTCDay()]] };
  }

  let sortObj = {};
  if (sort === "price_asc") sortObj.price = 1;
  if (sort === "rating_desc") sortObj.averageRating = -1;

  const exps = await Experience.find(query).sort(sortObj);
  const safe = (exps || []).map(e => stripExperiencePrivateFields((e.toObject ? e.toObject() : e)));
  res.json(safe);
});

// Experience detail
app.get("/api/experiences/:id", async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const exp = await Experience.findById(expId);
    if (!exp) return res.status(404).json({ message: "Not found" });
    const safe = stripExperiencePrivateFields((exp.toObject ? exp.toObject() : exp));
    return res.json(safe);
  } catch {
    res.status(404).json({ message: "Not found" });
  }
});

// Similar experiences
app.get("/api/experiences/:id/similar", async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const currentExp = await Experience.findById(expId);
    if (!currentExp) return res.status(404).json({ message: "Not found" });

    const similar = await Experience.find({
      _id: { $ne: currentExp._id },
      isPaused: false,
      $or: [{ tags: { $in: currentExp.tags } }, { city: currentExp.city }],
    })
      .limit(3)
      .select("title price images imageUrl city averageRating");

    if (similar.length === 0) {
      const fallback = await Experience.find({ _id: { $ne: currentExp._id }, isPaused: false })
        .sort({ averageRating: -1 })
        .limit(3)
        .select("title price images imageUrl city averageRating");
      return res.json(fallback);
    }

    res.json(similar);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// --- PRIVACY-FIRST ATTENDEES (Option 1 locked) ---
// Only host OR confirmed attendee can request attendee list.
// Only users with publicProfile=true appear, and only safe fields are returned.
app.get("/api/experiences/:id/attendees", authMiddleware, async (req, res) => {
  try {
    const gate = await viewerCanSeeAttendees(req.params.id, req.user._id);
    if (!gate.ok) return res.status(403).json({ message: "Not allowed" });

    const expId = String(gate.exp._id);

    const bookings = await Booking.find({
      experienceId: expId,
      $or: [{ status: "confirmed" }, { paymentStatus: "paid" }],
    }).populate("guestId", "name profilePic bio handle publicProfile");

    const seen = new Set();
    const publicGuests = [];
    for (const b of bookings) {
      if (!b.guestId) continue;
      const u = b.guestId;
      if (!u.publicProfile) continue;
      const uid = String(u._id);
      if (seen.has(uid)) continue;
      seen.add(uid);
      publicGuests.push(u);
    }

    const otherIds = publicGuests.map((u) => u._id);
    const statusMap = await computeConnectionStatuses(req.user._id, otherIds);

    const out = publicGuests.map((u) => ({
      ...publicUserCardFromDoc(u),
      connectionStatus: statusMap.get(String(u._id)) || "none",
    }));

    return res.json({ experienceId: expId, count: out.length, attendees: out });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Booking: Create + Stripe checkout
app.post("/api/experiences/:id/book", authMiddleware, async (req, res) => {
  const expId = __cleanId(req.params.id, 64);
  if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
  const exp = await Experience.findById(expId);
  if (!exp) return res.status(404).json({ message: "Experience not found" });
  if (exp.isPaused) return res.status(400).json({ message: "Host is paused." });
  const meId = String(((req.user && (req.user._id || req.user.id)) || (req.user && req.user.userId) || ""));
  const hostId = String(exp.hostId || "");
  if (meId && hostId && meId === hostId) {
    return res.status(403).json({ message: "Hosts cannot book their own experience." });
  }

  const { numGuests, isPrivate, bookingDate, timeSlot, guestNotes } = req.body || {};
  let guests = Number.parseInt(numGuests, 10) || 1;

  // Booking caps (non-negotiable):
  // - Public: 1..6 guests per request
  // - Private: user books the entire slot (exclusive)
  const __capInt = (v, lo, hi) => {
    const n = Number.parseInt(String(v), 10);
    if (!Number.isFinite(n)) return lo;
    return Math.max(lo, Math.min(hi, n));
  };

  const __fullCapacity = () => {
    const raw = (exp && (exp.privateCapacity || exp.maxGuests || 0)) || 0;
    const cap = __capInt(raw, 0, 500);
    return cap;
  };

  const __isPrivate = (function(v){
    if (v === true) return true;
    if (v === false) return false;
    const t = String(v || "").trim().toLowerCase();
    if (t === "true" || t === "1" || t === "yes") return true;
    return false;
  })(isPrivate);
  if (__isPrivate) {
    const fullCap = __fullCapacity();
    if (!(fullCap > 0)) return res.status(400).json({ message: "Invalid capacity for private booking." });
    guests = fullCap;
  } else {
    if (!(guests >= 1 && guests <= 6)) return res.status(400).json({ message: "Max 6 slots per booking" });
  }


  const bookingDateStr = String(bookingDate || "").trim();
  const timeSlotStr = String(timeSlot || "").trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(bookingDateStr)) return res.status(400).json({ message: "bookingDate required (YYYY-MM-DD)." });
  if (!timeSlotStr) return res.status(400).json({ message: "timeSlot is required." });
  if (!Number.isFinite(guests) || guests < 1) return res.status(400).json({ message: "numGuests must be >= 1." });
  const policyVersionAccepted = String(((req.body || {}).policyVersionAccepted) || ((req.body || {}).policyVersion) || "").trim();
  const termsVersionAccepted = String(((req.body || {}).termsVersionAccepted) || ((req.body || {}).termsVersion) || "").trim();

  const activePolicyDoc = await getActivePolicyDoc();
  const activeSnap = policySnapshotFromDoc(activePolicyDoc);
  const activeVer = String((activeSnap && activeSnap.version) || "");
  const hasPolicy = Boolean(policyVersionAccepted && activeVer && (policyVersionAccepted == activeVer));
  const hasTerms = Boolean(termsVersionAccepted && (termsVersionAccepted.length > 0));
  const okAccept = Boolean(hasPolicy && hasTerms);
  if (okAccept == false) return res.status(400).json({ message: "Policy and terms acceptance required", activePolicy: { ok: true, policy: activeSnap } });

  const toCents = (n) => Math.round(Number(n) * 100);

  const unitCents = toCents(exp.price);
  let totalCents = unitCents * guests;
  let description = `${guests} Guests`;

  // DYNAMIC_DISCOUNTS_V1 (tiered)
  // - host tiers: host funds discount (host payout reduced)
  // - admin tiers: admin funds discount (host paid full; admin absorbs subsidy)
  const __pickTier = (tiers, guestsNum) => {
    try {
      if (Array.isArray(tiers) == false) return null;
      let best = null;
      for (const t of tiers) {
        if (t == null || typeof t !== "object") continue;
        const minG = Math.floor(Number(t.minGuests));
        const pct = Number(t.percent);
        if (!(minG >= 2)) continue;
        if (!(pct > 0 && pct <= 50)) continue;
        if (guestsNum < minG) continue;
        if (best == null) best = { minGuests: minG, percent: pct };
        else {
          if (minG > best.minGuests) best = { minGuests: minG, percent: pct };
          else if (minG == best.minGuests && pct > best.percent) best = { minGuests: minG, percent: pct };
        }
      }
      return best;
    } catch (_) {
      return null;
    }
  };

  const dd = (exp && exp.dynamicDiscounts && typeof exp.dynamicDiscounts === "object") ? exp.dynamicDiscounts : {};
  const ddGroup = (dd && dd.group && typeof dd.group === "object") ? dd.group : {};

  const hostCfg = (ddGroup && ddGroup.host && typeof ddGroup.host === "object") ? ddGroup.host : {};
  const adminCfg = (ddGroup && ddGroup.admin && typeof ddGroup.admin === "object") ? ddGroup.admin : {};

  const hostEnabled = Boolean(hostCfg && hostCfg.enabled);
  const adminEnabled = Boolean(adminCfg && adminCfg.enabled);

  const hostTier = hostEnabled ? __pickTier(hostCfg.tiers, guests) : null;
  const adminTier = adminEnabled ? __pickTier(adminCfg.tiers, guests) : null;

  // Choose the best customer discount. If both exist, pick higher percent; tie -> prefer host (avoids admin subsidy).
  let chosen = null;
  if (hostTier && adminTier) {
    if (Number(adminTier.percent) > Number(hostTier.percent)) chosen = { source: "admin", tier: adminTier };
    else chosen = { source: "host", tier: hostTier };
  }
  else if (adminTier) chosen = { source: "admin", tier: adminTier };
  else if (hostTier) chosen = { source: "host", tier: hostTier };

  let preDiscountCents = totalCents;
  let discountSource = "";
  let discountPct = 0;
  let discountMinGuests = 0;

  if (chosen && !__isPrivate) {
    discountSource = String(chosen.source || "");
    discountPct = Number(chosen.tier && chosen.tier.percent) || 0;
    discountMinGuests = Number(chosen.tier && chosen.tier.minGuests) || 0;
    const factor = (100 - discountPct) / 100;
    totalCents = Math.round(totalCents * factor);
    if (discountPct > 0) {
      description += " (" + String(discountPct) + "% Group Discount Applied)";
    }
  }

  // Marketplace accounting:
  // - host discount => host payout == customer pays
  // - admin discount => host payout == pre-discount; admin absorbs difference
  let hostPayoutCents = totalCents;
  let adminSubsidyCents = 0;
  if (discountSource === "admin") {
    hostPayoutCents = preDiscountCents;
    adminSubsidyCents = Math.max(0, preDiscountCents - totalCents);
  }


  if (__isPrivate && exp.privatePrice) {
    totalCents = toCents(exp.privatePrice);
    description = "Private Booking";
    // Private booking: fixed total, no group discount mechanics, no admin subsidy
    discountSource = "";
    discountPct = 0;
    discountMinGuests = 0;
    // Align accounting fields to the fixed private total
    try {
      preDiscountCents = totalCents;
    } catch (_) { }
    hostPayoutCents = totalCents;
    adminSubsidyCents = 0;
  }
  // Capacity hold must happen AFTER policy/terms acceptance, and BEFORE booking save (race-safe)
  let hold = null;

  if (__isPrivate) {
    // Private booking must be exclusive: only allowed if nobody reserved this slot yet.
    const OR = String.fromCharCode(36) + "or";
    const EXISTS = String.fromCharCode(36) + "exists";
    const SET = String.fromCharCode(36) + "set";
    const SET_ON_INSERT = String.fromCharCode(36) + "setOnInsert";

    const q = { experienceId: String(exp._id), bookingDate: bookingDateStr, timeSlot: timeSlotStr };
    q[OR] = [
      { reservedGuests: (function(){ const x={}; x[EXISTS]=false; return x; })() },
      { reservedGuests: 0 }
    ];

    const now = new Date();
    const upd = {};
    upd[SET] = { reservedGuests: guests, maxGuests: guests, updatedAt: now };
    upd[SET_ON_INSERT] = { experienceId: String(exp._id), bookingDate: bookingDateStr, timeSlot: timeSlotStr, createdAt: now };

    let did = false;
    try {
      const r = await CapacitySlot.updateOne(q, upd, { upsert: true });
      const matched = Number(r && r.matchedCount) || 0;
      const upserted = Number(r && r.upsertedCount) || 0;
      did = Boolean(matched > 0 || upserted > 0);
    } catch (e) {
      const msg = String(e && e.message ? e.message : "");
      if (e && (e.code === 11000 || msg.indexOf("E11000") >= 0)) {
        did = false;
      } else {
        throw e;
      }
    }

    if (!did) {
      // Suggest the next available private slot to reduce booking friction.
      // python-style int helper in JS scope:
      function int(v){ const n = Number.parseInt(String(v), 10); return Number.isFinite(n) ? n : 0; }
      function pad2(n){ return (n < 10 ? "0" : "") + String(n); }
      function ymdFromDate(dt){
        const y = dt.getUTCFullYear();
        const m = dt.getUTCMonth() + 1;
        const d = dt.getUTCDate();
        return String(y) + "-" + pad2(m) + "-" + pad2(d);
      }
      function addDaysUTC(ymd, days){
        const parts = String(ymd).split("-");
        const y = int(parts[0]);
        const m = int(parts[1]);
        const d = int(parts[2]);
        const dt = new Date(Date.UTC(y, m - 1, d));
        dt.setUTCDate(dt.getUTCDate() + int(days));
        return ymdFromDate(dt);
      }
      function dayNameUTC(ymd){
        const parts = String(ymd).split("-");
        const y = int(parts[0]);
        const m = int(parts[1]);
        const d = int(parts[2]);
        const dt = new Date(Date.UTC(y, m - 1, d));
        const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        return days[dt.getUTCDay()];
      }

      const windowDays = 60;
      const slots = (Array.isArray(exp.timeSlots) && exp.timeSlots.length > 0) ? exp.timeSlots : [timeSlotStr];
      const availDays = (Array.isArray(exp.availableDays) && exp.availableDays.length > 0) ? exp.availableDays : null;
      const blocked = (Array.isArray(exp.blockedDates) && exp.blockedDates.length > 0) ? exp.blockedDates : [];

      let next = null;
      for (let k = 0; k <= windowDays; k++) {
        const d2 = addDaysUTC(bookingDateStr, k);
        if (exp.startDate && String(d2) < String(exp.startDate)) continue;
        if (exp.endDate && String(d2) > String(exp.endDate)) continue;
        if (blocked.includes(d2)) continue;
        if (availDays) {
          const dn = dayNameUTC(d2);
          if (!availDays.includes(dn)) continue;
        }

        for (const sl of slots) {
          const sl2 = String(sl || "").trim();
          if (!sl2) continue;
          const cur = await CapacitySlot.findOne({ experienceId: String(exp._id), bookingDate: d2, timeSlot: sl2 }).lean();
          const rsv = (cur && typeof cur.reservedGuests === "number") ? Number(cur.reservedGuests) : 0;
          if (rsv === 0) {
            next = { bookingDate: d2, timeSlot: sl2 };
            break;
          }
        }
        if (next) break;
      }

      return res.status(400).json({
        message: "Private booking requires an empty slot.",
        nextPrivateAvailable: next
      });
    }

    hold = { ok: true, maxGuests: guests };
  } else {
    hold = await reserveCapacitySlot(String(exp._id), bookingDateStr, timeSlotStr, guests);
  }

  const holdOk = Boolean(hold && hold.ok);
  if (holdOk == false) return res.status(400).json({ message: String(hold.message || "Fully booked.") });


  const booking = new Booking({
    experienceId: String(exp._id),
    guestId: req.user._id,
    guestName: req.user.name,
    guestEmail: req.user.email,
    hostId: String(exp.hostId),
    numGuests: guests,
    bookingDate: bookingDateStr,
    timeSlot: timeSlotStr,
    guestNotes: guestNotes || "",

    // pricing breakdown (DYNAMIC_DISCOUNTS_V1)
    pricing: {
      unitCents: unitCents,
      guests: guests,
      subtotalCents: unitCents * guests,
      preDiscountCents: preDiscountCents,
      discount: { source: discountSource, percent: discountPct, minGuests: discountMinGuests },
      totalCents: totalCents,
      hostPayoutCents: hostPayoutCents,
      adminSubsidyCents: adminSubsidyCents,
      description: String(description || "")
    },

    expiresAt: new Date(Date.now() + (15 * 60 * 1000)),


    policySnapshot: activeSnap || {},
    policyVersionId: activePolicyDoc ? String(activePolicyDoc._id) : "",
    policyVersion: String((activeSnap && activeSnap.version) || ""),
    policyEffectiveFrom: (activeSnap && activeSnap.effectiveFrom) ? new Date(activeSnap.effectiveFrom) : null,
    policyPublishedAt: (activeSnap && activeSnap.publishedAt) ? new Date(activeSnap.publishedAt) : null,
    policyAcceptedAt: new Date(),
    termsVersionAccepted: termsVersionAccepted,
    termsAcceptedAt: new Date(),
  });
  try {
    await booking.save();
  } catch (e) {
    try { await releaseCapacitySlot(String(exp._id), bookingDateStr, timeSlotStr, guests); } catch (_) {}
    throw e;
  }
  // Comms: booking request submitted (guest)
  try {
    const __guestEmail = (req.user && req.user.email) ? String(req.user.email).trim() : "";
    const __guestNameSafe = (req.user && req.user.name) ? String(req.user.name).trim() : "";
    if (__guestEmail) {
      await sendEventEmail({
        to: __guestEmail,
        eventName: "BOOKING_REQUEST_SUBMITTED",
        category: "NOTIFICATIONS",
        vars: {
          DASHBOARD_URL: __dashboardUrl(),
          DATE: bookingDateStr,
          TIME: timeSlotStr,
          EXPERIENCE_TITLE: String(exp.title || ""),
          Name: __guestNameSafe
        }
      });
    }
  } catch (_) {}

  try {
    const baseUrl = __requirePublicUrl();
    const session = await stripe.checkout.sessions.create({
      client_reference_id: String(booking._id),
      metadata: { bookingId: String(booking._id), experienceId: String(exp._id), guestId: String(req.user._id) },
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "aud",
            product_data: { name: exp.title, description },
            unit_amount: totalCents,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${baseUrl}/success.html?sessionId={CHECKOUT_SESSION_ID}&bookingId=${booking._id}`,
      cancel_url: `${baseUrl}/experience.html?id=${exp._id}`,
    });

    booking.stripeSessionId = session.id;
    await booking.save();
    return res.json({
      bookingId: String(booking._id),
      sessionId: String(session.id),
      url: session.url,
    });
  } catch (e) {
    try {
      await releaseCapacitySlot(String(exp._id), bookingDateStr, timeSlotStr, guests);
    } catch (_) {}

    // Do not leave an orphan pending_payment booking without a Stripe session.
    try {
      booking.paymentStatus = "unpaid";
      booking.expiredAt = new Date();
      await booking.save();
      await transitionBooking(booking, "expired", { reason: "stripe_checkout_error", suppressComms: true });
    } catch (_) {}

    __log("error", "stripe_checkout_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    res.status(500).json({ message: "Payment initialization failed" });
  }
});

// Booking verify
app.post("/api/bookings/verify", async (req, res) => {
  const bid = __cleanId(((req.body || {}).bookingId), 80);
  const sid = __cleanId(((req.body || {}).sessionId), 120);
  if (bid.length === 0) return res.status(400).json({ status: "invalid_booking_id" });
  if (sid.length === 0) return res.status(400).json({ status: "invalid_session_id" });
  const bookingId = bid;
  const sessionId = sid;
  if (!(mongoose && mongoose.Types && mongoose.Types.ObjectId && mongoose.Types.ObjectId.isValid && mongoose.Types.ObjectId.isValid(bookingId))) {
    return res.status(400).json({ status: "invalid_booking_id" });
  }
  const booking = await Booking.findById(bookingId);
  if (!booking) return res.status(404).json({ status: "not_found" });
  const me = String(((req.user && (req.user._id || req.user.id)) || (req.user && req.user.userId) || ""));
  const hasUser = Boolean(req.user && (me !== "" || req.user.isAdmin || req.user.admin === true));
  if (hasUser) {
    const isOwner = (me != "") && (String(booking.guestId || "") == me);
    const isHost = (me != "") && (String(booking.hostId || "") == me);
    const isAdmin = Boolean(req.user && (req.user.isAdmin || req.user.admin === true));
    const isAllowed = (isOwner || isHost || isAdmin);
    if (isAllowed == false) return res.status(403).json({ status: "VERIFY_FORBIDDEN" });
  }
  const prevStatus = String(booking.status || "");
  const isTerminal = (prevStatus.indexOf("cancelled") >= 0) || (prevStatus == "refunded");


  if (booking.paymentStatus === "paid" || booking.status === "confirmed") {
    try {
      const hasSnap = booking.policySnapshot && typeof booking.policySnapshot === "object" && Object.keys(booking.policySnapshot).length > 0;
      if (!hasSnap) {
        const activePolicyDoc = await getActivePolicyDoc();
        const snap = policySnapshotFromDoc(activePolicyDoc);
        booking.policySnapshot = snap || {};
        booking.policyVersionId = activePolicyDoc ? String(activePolicyDoc._id) : "";
        booking.policyVersion = (snap && snap.version) ? String(snap.version) : "";
        booking.policyEffectiveFrom = (snap && snap.effectiveFrom) ? new Date(snap.effectiveFrom) : null;
        booking.policyPublishedAt = (snap && snap.publishedAt) ? new Date(snap.publishedAt) : null;
        await booking.save();
      }
    } catch (_) {}
    await maybeSendBookingConfirmedComms(booking);
    return res.json({ status: "confirmed" });
  }


  try {
    const session = await stripe.checkout.sessions.retrieve(String(sessionId || ""), { expand: ["payment_intent"] });

    const metaBookingId =
      (session && session.client_reference_id) ||
      (session && session.metadata && session.metadata.bookingId) ||
      "";

    const metaOk = (String(metaBookingId) === String(booking._id));
    const metaMissing = (String(metaBookingId || "") === "");
    const sessionOk = (String(booking.stripeSessionId || "") === String((session && session.id) ? session.id : sessionId));
    if (!metaOk) {
      // Legacy sessions may not carry client_reference_id/metadata.bookingId.
      // Safe fallback: allow only if booking already stores the same Stripe session id.
      if (!(metaMissing && sessionOk)) {
        return res.status(400).json({ status: "mismatch", error: "session does not match booking" });
      }
    }

    const currency = String(session.currency || "aud").toLowerCase();
    const amountTotal = Number.isFinite(session.amount_total) ? Number(session.amount_total) : null;

    const expectedCents = booking.pricing && Number.isFinite(booking.pricing.totalCents) ? Number(booking.pricing.totalCents) : null;

    if (expectedCents !== null && amountTotal !== null && amountTotal !== expectedCents) return res.status(400).json({ status: "mismatch", error: "amount mismatch" });

    const stripeStatus = String(session.payment_status || "unknown");
    // PAYMENT_ATTEMPT_POLICY_V1
    // Count only real failures (requires_payment_method / canceled).
    // Do NOT count requires_action (3DS) as a failure attempt.
    const piStatus = String((session && session.payment_intent && session.payment_intent.status) ? session.payment_intent.status : "");
    booking.paymentLastStripeStatus = stripeStatus;
    booking.paymentLastPiStatus = piStatus;

    const now = new Date();
    const lockedUntil = booking.paymentLockedUntil ? new Date(booking.paymentLockedUntil) : null;
    if (lockedUntil && lockedUntil.getTime() > now.getTime()) {
      return res.status(429).json({ status: "payment_locked", lockedUntil: lockedUntil.toISOString() });
    }

    const isFail = (piStatus === "requires_payment_method" || piStatus === "canceled" || piStatus === "cancelled");
    if (stripeStatus !== "paid" && isFail) {
      booking.paymentAttemptCount = Number.isFinite(Number(booking.paymentAttemptCount)) ? Number(booking.paymentAttemptCount) + 1 : 1;
      booking.paymentAttemptFirstAt = booking.paymentAttemptFirstAt || now;
      booking.paymentAttemptLastAt = now;

      // Policy: 5 failures within 30 minutes => lock for 30 minutes
      const firstAt = booking.paymentAttemptFirstAt ? new Date(booking.paymentAttemptFirstAt) : now;
      const within30m = (now.getTime() - firstAt.getTime()) <= (30 * 60 * 1000);
      const attempts = Number(booking.paymentAttemptCount || 0);
      if (within30m && attempts >= 5) {
        booking.paymentLockedUntil = new Date(now.getTime() + (30 * 60 * 1000));
        await booking.save();
        return res.status(429).json({ status: "payment_locked", lockedUntil: booking.paymentLockedUntil.toISOString() });
      }
      await booking.save();
    }


    if (stripeStatus === "paid") {
        // PAID_AFTER_EXPIRY_GUARD_V1
        const curStatus = String(booking.status || "");
        if (curStatus === "expired") {
          booking.paymentStatus = "paid";
          booking.paymentAnomaly = booking.paymentAnomaly || "paid_after_expiry";
          booking.paymentAnomalyAt = booking.paymentAnomalyAt || new Date();
          booking.stripeSessionId = String(session.id || booking.stripeSessionId || "");
          if (session.payment_intent) booking.stripePaymentIntentId = String(session.payment_intent.id || session.payment_intent);

          await booking.save();
          return res.json({ status: "paid_after_expiry" });
        }
      if (isTerminal === false) await transitionBooking(booking, "confirmed");
      booking.paymentStatus = "paid";
      if (isTerminal) {
        booking.paymentAnomaly = booking.paymentAnomaly || "paid_after_cancel";
        booking.paymentAnomalyAt = booking.paymentAnomalyAt || new Date();
      }
      booking.stripeSessionId = String(session.id || booking.stripeSessionId || "");
      if (session.payment_intent) booking.stripePaymentIntentId = String(session.payment_intent.id || session.payment_intent);
      booking.amountCents = expectedCents !== null ? expectedCents : amountTotal;
      booking.currency = currency;
      booking.paidAt = booking.paidAt || new Date();
      await booking.save();
      // SNAPSHOT_ON_PAYMENT_CONFIRM (authoritative policy lock at payment time; write-once)
      let snapWritten = false;
      try {
        const hasSnap = booking.policySnapshot && typeof booking.policySnapshot === "object" && Object.keys(booking.policySnapshot).length > 0;
        if (!hasSnap) {
          const activePolicyDoc = await getActivePolicyDoc();
          const snap = policySnapshotFromDoc(activePolicyDoc);
          booking.policySnapshot = snap || {};
          booking.policyVersionId = activePolicyDoc ? String(activePolicyDoc._id) : "";
          booking.policyVersion = (snap && snap.version) ? String(snap.version) : "";
          booking.policyEffectiveFrom = (snap && snap.effectiveFrom) ? new Date(snap.effectiveFrom) : null;
          booking.policyPublishedAt = (snap && snap.publishedAt) ? new Date(snap.publishedAt) : null;
          snapWritten = true;
        }
      } catch (_) {
        // If policy lookup fails, do not break payment confirmation.
      }
      // SNAPSHOT_ON_PAYMENT_CONFIRM_SAVE
      if (snapWritten) await booking.save();


      await maybeSendBookingConfirmedComms(booking);
      return res.json({ status: "confirmed" });
    }

    return res.json({ status: stripeStatus, bookingStatus: booking.status, paymentStatus: booking.paymentStatus });
  } catch (e) {
    return res.status(500).json({ message: "Verification failed" });
  }
});

// Host dashboard bookings (NO mobile leakage)
app.get("/api/bookings/host-bookings", authMiddleware, async (req, res) => {
  try {
    const hostId = String(req.user._id);
    const bookings = await Booking.find({ hostId })
      .populate("experience", "title images price imageUrl city")
      .populate("guestId", "name profilePic handle publicProfile") // mobile NOT included
      .sort({ bookingDate: 1 });
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/host/bookings/:experienceId", authMiddleware, async (req, res) => {
  try {
    const hostId = String(req.user._id);
    const experienceId = req.params.experienceId;
    const bookings = await Booking.find({ hostId, experienceId })
      .select("-guestEmail")
      .populate("experience", "title images price imageUrl city")
      .populate("guestId", "name profilePic handle publicProfile") // mobile NOT included
      .sort({ bookingDate: 1 });

    const out = bookings.map((b) => {
      const o = (b && typeof b.toObject === "function") ? b.toObject() : b;
      if (o && typeof o === "object") delete o.guestEmail;
      return o;
    });

    res.json(out);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Guest bookings
async function getMyBookings(req, res) {
  const bookings = await Booking.find({ guestId: req.user._id }).populate("experience").sort({ bookingDate: -1 });
  res.json(bookings);
}

app.get("/api/bookings/my-bookings", authMiddleware, async (req, res) => getMyBookings(req, res));
app.get("/api/my/bookings", authMiddleware, async (req, res) => {
  try {
    res.set("Deprecation", "true");
    res.set("Sunset", "Sat, 01 Feb 2026 00:00:00 GMT");
    res.set("Link", "</api/bookings/my-bookings>; rel=\"canonical\"");
  } catch (_) {}
  return getMyBookings(req, res);
});

// Cancel booking
app.post("/api/bookings/:id/cancel", authMiddleware, async (req, res) => {
  try {
    const bookingId = __cleanId(req.params.id, 64);
    if (!bookingId) return res.status(400).json({ message: "Invalid bookingId" });
    const booking = await Booking.findById(bookingId);
    if (!booking) return res.status(404).json({ message: "Booking not found" });
    if (String(booking.guestId) !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" });

    // Idempotent: if already cancelled, return existing decision
    if (booking.status === "cancelled" || booking.status === "cancelled_by_host") {
      return res.json({
        message: "Already cancelled",
        refund: booking.refundDecision || { status: "none", amountCents: 0, currency: "aud", percent: 0 },
      });
    }

    const wasConfirmed = (String(booking.status || "") == "confirmed");

    await transitionBooking(booking, "cancelled");
    booking.cancellationReason = "User requested cancellation";
    booking.cancellation = { by: "guest", at: new Date(), reasonCode: "guest_cancel", note: "" };

    const totalCents =
      booking.pricing && Number.isFinite(booking.pricing.totalCents) ? Number(booking.pricing.totalCents) : null;

    const snap = booking.policySnapshot || null;
    const rules = (snap && snap.rules && typeof snap.rules === "object") ? snap.rules : null;

    let refundCents = 0;
    let refundPercent = 0;
    let decisionStatus = "manual";

    if (totalCents !== null && rules) {
      const cap = Number.isFinite(rules.absoluteMaxGuestRefundPercent) ? Number(rules.absoluteMaxGuestRefundPercent) : 0.95;
      const pRaw = Number.isFinite(rules.guestMaxRefundPercent) ? Number(rules.guestMaxRefundPercent) : 0.95;
      refundPercent = Math.max(0, Math.min(cap, pRaw));
      refundCents = Math.round(totalCents * refundPercent);
      decisionStatus = "computed";
      booking.refundAmount = Number((refundCents / 100).toFixed(2)); // keep legacy UI field
    } else {
      booking.refundAmount = 0;
    }

    booking.refundDecision = {
      status: decisionStatus,
      amountCents: refundCents,
      currency: String((rules && rules.currency) || booking.currency || "aud").toLowerCase(),
      percent: refundPercent,
      computedAt: new Date(),
      stripeRefundId: "",
      stripeRefundStatus: "",
    };

    // If already paid and refund is due, initiate Stripe refund server-side (idempotent)
    try {
      const isPaid = (booking.paymentStatus === "paid");
      const pi = String(booking.stripePaymentIntentId || "");
      const alreadyHasRefund = booking.refundDecision && booking.refundDecision.stripeRefundId;
      if (isPaid && refundCents > 0 && pi && !alreadyHasRefund) {
        const refund = await stripe.refunds.create(
          { payment_intent: pi, amount: refundCents },
          { idempotencyKey: `booking_refund_${String(booking._id)}_${refundCents}` }
        );
        booking.refundDecision.stripeRefundId = String(refund.id || "");
        booking.refundDecision.stripeRefundStatus = String(refund.status || "");
        booking.refundDecision.status = "refund_requested";
      }
    } catch (e) {
      try {
        if (!booking.refundDecision || typeof booking.refundDecision !== "object") booking.refundDecision = {};
        booking.refundDecision.attemptCount = Number.isFinite(Number(booking.refundDecision.attemptCount)) ? Number(booking.refundDecision.attemptCount) + 1 : 1;
        booking.refundDecision.lastAttemptAt = new Date();
        booking.refundDecision.lastError = String((e && e.message) ? e.message : "refund_initiation_error").slice(0, 240);
        booking.refundDecision.stripeRefundStatus = "error";
        booking.refundDecision.status = "refund_failed";
      } catch (_) {}
      __log("error", "refund_initiation_failed", { rid: undefined, path: undefined });
      // Do not fail cancellation if refund initiation fails; webhook/retry/admin can reconcile.
    }

    await booking.save();


    return res.json({
      message: "Booking cancelled.",
      refund: booking.refundDecision,
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Reviews
app.post("/api/reviews", authMiddleware, async (req, res) => {
  const body = req.body || {};
  if (__isPlainObject(body) === false) return res.status(400).json({ message: "Invalid payload" });
  if (Object.prototype.hasOwnProperty.call(body, "__proto__") || Object.prototype.hasOwnProperty.call(body, "constructor") || Object.prototype.hasOwnProperty.call(body, "prototype")) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  const { experienceId, bookingId, rating, comment, type, targetId } = body;
  const reviewType = type || "guest_to_host";

  if (await Review.findOne({ bookingId, authorId: req.user._id })) return res.status(400).json({ message: "Duplicate" });

  const review = new Review({
    experienceId,
    bookingId,
    authorId: req.user._id,
    authorName: req.user.name,
    targetId,
    type: reviewType,
    rating,
    comment,
  });

  await review.save();

  if (reviewType === "guest_to_host") {
    const reviews = await Review.find({ experienceId, type: "guest_to_host" });
    const avg = reviews.reduce((acc, r) => acc + r.rating, 0) / reviews.length;
    await Experience.findByIdAndUpdate(experienceId, { averageRating: avg, reviewCount: reviews.length });
  } else {
    const userReviews = await Review.find({ targetId, type: "host_to_guest" });
    const avg = userReviews.reduce((acc, r) => acc + r.rating, 0) / userReviews.length;
    await User.findByIdAndUpdate(targetId, { guestRating: avg, guestReviewCount: userReviews.length });
  }

  res.json(review);
});

app.get("/api/experiences/:id/reviews", async (req, res) => {
  const expId = __cleanId(req.params.id, 64);
  if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
  const reviews = await Review.find({ experienceId: expId, type: "guest_to_host" }).sort({ date: -1 });
  res.json(reviews);
});

// --- Likes --- (toggle + count)
app.post("/api/experiences/:id/like", authMiddleware, async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const existing = await ExperienceLike.findOne({ experienceId: expId, userId: req.user._id });
    if (existing) {
      await ExperienceLike.findByIdAndDelete(existing._id);
      const count = await ExperienceLike.countDocuments({ experienceId: expId });
      return res.json({ liked: false, count });
    }
    await ExperienceLike.create({ experienceId: expId, userId: req.user._id });
    const count = await ExperienceLike.countDocuments({ experienceId: expId });
    return res.json({ liked: true, count });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/experiences/:id/like", authMiddleware, async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const liked = !!(await ExperienceLike.findOne({ experienceId: expId, userId: req.user._id }));
    const count = await ExperienceLike.countDocuments({ experienceId: expId });
    return res.json({ liked, count });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// --- Comments --- (host + confirmed attendees only)
async function canComment(expId, userId) {
  const exp = await Experience.findById(expId);
  if (!exp) return { ok: false, reason: "Experience not found" };
  if (String(exp.hostId) === String(userId)) return { ok: true, exp, role: "host" };

  const b = await Booking.findOne({
    experienceId: String(exp._id),
    guestId: userId,
    $or: [{ status: "confirmed" }, { paymentStatus: "paid" }],
  });

  if (b) return { ok: true, exp, role: "attendee" };
  return { ok: false, reason: "Not allowed" };
}

app.post("/api/experiences/:id/comments", authMiddleware, async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const gate = await canComment(expId, req.user._id);
    if (!gate.ok) return res.status(403).json({ message: "Not allowed" });

    const text = String((req.body && req.body.text) || "").trim();
    if (!text) return res.status(400).json({ message: "Comment text required" });
    if (text.length > 1000) return res.status(400).json({ message: "Comment too long" });

    const c = await ExperienceComment.create({ experienceId: expId, authorId: req.user._id, text });

    return res.json({
      _id: c._id,
      experienceId: expId,
      text: c.text,
      createdAt: c.createdAt,
      author: {
        _id: req.user._id,
        name: String(req.user.name || ""),
        profilePic: req.user.publicProfile ? String(req.user.profilePic || "") : "",
        bio: req.user.publicProfile ? String(req.user.bio || "") : "",
        handle: String(req.user.handle || ""),
        publicProfile: !!req.user.publicProfile,
      },
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/experiences/:id/comments", authMiddleware, async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const gate = await canComment(expId, req.user._id);
    if (!gate.ok) return res.status(403).json({ message: "Not allowed" });

    const comments = await ExperienceComment.find({ experienceId: expId })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate("authorId", "name profilePic bio handle publicProfile");

    const out = comments.map((c) => {
      const u = c.authorId;
      return {
        _id: c._id,
        experienceId: expId,
        text: c.text,
        createdAt: c.createdAt,
        author: u
          ? {
              _id: u._id,
              name: String(u.name || ""),
              profilePic: u.publicProfile ? String(u.profilePic || "") : "",
              bio: u.publicProfile ? String(u.bio || "") : "",
              handle: String(u.handle || ""),
              publicProfile: !!u.publicProfile,
            }
          : null,
      };
    });

    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Bookmarks
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
  const exps = await Experience.find({ _id: { $in: bms.map((b) => b.experienceId) } });
  res.json(exps);
});

// Booking visibility (friends feed opt-in)
app.put("/api/bookings/:id/visibility", authMiddleware, async (req, res) => {
  try {
    const bookingId = __cleanId(req.params.id, 64);
    if (!bookingId) return res.status(400).json({ message: "Invalid bookingId" });
    const booking = await Booking.findById(bookingId);
    if (!booking) return res.status(404).json({ message: "Booking not found" });
    if (String(booking.guestId) !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" });

    const __toBoolStrict = (v) => {
      if (typeof v === "boolean") return v;
      const x = String(v || "").toLowerCase().trim();
      if (x === "true" || x === "1" || x === "yes" || x === "y") return true;
      if (x === "false" || x === "0" || x === "no" || x === "n") return false;
      return null;
    };

    const raw = (req.body && Object.prototype.hasOwnProperty.call(req.body, "toFriends")) ? req.body.toFriends : undefined;
    const parsed = __toBoolStrict(raw);
    if (parsed === null) return res.status(400).json({ message: "toFriends must be a boolean." });
    const toFriends = parsed;
    booking.visibilityToFriends = toFriends;
    await booking.save();
    return res.json({ ok: true, visibilityToFriends: booking.visibilityToFriends });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Social: connect
app.post("/api/social/connect", authMiddleware, async (req, res) => {
  try {
    const __toStr = (v) => String(v || "").trim();

    let targetUserId = __toStr((req.body && req.body.targetUserId) || "");
    let handle = normalizeHandle((req.body && req.body.handle) || "");

    if (targetUserId) {
      const okId = (mongoose && mongoose.Types && mongoose.Types.ObjectId && mongoose.Types.ObjectId.isValid)
        ? mongoose.Types.ObjectId.isValid(targetUserId)
        : false;
      if (!okId) return res.status(400).json({ message: "Invalid targetUserId." });
    }

    if (handle) {
      handle = __toStr(handle);
      if (handle.length > 32) handle = handle.slice(0, 32);
    }

    if (!targetUserId && !handle) return res.status(400).json({ message: "targetUserId or handle required." });

    let target = null;
    if (targetUserId) target = await User.findById(targetUserId);
    if (!target && handle) target = await User.findOne({ handle, allowHandleSearch: true });

    if (!target) return res.status(404).json({ message: "User not found." });
    if (String(target._id) === String(req.user._id)) return res.status(400).json({ message: "Cannot connect to yourself." });

    const reverse = await Connection.findOne({ requesterId: target._id, addresseeId: req.user._id });
    if (reverse && reverse.status === "pending") {
      reverse.status = "accepted";
      reverse.respondedAt = new Date();
      await reverse.save();
      return res.json({ status: "accepted", connectionId: reverse._id });
    }

    const existing = await Connection.findOne({ requesterId: req.user._id, addresseeId: target._id });
    if (existing) {
      if (existing.status === "accepted") return res.json({ status: "accepted", connectionId: existing._id });
      if (existing.status === "pending") return res.json({ status: "pending", connectionId: existing._id });
      if (existing.status === "blocked") return res.status(403).json({ message: "Connection blocked." });
    }

    const c = await Connection.create({ requesterId: req.user._id, addresseeId: target._id, status: "pending" });
    return res.json({ status: "pending", connectionId: c._id });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Social: incoming requests
app.get("/api/social/requests", authMiddleware, async (req, res) => {
  try {
    const reqs = await Connection.find({ addresseeId: req.user._id, status: "pending" }).sort({ createdAt: -1 });
    const out = [];
    for (const r of reqs) out.push({ _id: r._id, from: await minimalUserCard(r.requesterId), createdAt: r.createdAt });
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Social: accept / reject / block
app.post("/api/social/requests/:id/accept", authMiddleware, async (req, res) => {
  try {
    const connId = __cleanId(req.params.id, 64);
    if (!connId) return res.status(400).json({ message: "Invalid requestId" });
    const c = await Connection.findById(connId);
    if (!c) return res.status(404).json({ message: "Not found" });
    if (String(c.addresseeId) !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" });
    if (c.status !== "pending") return res.status(400).json({ message: "Not pending" });

    c.status = "accepted";
    c.respondedAt = new Date();
    await c.save();
    return res.json({ status: "accepted" });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/social/requests/:id/reject", authMiddleware, async (req, res) => {
  try {
    const connId = __cleanId(req.params.id, 64);
    if (!connId) return res.status(400).json({ message: "Invalid requestId" });
    const c = await Connection.findById(connId);
    if (!c) return res.status(404).json({ message: "Not found" });
    if (String(c.addresseeId) !== String(req.user._id)) return res.status(403).json({ message: "Unauthorized" });
    if (c.status !== "pending") return res.status(400).json({ message: "Not pending" });

    c.status = "rejected";
    c.respondedAt = new Date();
    await c.save();
    return res.json({ status: "rejected" });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/social/requests/:id/block", authMiddleware, async (req, res) => {
  try {
    const connId = __cleanId(req.params.id, 64);
    if (!connId) return res.status(400).json({ message: "Invalid requestId" });
    const c = await Connection.findById(connId);
    if (!c) return res.status(404).json({ message: "Not found" });

    const me = String(req.user._id);
    if (String(c.addresseeId) !== me && String(c.requesterId) !== me) return res.status(403).json({ message: "Unauthorized" });

    c.status = "blocked";
    c.respondedAt = new Date();
    await c.save();
    return res.json({ status: "blocked" });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Social: list accepted connections
app.get("/api/social/connections", authMiddleware, async (req, res) => {
  try {
    const me = req.user._id;
    const conns = await Connection.find({
      status: "accepted",
      $or: [{ requesterId: me }, { addresseeId: me }],
    }).sort({ respondedAt: -1 });

    const out = [];
    for (const c of conns) {
      const otherId = String(c.requesterId) === String(me) ? c.addresseeId : c.requesterId;
      out.push({ _id: c._id, user: await minimalUserCard(otherId) });
    }
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Social: friends feed (opt-in)
app.get("/api/social/feed", authMiddleware, async (req, res) => {
  try {
    const me = req.user._id;

    const conns = await Connection.find({
      status: "accepted",
      $or: [{ requesterId: me }, { addresseeId: me }],
    });

    const friendIds = conns.map((c) => (String(c.requesterId) === String(me) ? c.addresseeId : c.requesterId));
    if (friendIds.length === 0) return res.json([]);

    const allowedUsers = await User.find({ _id: { $in: friendIds }, showExperiencesToFriends: true }).select("_id");
    const allowedFriendIds = allowedUsers.map((u) => u._id);
    if (allowedFriendIds.length === 0) return res.json([]);

    const bookings = await Booking.find({
      guestId: { $in: allowedFriendIds },
      visibilityToFriends: true,
      $or: [{ status: "confirmed" }, { paymentStatus: "paid" }],
    })
      .sort({ createdAt: -1 })
      .limit(30)
      .populate("experience", "title images imageUrl city")
      .populate("guestId", "name profilePic handle publicProfile");

    const out = bookings.map((b) => ({
      _id: b._id,
      when: b.bookingDate,
      timeSlot: b.timeSlot,
      guest: b.guestId
        ? {
            _id: b.guestId._id,
            name: b.guestId.name,
            profilePic: b.guestId.publicProfile ? (b.guestId.profilePic || "") : "",
            handle: b.guestId.handle || "",
          }
        : null,
      experience: b.experience
        ? {
            _id: b.experience._id,
            title: b.experience.title,
            city: b.experience.city,
            imageUrl: b.experience.imageUrl || (Array.isArray(b.experience.images) ? b.experience.images[0] : ""),
          }
        : { _id: b.experienceId },
    }));

    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ Friend-circle history endpoint (privacy gates)
app.get("/api/social/user/:userId/visible-bookings", authMiddleware, async (req, res) => {
  try {
    const me = String(req.user._id);
    const other = __cleanId(req.params.userId, 64);
    if (!other) return res.status(400).json({ message: "Invalid userId" });
    if (!other) return res.status(400).json({ message: "userId required" });
    if (me === other) return res.status(400).json({ message: "Use your bookings endpoint" });

    const target = await User.findById(other);
    if (!target) return res.status(404).json({ message: "User not found" });
    if (!target.showExperiencesToFriends) return res.json([]);

    const conn = await Connection.findOne({
      status: "accepted",
      $or: [
        { requesterId: me, addresseeId: other },
        { requesterId: other, addresseeId: me },
      ],
    });
    if (!conn) return res.status(403).json({ message: "Not allowed" });

    const bookings = await Booking.find({
      guestId: other,
      visibilityToFriends: true,
      $or: [{ status: "confirmed" }, { paymentStatus: "paid" }],
    })
      .sort({ bookingDate: -1 })
      .limit(50)
      .populate("experience", "title images imageUrl city");

    const out = bookings.map((b) => ({
      _id: b._id,
      when: b.bookingDate,
      timeSlot: b.timeSlot,
      experience: b.experience
        ? {
            _id: b.experience._id,
            title: b.experience.title,
            city: b.experience.city,
            imageUrl: b.experience.imageUrl || (Array.isArray(b.experience.images) ? b.experience.images[0] : ""),
          }
        : { _id: b.experienceId },
    }));

    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Admin stats
app.get("/api/admin/stats", adminMiddleware, async (req, res) => {
  const revenueDocs = await Booking.find({ status: "confirmed" }, "pricing");
  res.json({
    userCount: await User.countDocuments(),
    expCount: await Experience.countDocuments(),
    bookingCount: await Booking.countDocuments(),
    totalRevenue: revenueDocs.reduce((acc, b) => acc + (b.pricing && b.pricing.totalPrice ? b.pricing.totalPrice : 0), 0),
  });
});

// Admin bookings
app.get("/api/admin/bookings", adminMiddleware, async (req, res) => {
  try {
    const bookings = await Booking.find()
      .populate("experience")
      .populate({ path: "user", select: "-password -email" })
      .sort({ createdAt: -1 })
      .limit(50);

    const out = (bookings || []).map((b) => {
      const o = (b && typeof b.toObject === "function")
        ? b.toObject({ virtuals: true })
        : (b || {});
      if (o && typeof o === "object") delete o.guestEmail;
      if (o && o.user && typeof o.user === "object") o.user = adminSafeUser(o.user);
      return o;
    });

    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Recommendations
app.get("/api/recommendations", authMiddleware, async (req, res) => {
  const exps = await Experience.find({ isPaused: false }).sort({ averageRating: -1 }).limit(4);
  if (exps.length > 0) return res.json(exps);
  const fallback = await Experience.find({ isPaused: false }).limit(4);
  res.json(fallback);
});

// Admin users
app.get("/api/admin/users", adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    return res.json((users || []).map(u => adminSafeUser(u)));
  } catch (err) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/admin/users/:id", adminMiddleware, async (req, res) => {
  try {
    const userIdParam = __cleanId(req.params.id, 64);
    if (!userIdParam) return res.status(400).json({ message: "Invalid userId" });
    await User.findByIdAndDelete(userIdParam);
    res.json({ message: "User banned/deleted." });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/admin/experiences", adminMiddleware, async (req, res) => {
  try {
    const exps = await Experience.find().sort({ createdAt: -1 });
    res.json(exps);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/api/admin/experiences/:id/toggle", adminMiddleware, async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const exp = await Experience.findById(expId);
    if (!exp) return res.status(404).json({ message: "Not found" });
    exp.isPaused = !exp.isPaused;
    await exp.save();
    res.json(exp);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/users/:userId/profile", async (req, res) => {
  try {
    const userIdParam = __cleanId(req.params.userId, 64);
    if (!userIdParam) return res.status(400).json({ message: "Invalid userId" });
    const user = await User.findById(userIdParam)
      .select("name profilePic bio handle publicProfile createdAt")
      .lean();

    if (!user) return res.status(404).json({ message: "User not found." });

    const isHostProfile = await isHost(user._id);

    // Guests must opt-in; hosts are always viewable (trust model)
    if (!isHostProfile && !user.publicProfile) {
      return res.status(403).json({ message: "Profile is private." });
    }

    let experiences = [];
    let reviews = [];
    let hostRating = 0;
    let hostReviewCount = 0;

    if (isHostProfile) {
      experiences = await Experience.find({
        hostId: String(user._id),
        isPaused: false
      }).sort({ averageRating: -1, createdAt: -1 });

      const expIds = experiences.map(e => String(e._id));

      reviews = await Review.find({
        experienceId: { $in: expIds },
        type: "guest_to_host"
      }).sort({ date: -1 }).limit(10);

      hostReviewCount = reviews.length;

      const rated = experiences.filter(e => Number(e.averageRating) > 0);
      if (rated.length > 0) {
        hostRating = rated.reduce((s, e) => s + Number(e.averageRating || 0), 0) / rated.length;
      }
    }

    return res.json({
      user: publicUserCardFromDoc(user),
      isHost: isHostProfile,
      experiences: (experiences || []).map(e => stripExperiencePrivateFields((e && typeof e.toObject === "function") ? e.toObject() : e)),
      reviews,
      hostStats: { rating: hostRating, reviewCount: hostReviewCount }
    });

  } catch (err) {
    return res.status(500).json({ message: "Server error fetching profile." });
  }
});

// UNPAID_BOOKING_EXPIRY_CLEANUP_V1

// ===== PAYMENT RECONCILIATION (Stripe -> DB) =====
// Periodically reconciles recent pending payments so bookings do not get stuck.
async function runPaymentReconciliationOnce_V1() {
  const BookingModel = mongoose.model("Booking");

  const now = new Date();
  const since = new Date(Date.now() - 1000 * 60 * 60 * 48); // 48h window
  const q = {
    createdAt: { $gte: since },
    stripeSessionId: { $exists: true, $ne: "" },
    $and: [
      { paymentStatus: { $ne: "paid" } },
      { status: { $ne: "confirmed" } },
    ],
  };
  const batch = await Booking.find(q).sort({ createdAt: -1 }).limit(40);
  for (const booking of batch) {
    try {
      const sid = String(booking.stripeSessionId || "");
      if (!sid) continue;
      const session = await stripe.checkout.sessions.retrieve(sid, { expand: ["payment_intent"] });
      const stripeStatus = String(session.payment_status || "unknown");
      const piStatus = String((session.payment_intent && session.payment_intent.status) ? session.payment_intent.status : "");
      const sessionStatus = String(session.status || "");
      booking.paymentLastStripeStatus = stripeStatus;
      booking.paymentLastPiStatus = piStatus;
      if (session.payment_intent) booking.stripePaymentIntentId = String(session.payment_intent.id || session.payment_intent);
      const outcome = __classifyPaymentOutcome(stripeStatus, piStatus, sessionStatus);
      const cur = String(booking.paymentStatus || "unpaid");
      if (cur !== outcome) {
        booking.paymentStatus = outcome;
        if (outcome === "paid") booking.paidAt = booking.paidAt || now;
      }
      await booking.save();
    } catch (_) {
    }
  }
}

function startPaymentReconciliationLoop_V1() {
  if (!__shouldRunJobs()) { __log("info", "jobs_skipped_disabled", { job: "payment_reconciliation_v1", reason: "RUN_JOBS disabled" }); return; }
  if (global.__tsts_payment_recon_started_v1 === true) return;
  global.__tsts_payment_recon_started_v1 = true;
  try { __log("info", "job_runner_started", { job: "payment_reconciliation_v1" }); } catch (_) {}
  setTimeout(() => { runPaymentReconciliationOnce_V1().catch(() => {}); }, 30 * 1000);
  setInterval(() => { runPaymentReconciliationOnce_V1().catch(() => {}); }, 10 * 60 * 1000);
}

// Expires unpaid bookings and releases reserved capacity (idempotent + race-safe).
async function runUnpaidBookingExpiryCleanupOnce_V1() {
  try {
    const now = new Date();

    const LTE = String.fromCharCode(36) + "lte";
    const SET = String.fromCharCode(36) + "set";

    const q = {
      status: "pending_payment",
      paymentStatus: "unpaid",
      expiresAt: (function(){ const x={}; x[LTE]=now; return x; })(),
    };

    const expired = await Booking.find(q)
      .select("_id experienceId bookingDate timeSlot numGuests")
      .lean();

    if (Array.isArray(expired) == false) return;

    for (const b of expired) {
      const upd = {};
      upd[SET] = { status: "expired", paymentStatus: "unpaid", expiredAt: now };

      const r = await Booking.updateOne(
        { _id: b._id, status: "pending_payment", paymentStatus: "unpaid" },
        upd
      );

      const didExpire = Boolean(r && (Number(r.modifiedCount) > 0 || Number(r.nModified) > 0));
      if (didExpire) {
        try {
          const expId = String(b.experienceId || "");
          const dateStr = String(b.bookingDate || "");
          const slot = String(b.timeSlot || "");
          const g = Number.parseInt(String(b.numGuests || "0"), 10) || 0;

          const ok = Boolean(expId.length > 0 && dateStr.length > 0 && slot.length > 0 && g > 0);
          if (ok) {
            await releaseCapacitySlot(expId, dateStr, slot, g);
            try {
              const bookingDoc = await Booking.findById(String(b._id || ""));
              if (bookingDoc) await maybeSendBookingExpiredComms(bookingDoc);
            } catch (_) {}

          }
        } catch (_) {}
      }
    }
  } catch (_) {}
}

function startUnpaidBookingExpiryCleanupLoop_V1() {
  if (!__shouldRunJobs()) { __log("info", "jobs_skipped_disabled", { job: "unpaid_booking_expiry_cleanup_v1", reason: "RUN_JOBS disabled" }); return; }

  if (global.__tsts_unpaid_cleanup_started_v1 === true) return;
  global.__tsts_unpaid_cleanup_started_v1 = true;

  try {
    startJobs((level, msg, meta) => {
      try { __log(level, msg, meta || {}); } catch (_) {}
    });

    setTimeout(() => {
      runUnpaidBookingExpiryCleanupOnce_V1().catch(() => {});
    }, 10 * 1000);

    registerInterval(
      "unpaid_booking_expiry_cleanup_v1",
      () => runUnpaidBookingExpiryCleanupOnce_V1(),
      60 * 1000
    );
  } catch (e) {
    setTimeout(() => { runUnpaidBookingExpiryCleanupOnce_V1().catch(() => {}); }, 10 * 1000);
    setInterval(() => { runUnpaidBookingExpiryCleanupOnce_V1().catch(() => {}); }, 60 * 1000);
  }
}

// Start unpaid expiry cleanup loop (safe + idempotent)
// startUnpaidBookingExpiryCleanupLoop_V1(); // moved to db_connected






// Health check (production-safe)


// TSTS_VERSION_ENDPOINT
app.get("/version", (req, res) => {
  const sha =
    String(process.env.RENDER_GIT_COMMIT || "") ||
    String(process.env.GIT_SHA || "") ||
    String(process.env.COMMIT_SHA || "") ||
    "unknown";
  return res.json({ service: "shared-table-api", sha });
});



// INTERNAL_JOBS_ENDPOINT_TSTS (Batch6 D1)
// Trigger idempotent job runs via scheduler (Render Cron / trusted caller).
// Security: requires env INTERNAL_JOBS_TOKEN and header X-Internal-Token to match.
// Note: This endpoint runs functions that are already safe/idempotent by design.
app.post("/api/internal/jobs/run", async (req, res) => {

  // Guard 1: do not run until DB is ready
  if (typeof __dbReady !== "undefined" && __dbReady !== true) {
    try { __log("error", "internal_jobs_db_not_ready", { rid: undefined, path: "/api/internal/jobs/run" }); } catch (_) {}
    return res.status(503).json({ ok: false, error: "DB_NOT_READY" });
  }

  const expected = String(process.env.INTERNAL_JOBS_TOKEN || "").trim();
  if (expected.length === 0) {
    try { __log("error", "internal_jobs_token_missing", { rid: undefined, path: "/api/internal/jobs/run" }); } catch (_) {}
    return res.status(503).json({ ok: false, error: "INTERNAL_JOBS_TOKEN_MISSING" });
  }

  const got = String(
    (req && req.headers && (req.headers["x-internal-token"] || req.headers["X-Internal-Token"])) || ""
  ).trim();

  if (got.length === 0 || got !== expected) {
    try { __log("error", "internal_jobs_unauthorized", { rid: undefined, path: "/api/internal/jobs/run" }); } catch (_) {}
    return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
  }

  // Guard 2: prevent overlapping runs in this process (set after auth)
  try {
    if (global && global.__tsts_internal_jobs_running === true) {
      try { __log("error", "internal_jobs_busy", { rid: undefined, path: "/api/internal/jobs/run" }); } catch (_) {}
      return res.status(409).json({ ok: false, error: "BUSY" });
    }
    if (global) global.__tsts_internal_jobs_running = true;
  } catch (_) {}

  try {
    const ran = [];
    const errors = [];

    // Respond immediately so cron callers never time out.
    const queued = ["unpaid_booking_expiry_cleanup_v1", "payment_reconciliation_v1"];
    try {
      res.status(202).json({ ok: true, accepted: true, queued: queued });
    } catch (_) {}

    // Fire-and-forget background run; results go to logs.
    setTimeout(async () => {
      const ran = [];
      const errors = [];

      try {
        await runUnpaidBookingExpiryCleanupOnce_V1();
        ran.push("unpaid_booking_expiry_cleanup_v1");
      } catch (e) {
        const msg = (e && e.message) ? String(e.message) : String(e);
        errors.push({ job: "unpaid_booking_expiry_cleanup_v1", error: msg });
      }

      try {
        await runPaymentReconciliationOnce_V1();
        ran.push("payment_reconciliation_v1");
      } catch (e) {
        const msg = (e && e.message) ? String(e.message) : String(e);
        errors.push({ job: "payment_reconciliation_v1", error: msg });
      }

      const ok = errors.length == 0;
      try {
        __log(ok ? "info" : "error",
          ok ? "internal_jobs_async_ok" : "internal_jobs_async_fail",
          { rid: undefined, path: "/api/internal/jobs/run", ran: ran, errors: errors }
        );
      } catch (_) {}
    }, 0);

    return;

  } finally {
    try { if (global) global.__tsts_internal_jobs_running = false; } catch (_) {}
  }
});



// STARTUP: do not accept traffic until DB is ready (avoid mongoose buffering dead-hangs)
async function __startServerAfterDb() {
  try {
    // Wait for mongoose connection to be readyState=1
    const t0 = Date.now();
    while (!(global && global.__tsts_db_connected === true)) {
      if (Date.now() - t0 > 30000) {
        console.error("STARTUP_DB_TIMEOUT");
        process.exit(1);
      }
      await new Promise((r) => setTimeout(r, 100));
    }

    // Start job loops only after DB is ready
    // jobs start after db_connected



  } catch (e) {
    console.error("STARTUP_FATAL", (e && e.message) ? e.message : String(e));
    process.exit(1);
  }
}

app.get("/health", (req, res) => res.status(200).json({ ok: true, dbReady: __dbReady }));
app.get("/ready", (req, res) => (__dbReady ? res.status(200).json({ ok: true }) : res.status(503).json({ ok: false })));



let __httpServerStarted = false;
function __startHttpServerOnce() {
  if (__httpServerStarted) return;
  __httpServerStarted = true;
      app.listen(PORT, () => {
        try { __log("info", "server_listen", { rid: undefined, path: undefined }); } catch (_) {}
      });
}
__startHttpServerOnce();

__startServerAfterDb();

// ===== BOOKING STATE TRANSITIONS =====
// Single canonical transition handler.
// Ensures timestamps + comms are always in sync.

async function transitionBooking(booking, nextStatus, meta = {}) {
  const now = new Date();

  if (!booking || !nextStatus) return booking;

  if (booking.status === nextStatus) return booking;

  const updates = {
    status: nextStatus,
    updatedAt: now
  };

  if (nextStatus === "confirmed") {
    updates.guestConfirmedAt = booking.guestConfirmedAt || now;
  }

  if (nextStatus === "cancelled") {
    updates.guestCancelledAt = booking.guestCancelledAt || now;
  }
  if (nextStatus === "cancelled_by_host") {
    updates.hostCancelledAt = booking.hostCancelledAt || now;
  }

  if (nextStatus === "expired") {
    updates.expiredAt = booking.expiredAt || now;
  }
  if (nextStatus === "refunded") {
    updates.refundedAt = booking.refundedAt || now;
  }

  // Keep in-memory doc consistent with persisted transition
  try {
    Object.assign(booking, updates);
  } catch (_) {}

  await booking.updateOne({ $set: updates });

  // fire-and-forget comms (must not block state)
  // meta.suppressComms=true allows internal transitions without email noise
  if (!(meta && meta.suppressComms === true)) {
    try {
      if (nextStatus === "confirmed") {
        await maybeSendBookingConfirmedComms(booking);
      }
      if (nextStatus === "cancelled") {
        await maybeSendBookingCancelledComms(booking);
      }
      if (nextStatus === "expired") {
        await maybeSendBookingExpiredComms(booking);
      }
      if (nextStatus === "cancelled_by_host") {
        await maybeSendBookingCancelledByHostComms(booking);
      }
      if (nextStatus === "refunded") {
        await maybeSendRefundProcessedComms(booking);
      }
    } catch (e) {
      console.error("BOOKING_COMMS_FAIL", booking._id, nextStatus, e?.message);
    }
  }

  return booking;
}


