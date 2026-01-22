
// server.js - FULL VERSION (Privacy-first attendee discovery + Like/Comment + Public profile hardening)

require("dotenv").config();


function __tstsLogEarly(level, event, meta) {
  try {
    const payload = { level: String(level || "info"), event: String(event || "event"), meta: meta || {}, ts: new Date().toISOString() };
    process.stderr.write(JSON.stringify(payload) + "\n");
  } catch (_) {}
}


// TSTS_ENV_VALIDATION (Batch0 L0-6) — fail-fast in production, warn in dev
function __tstsValidateEnv() {
  // NODE_ENV contract:
  // - If explicitly provided, honor it (must be one of allowed).
  // - If missing/blank, infer:
  //   - Render => production
  //   - otherwise => development
  const raw = String(process.env.NODE_ENV || "").trim().toLowerCase();

  const isRender =
    String(process.env.RENDER || "").trim().length > 0 ||
    String(process.env.RENDER_SERVICE_ID || "").trim().length > 0 ||
    String(process.env.RENDER_INSTANCE_ID || "").trim().length > 0;

  const env = raw.length > 0 ? raw : (isRender ? "production" : "development");

  const isProd = env === "production";
  const allowed = new Set(["production", "development", "test", "staging", "preview"]);
  if (!allowed.has(env)) {
    throw new Error("ENV_INVALID_NODE_ENV: " + env);
  }

  if (raw.length === 0) {
    try { __tstsLogEarly("warn", "env_node_env_missing_inferred", { env: env }); } catch (_) {}
  }

  const requiredProd = [
    "JWT_SECRET",
    "MONGO_URI",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "FRONTEND_BASE_URL",
  ];

  const missing = [];
  for (const k of requiredProd) {
    const v = String(process.env[k] || "").trim();
    if (!v) missing.push(k);
  }

  if (isProd) {
    if (missing.length) {
      throw new Error("ENV_MISSING_REQUIRED: " + missing.join(","));
    }
  } else {
    if (missing.length) {
      try { __tstsLogEarly("warn", "env_missing_dev_allowed", { missing: missing }); } catch (_) {}
    }
  }

  if (isProd) {
    const corsRaw = String(process.env.CORS_ORIGINS || "").toLowerCase();
    if (corsRaw.includes("localhost") || corsRaw.includes("127.0.0.1")) {
      throw new Error("ENV_INVALID_CORS_ORIGINS_LOCALHOST_IN_PROD");
    }
  }
}

try {
  __tstsValidateEnv();
} catch (e) {
  try { __tstsLogEarly("error", "boot_env_validation_failed", { message: (e && e.message) ? String(e.message) : String(e) }); } catch (_) {}
  process.exit(1);
}

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

// === EMAIL_DELIVERY_LEDGER_V1 ===
const EmailDeliverySchema = new mongoose.Schema({
  bookingId: { type: String, index: true },
  email: { type: String, index: true },
  template: { type: String, index: true },
  state: { type: String },
  providerMessageId: { type: String },
  error: { type: String },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

EmailDeliverySchema.index(
  { bookingId: 1, template: 1 },
  { unique: true }
);

const EmailDelivery = mongoose.model("EmailDelivery", EmailDeliverySchema);

const EmailSuppressionSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  reason: { type: String },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const EmailSuppression = mongoose.model("EmailSuppression", EmailSuppressionSchema);
// === END EMAIL_DELIVERY_LEDGER_V1 ===


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

const stripe = require("stripe")(String(process.env.STRIPE_SECRET_KEY || "").trim());
const pricing = require("./pricing");
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
          try { __log("error", "email_async_err", { rid: __tstsRidNow(), msg: String(msg) }); } catch (_) {}
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      });
    }
  } catch (e) {
    try {
      const msg = (e && e.message) ? e.message : String(e);
      try { __log("error", "email_dispatch_err", { rid: __tstsRidNow(), msg: String(msg) }); } catch (_) {}
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  }
}

const bcrypt = require("bcryptjs");
const { ipKeyGenerator } = require("express-rate-limit");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { AsyncLocalStorage } = require("async_hooks");
const __als = new AsyncLocalStorage();

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
  statusCode: { type: Number, default: null },
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

// ADMIN_AUDIT_TRAIL_TSTS (Batch6 E1)
// Who + why + when + what (privacy-preserving).
// reason is optional; can come from header x-admin-reason or body.reason
const adminAuditSchema = new mongoose.Schema({
  createdAt: { type: Date, default: Date.now },
  actorId: { type: String, default: "" },
  actorMasked: { type: String, default: "" },
  actorHash: { type: String, default: "" },
  isAdmin: { type: Boolean, default: false },
  action: { type: String, default: "" },
  method: { type: String, default: "" },
  path: { type: String, default: "" },
  targetType: { type: String, default: "" },
  targetId: { type: String, default: "" },
  reason: { type: String, default: "" },
  ok: { type: Boolean, default: true },
  error: { type: String, default: "" },
  meta: { type: Object, default: {} }
}, { minimize: false });
adminAuditSchema.index({ createdAt: -1 });
adminAuditSchema.index({ actorId: 1, createdAt: -1 });
adminAuditSchema.index({ action: 1, createdAt: -1 });

const AdminAudit = mongoose.models.AdminAudit || mongoose.model("AdminAudit", adminAuditSchema);

const reportSchema = new mongoose.Schema({
  createdAt: { type: Date, default: Date.now },

  reporterId: { type: String, default: "" },
  reporterMasked: { type: String, default: "" },
  reporterHash: { type: String, default: "" },

  targetType: { type: String, default: "" }, // user|experience|booking|review|comment
  targetId: { type: String, default: "" },

  category: { type: String, default: "" }, // spam|harassment|fraud|safety|other
  message: { type: String, default: "" },

  status: { type: String, default: "open" }, // open|triaged|actioned|closed
  adminActorId: { type: String, default: "" },
  adminReason: { type: String, default: "" },
  adminAction: { type: String, default: "" }, // none|mute_user|delete_user|pause_experience
  adminMeta: { type: Object, default: {} },

  resolvedAt: { type: Date, default: null }
}, { minimize: false });

reportSchema.index({ createdAt: -1 });
reportSchema.index({ status: 1, createdAt: -1 });
reportSchema.index({ targetType: 1, targetId: 1, createdAt: -1 });
reportSchema.index({ reporterId: 1, createdAt: -1 });

const Report = mongoose.models.Report || mongoose.model("Report", reportSchema);


function __adminReason(req) {
  try {
    const h = (req && req.headers) ? req.headers : {};
    const v = (h && (h["x-admin-reason"] || h["X-Admin-Reason"])) ? String(h["x-admin-reason"] || h["X-Admin-Reason"]) : "";
    if (v && v.trim()) return v.trim().slice(0, 240);
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  return "";
}

async function __auditAdmin(req, action, meta, outcome) {
  try {
    const u = (req && req.user) ? req.user : null;
    const actorId = u && (u._id || u.id) ? String(u._id || u.id) : "";
    const email = u && u.email ? String(u.email) : "";
    const actorMasked = (typeof __maskEmail === "function") ? __maskEmail(email) : "";
    const actorHash = (typeof __hashEmail === "function") ? __hashEmail(email) : "";
    const isAdmin = !!(u && (u.isAdmin || u.admin === true));

    const out = (outcome && typeof outcome === "object") ? outcome : {};
    const ok = (out.ok === false) ? false : true;
    const err = out.error ? String(out.error) : "";

    const m = (meta && typeof meta === "object") ? meta : {};
    const targetType = m.targetType ? String(m.targetType) : "";
    const targetId = m.targetId ? String(m.targetId) : "";

    const path = (req && (req.originalUrl || req.path)) ? String(req.originalUrl || req.path) : "";
    const method = (req && req.method) ? String(req.method) : "";
    const reason = __adminReason(req);

    await AdminAudit.create({
      actorId: actorId,
      actorMasked: actorMasked,
      actorHash: actorHash,
      isAdmin: isAdmin,
      action: String(action || ""),
      method: method,
      path: path,
      targetType: targetType,
      targetId: targetId,
      reason: reason,
      ok: ok,
      error: err.slice(0, 800),
      meta: m
    });
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
}


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

  async function __sendEventEmailTracked(payload, meta) {
  const p = payload || {};
  const m = meta || {};

  const toRaw =
    (p && (p.to || p.email || p.recipient)) ||
    (m && (m.to || m.email || m.recipient)) ||
    "";
  const to = String(toRaw || "").toLowerCase().trim();

  const bookingIdRaw =
    (m && (m.bookingId || m.BOOKING_ID)) ||
    (p && (p.bookingId || p.BOOKING_ID)) ||
    "";
  const bookingId = String(bookingIdRaw || "").trim();

  const templateRaw =
    (m && (m.template || m.eventName || m.type)) ||
    (p && (p.template || p.eventName || p.type)) ||
    "EVENT_EMAIL";
  const template = String(templateRaw || "EVENT_EMAIL").trim();

  const enforceLedger = (bookingId.length > 0 && to.length > 0);

  // Suppression precheck
  if (to.length > 0) {
    try {
      const sup = await EmailSuppression.findOne({ email: to }).lean();
      if (sup) {
        if (enforceLedger) {
          try {
            await EmailDelivery.create({
              bookingId,
              email: to,
              template,
              state: "suppressed",
              providerMessageId: "",
              error: String((sup && sup.reason) || "suppressed")
            });
          } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
        }
        __log("info", "email_suppressed_skip", { bookingId: bookingId || undefined, template, to });
        return false;
      }
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  }

  // Exactly-once gate (bookingId+template unique index)
  if (enforceLedger) {
    try {
      await EmailDelivery.create({
        bookingId,
        email: to,
        template,
        state: "queued",
        providerMessageId: "",
        error: ""
      });
    } catch (err) {
      const msg = (err && err.message) ? String(err.message) : "";
      const dup = msg.toLowerCase().indexOf("duplicate") >= 0 || msg.indexOf("E11000") >= 0;
      if (dup) {
        __log("info", "email_idempotent_skip", { bookingId, template, to });
        return true;
      }
      __log("error", "email_ledger_create_failed", { bookingId, template, to, err: msg });
    }
  }

  const subject = String(p.subject || "");
  const html = (typeof p.html !== "undefined") ? p.html : undefined;
  const text = (typeof p.text !== "undefined") ? p.text : undefined;

  const r = await sendEmailWithInfo({ to, subject, html, text });

  if (enforceLedger) {
    try {
      const upd = {
        state: (r && r.ok === true) ? "sent" : "failed",
        providerMessageId: String((r && r.providerMessageId) || ""),
        error: String((r && r.error) || "")
      };
      await EmailDelivery.updateOne({ bookingId, template }, { $set: upd });
    } catch (err) {
      const msg = (err && err.message) ? String(err.message) : "ledger_update_failed";
      __log("error", "email_ledger_update_failed", { bookingId, template, to, err: msg });
    }
  }

  if (!(r && r.ok === true)) {
    __log("error", "email_delivery_failed", { bookingId: bookingId || undefined, template, to, err: String((r && r.error) || "") });
  }

  return (r && r.ok === true);
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


// TRUST_PROXY_TSTS
app.set("trust proxy", 1);
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
    let rid;
    try {
      const st = (__als && typeof __als.getStore === "function") ? __als.getStore() : undefined;
      const r = (st && st.rid) ? String(st.rid) : "";
      if (r && r.trim()) rid = r.trim();
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    try {
      if (rid && (m.rid == null)) m.rid = rid;
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    const payload = { ts: new Date().toISOString(), level: lvl, event: ev };
    if (rid) payload.rid = rid;
    payload.meta = __redact(m, 0);
    if (__winstonLogger) {
      const fn = (__winstonLogger[lvl] && typeof __winstonLogger[lvl] === "function") ? __winstonLogger[lvl] : __winstonLogger.info;
      fn.call(__winstonLogger, payload);
      return;
    }
    const line = JSON.stringify(payload);
    if (lvl === "error") {
      try { process.stderr.write(String(line) + "\n"); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      return;
    }
    return;
  } catch (_) {
    try { process.stderr.write("LOG_FAIL\n"); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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

// BE-YELLOW-01: Structured error helper for consistent error responses
function __err(res, code, status, err, meta) {
  try {
    const rid = __tstsRidNow();
    const statusCode = Number.isFinite(Number(status)) ? Number(status) : 500;
    const errorCode = String(code || "SERVER_ERROR").toUpperCase();
    const errMsg = (err && err.message) ? String(err.message) : (typeof err === "string" ? err : "");
    __log("error", errorCode.toLowerCase(), { rid, code: errorCode, status: statusCode, error: errMsg, ...(meta || {}) });
    return res.status(statusCode).json({ ok: false, error: errorCode, code: errorCode, message: errMsg || "Server error", rid });
  } catch (_) {
    return res.status(500).json({ ok: false, error: "SERVER_ERROR", code: "SERVER_ERROR", message: "Server error" });
  }
}

function __tstsCodeFromStatus(statusCode) {
  const sc = Number(statusCode || 0);
  if (sc === 400) return "BAD_REQUEST";
  if (sc === 401) return "UNAUTHORIZED";
  if (sc === 403) return "FORBIDDEN";
  if (sc === 404) return "NOT_FOUND";
  if (sc === 409) return "CONFLICT";
  if (sc === 413) return "PAYLOAD_TOO_LARGE";
  if (sc === 429) return "RATE_LIMITED";
  if (sc >= 500) return "SERVER_ERROR";
  return "ERROR";
}

function __tstsNormalizeErrorPayload(payload, rid, statusCode) {
  const sc = Number(statusCode || 0);
  const r = rid || undefined;
  if (payload == null) return { ok: false, code: __tstsCodeFromStatus(sc), message: "Error", rid: r };
  if (typeof payload === "string") return { ok: false, code: __tstsCodeFromStatus(sc), message: String(payload), rid: r };
  if (typeof payload !== "object") return { ok: false, code: __tstsCodeFromStatus(sc), message: "Error", rid: r };
  const out = Object.assign({}, payload);
  out.ok = false;
  if (!out.code) out.code = __tstsCodeFromStatus(sc);
  if (!out.message) out.message = (out.error && typeof out.error === "string") ? out.error : "Error";
  if (!out.rid) out.rid = r;
  return out;
}

function __tstsWrapResJson(req, res, next) {
  try {
    const orig = res.json.bind(res);
    res.json = function(payload) {
      try {
        const rid = (__ridFromReq(req) || req.requestId || req.rid || __tstsRidNow());
        const sc = Number(res.statusCode || 200);
        const looksError = (sc >= 400) || (payload && typeof payload === "object" && (payload.ok === false || payload.error || payload.message));
        if (looksError) {
          const normalized = __tstsNormalizeErrorPayload(payload, rid, sc);
          try { if (rid && !res.getHeader("X-Request-Id")) res.setHeader("X-Request-Id", String(rid)); } catch (_) {}
          return orig(normalized);
        }
        try { if (rid && !res.getHeader("X-Request-Id")) res.setHeader("X-Request-Id", String(rid)); } catch (_) {}
        return orig(payload);
      } catch (_) {
        return orig(payload);
      }
    };
  } catch (_) {}
  return next();
}

app.use(__tstsWrapResJson);

// attach requestId + access logs

// L11_HEALTH_READY_BASELINE_V2
// Core liveness/readiness routes must be defined early so they are never intercepted by auth/admin gates or 404 middleware.
function __tstsDbReadyNow() {
  try {
    if (typeof global !== "undefined" && global && global.__tsts_db_connected === true) return true;
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  try {
    if (typeof mongoose !== "undefined" && mongoose && mongoose.connection) return (mongoose.connection.readyState === 1);
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  return false;
}
function __tstsRidNow() {
  try {
    const c = require("crypto");
    return c.randomBytes(12).toString("hex");
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  try {
    return (Date.now().toString(16) + Math.random().toString(16).slice(2)).slice(0, 24);
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  return "";
}
app.get("/health", (req, res) => {
  const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
  try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  return res.status(200).json({ ok: true, dbReady: __tstsDbReadyNow(), rid: rid });
});
app.get("/ready", (req, res) => {
  const dbReady = __tstsDbReadyNow();
  const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
  try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  return dbReady ? res.status(200).json({ ok: true, dbReady: true, rid: rid }) : res.status(503).json({ ok: false, dbReady: false, rid: rid });
});

app.use((req, res, next) => {
  const rid = __rid();
  req.requestId = rid;
  try { res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  // Ensure all downstream logs can be correlated (async-safe)
  return __als.run({ rid: rid }, () => {
    // JSON response shim: always include rid + stable code for errors
    try {
      const __origJson = res.json.bind(res);

      const __origSend = res.send.bind(res);
      res.send = (payload) => {
        try {
          const statusCode = (typeof res.statusCode === "number") ? res.statusCode : 200;
          const isString = (typeof payload === "string");
          if (isString && statusCode >= 400) {
            return res.json({ message: String(payload || "Error") });
          }
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
        return __origSend(payload);
      };

      res.json = (payload) => {
        try {
          const statusCode = (typeof res.statusCode === "number") ? res.statusCode : 200;
          const isObj = (payload !== null) && (typeof payload === "object") && (Array.isArray(payload) === false);
          if (isObj) {
            if (payload.rid == null) payload.rid = rid;
            if (statusCode >= 400 && payload.code == null) {
              let code = "ERROR";
              if (statusCode === 400) code = "BAD_REQUEST";
              else if (statusCode === 401) code = "UNAUTHENTICATED";
              else if (statusCode === 403) code = "FORBIDDEN";
              else if (statusCode === 404) code = "NOT_FOUND";
              else if (statusCode === 409) code = "CONFLICT";
              else if (statusCode === 413) code = "PAYLOAD_TOO_LARGE";
              else if (statusCode === 415) code = "UNSUPPORTED_MEDIA_TYPE";
              else if (statusCode === 429) code = "RATE_LIMITED";
              else if (statusCode >= 500) code = "SERVER_ERROR";
              payload.code = code;
            }
          }
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
        return __origJson(payload);
      };
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    const start = Date.now();
    res.on("finish", () => {
      __log("info", "http_access", {
        rid: rid,
        method: req.method,
        path: String(req.originalUrl || "").split("?")[0],
        status: res.statusCode,
        durationMs: Date.now() - start,
        ip: req.ip
      });
    });

    return next();
  });
});

const PORT = process.env.PORT || 4000;

function __validateEnvOrExit() {
  try {
    const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";
    const missing = [];

    function req(name) {
      const v = String(process.env[name] || "").trim();
      if (v.length === 0) missing.push(name);
      return v;
    }

    function anySet(names) {
      for (const n of names) {
        if (String(process.env[n] || "").trim().length > 0) return true;
      }
      return false;
    }

    req("MONGO_URI");
    req("JWT_SECRET");

    if (isProd || anySet(["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"])) {
      req("STRIPE_SECRET_KEY");
      req("STRIPE_WEBHOOK_SECRET");
    }

    if (isProd || anySet(["CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET"])) {
      req("CLOUDINARY_CLOUD_NAME");
      req("CLOUDINARY_API_KEY");
      req("CLOUDINARY_API_SECRET");
    }

    if (anySet(["SMTP_HOST", "SMTP_USER", "SMTP_PASS"])) {
      req("SMTP_HOST");
      req("SMTP_USER");
      req("SMTP_PASS");
    }

    try {
      const runJobs = String(process.env.RUN_JOBS || "").toLowerCase().trim();
      const jobsOn = (runJobs === "1" || runJobs === "true" || runJobs === "yes" || runJobs === "on");
      if (jobsOn) req("INTERNAL_JOBS_TOKEN");
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    if (isProd) req("FRONTEND_BASE_URL");

    if (missing.length > 0) {
      const uniq = Array.from(new Set(missing));
      if (isProd) {
        try { __log("error", "env_guard_fail_missing", { missing: uniq, rid: __tstsRidNow() }); } catch (_) {}
        process.exit(1);
      } else {
        try { __log("warn", "env_guard_warn_missing", { missing: uniq, rid: __tstsRidNow() }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      }
    }
  } catch (e) {
    const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";
    if (isProd) {
      try { __log("error", "env_guard_fatal", { message: (e && e.message) ? String(e.message) : String(e), rid: __tstsRidNow() }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      process.exit(1);
    }
  }
}

__validateEnvOrExit();


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
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com", "https://cdn.tailwindcss.com", "https://kit.fontawesome.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.tailwindcss.com"],
        imgSrc: ["'self'", "data:", "blob:", "https://res.cloudinary.com", "https://*.stripe.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://ka-f.fontawesome.com"],
        connectSrc: ["'self'", "https://api.stripe.com", "https://api.cloudinary.com"],
        frameSrc: ["'self'", "https://js.stripe.com", "https://hooks.stripe.com"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: {
      policy: "strict-origin-when-cross-origin",
    },
    permissionsPolicy: {
      features: {
        geolocation: [],
        camera: [],
        microphone: [],
        payment: ["self", "https://js.stripe.com"],
      },
    },
  })
);

// ROOT_SERVICE_MARKER_TSTS
app.get("/", (req, res) => {
  res.status(200).json({ service: "shared-table-api", status: "ok" });
});

// L11_CORE_ROUTES_EARLY_V1
// Define core status routes before 404 middleware so they are never intercepted.
app.get("/version", (req, res) => {
  const sha = String(process.env.RENDER_GIT_COMMIT || process.env.GIT_SHA || process.env.SHA || process.env.COMMIT_SHA || "unknown");
  const rid = String((req && req.requestId) ? req.requestId : "");
  return res.status(200).json({ service: "shared-table-api", sha: sha, rid: rid });
});





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
  handler: function (req, res) {
    const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : "");
    try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(429).json({ ok: false, code: "RATE_LIMITED", message: "Too many requests", rid: rid });
  },
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: function (req, res) {
    const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : "");
    try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(429).json({ ok: false, code: "RATE_LIMITED", message: "Too many requests", rid: rid });
  },
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: function (req, res) {
    const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : "");
    try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(429).json({ ok: false, code: "RATE_LIMITED", message: "Too many requests", rid: rid });
  },
});

const forgotPasswordEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: function (req) {
    try {
      const emailRaw = (req && req.body && req.body.email) ? String(req.body.email) : "";
      const email = emailRaw.toLowerCase().trim();
      if (email) return "fp_email:" + email;
    } catch (_) {}
    try { return __rlKey(req); } catch (_) {}
    return "";
  },
  handler: function (req, res) {
    const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : "");
    try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
      try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
    }
    return res.status(429).json({ ok: false, code: "RATE_LIMITED", message: "Too many requests", rid: rid });
  },
});


const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: function (req, res) {
    const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : "");
    try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(429).json({ ok: false, code: "RATE_LIMITED", message: "Too many requests", rid: rid });
  },
});

const resetPasswordEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: function (req) {
    try {
      const emailRaw = (req && req.body && req.body.email) ? String(req.body.email) : "";
      const email = emailRaw.toLowerCase().trim();
      if (email) return "rp_email:" + email;
    } catch (_) {}
    try { return __rlKey(req); } catch (_) {}
    return "";
  },
  handler: function (req, res) {
    const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : "");
    try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
      try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
    }
    return res.status(429).json({ ok: false, code: "RATE_LIMITED", message: "Too many requests", rid: rid });
  },
});


const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// PER_ACTION_LIMITERS_TSTS (Batch6 G1)
// Per-route limiters (explicit attachments)
const promoCreateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("promo_admin")
});

const bookingVerifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("booking_verify")
});

function __rlKey(req) {
  try {
    if (req && req.user && (req.user._id || req.user.id)) return String(req.user._id || req.user.id);
    if (req) return String(ipKeyGenerator(req));
    return "";
  } catch (_) {
    return "";
  }
}

function __rlHandler(reason) {
  return async function(req, res) {
    try { await __maybeStrikeAndMute(req, reason); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(429).json({ message: "Too many requests" });
  };
}

const commentLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 6,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("comment")
});

const likeLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("like")
});

const connectLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("connect")
});

const bookingCreateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("book")
});

const reviewLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 6,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("review")
});

const reportLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 6,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: __rlKey,
  handler: __rlHandler("report")
});



// ABUSE_CONTROLS_TSTS (Batch6 G1)
function __abuseMuteMinutes() {
  const raw = String(process.env.ABUSE_MUTE_MINUTES || "15").trim();
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) return 15;
  if (n > 1440) return 1440;
  return n;
}

function __abuseStrikeWindowMs() {
  const raw = String(process.env.ABUSE_STRIKE_WINDOW_MS || "900000").trim();
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 60000) return 900000;
  if (n > 86400000) return 86400000;
  return n;
}

function __abuseStrikeThreshold() {
  const raw = String(process.env.ABUSE_STRIKE_THRESHOLD || "3").trim();
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) return 3;
  if (n > 20) return 20;
  return n;
}

async function __maybeStrikeAndMute(req, reason) {
  try {
    const u = (req && req.user) ? req.user : null;
    if (!u) return;
    const now = new Date();
    const winMs = __abuseStrikeWindowMs();
    const thr = __abuseStrikeThreshold();
    const ws = (u.abuseStrikeWindowStart instanceof Date && !Number.isNaN(u.abuseStrikeWindowStart.getTime())) ? u.abuseStrikeWindowStart : null;
    const within = ws ? ((now.getTime() - ws.getTime()) <= winMs) : false;
    if (!within) {
      u.abuseStrikeWindowStart = now;
      u.abuseStrikeCount = 0;
    }
    const cur = Number.isFinite(Number(u.abuseStrikeCount)) ? Number(u.abuseStrikeCount) : 0;
    u.abuseStrikeCount = cur + 1;
    if (u.abuseStrikeCount >= thr) {
      const mins = __abuseMuteMinutes();
      u.mutedUntil = new Date(now.getTime() + mins * 60 * 1000);
    }
    await u.save();
  } catch (_) {
  }
}


// CORS (locked allowlist)
// Set CORS_ORIGINS as comma-separated list
// Example: "https://thesharedtablestory.com,https://www.thesharedtablestory.com,http://localhost:3000"
const DEFAULT_CORS_ORIGINS = (String(process.env.NODE_ENV || "").toLowerCase() === "production")
  ? [
      "https://shared-table-frontend.onrender.com",
      "https://thesharedtablestory.com",
      "https://www.thesharedtablestory.com",
    ]
  : [
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "http://localhost:5173",
      "http://127.0.0.1:5173",
      "https://shared-table-frontend.onrender.com",
      "https://thesharedtablestory.com",
      "https://www.thesharedtablestory.com",
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
  allowedHeaders: ["Content-Type", "Authorization", "X-Admin-Reason", "X-Internal-Token", "X-Request-Id"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// L3_ADMIN_PARTIAL_REFUND_TRIGGER_ROUTE_V1
// Admin-only trigger: create a partial refund in Stripe.
// IMPORTANT: This route is placed before global express.json(), so it includes its own JSON parser.
// Webhooks (already partial-safe) decide whether to transition to terminal "refunded".
app.post(
  "/api/admin/bookings/:id/refund-partial",
  express.json({ limit: "200kb" }),
  adminMiddleware,
  requireAdminReason,
  async (req, res) => {
    try {
      const bookingId = String((req.params && req.params.id) ? req.params.id : "");
      if (!bookingId) return res.status(400).json({ message: "bookingId required" });

      const rawAmt = req.body && req.body.amountCents;
      const amountCents = Number.isFinite(Number(rawAmt)) ? Math.max(0, Math.floor(Number(rawAmt))) : 0;
      if (amountCents <= 0) return res.status(400).json({ message: "amountCents must be > 0" });

      const BookingModel = mongoose.model("Booking");
      const booking = await BookingModel.findById(bookingId);
      if (!booking) return res.status(404).json({ message: "Booking not found" });

      const pi = String(booking.stripePaymentIntentId || "");
      if (!pi) return res.status(400).json({ message: "Booking has no stripePaymentIntentId" });

      // Safety: best-effort cap so admins cannot refund above total.
      const totalCents = Number(
        (((booking.feeBreakdown && booking.feeBreakdown.totalCents) != null) ? booking.feeBreakdown.totalCents :
        (((booking.pricingSnapshot && booking.pricingSnapshot.totalCents) != null) ? booking.pricingSnapshot.totalCents : 0))
      ) || 0;

      if (!Number.isFinite(Number(booking.totalRefundedCents))) booking.totalRefundedCents = 0;
      const alreadyRefunded = Math.max(0, Math.floor(Number(booking.totalRefundedCents) || 0));

      if (totalCents > 0 && (alreadyRefunded + amountCents) > totalCents) {
        return res.status(400).json({ message: "Refund exceeds booking total" });
      }

      // Stripe reason whitelist
      const reasonRaw = String((req.body && req.body.reason) ? req.body.reason : "");
      const reason = (reasonRaw === "duplicate" || reasonRaw === "fraudulent" || reasonRaw === "requested_by_customer")
        ? reasonRaw
        : "requested_by_customer";

      const note = String((req.body && req.body.note) ? req.body.note : "");

      // Trigger refund (partial). Webhook will update totals/status and decide terminal transition.
      const refund = await stripe.refunds.create({
        payment_intent: pi,
        amount: amountCents,
        reason: reason,
        metadata: {
          bookingId: String(booking._id),
          trigger: "admin_partial_refund",
        },
      });

      if (!booking.refundDecision || typeof booking.refundDecision !== "object") booking.refundDecision = {};
      booking.refundDecision.status = "partial_refund_requested";
      booking.refundDecision.requestedAmountCents = amountCents;
      booking.refundDecision.requestedReason = reason;
      if (note) booking.refundDecision.requestedNote = note;
      if (!booking.refundDecision.currency) booking.refundDecision.currency = "aud";
      booking.refundDecision.stripeRefundId = String((refund && refund.id) ? refund.id : "");
      booking.refundDecision.stripeRefundStatus = String((refund && refund.status) ? refund.status : "created");

      if (!Array.isArray(booking.refundEvents)) booking.refundEvents = [];
      booking.refundEvents.push({
        at: new Date(),
        by: "admin",
        event: "partial_refund_requested",
        stripeRefundId: booking.refundDecision.stripeRefundId,
        amountCents: amountCents,
        status: booking.refundDecision.stripeRefundStatus,
        note: note,
      });

      booking.partialRefund = true;
      // Semantics: confirmed refunded so far (not the amount just requested). Webhook is authoritative for totals.
      booking.partialRefundCents = alreadyRefunded;

      await booking.save();

      return res.json({
        ok: true,
        bookingId: String(booking._id),
        stripeRefundId: booking.refundDecision.stripeRefundId,
        stripeRefundStatus: booking.refundDecision.stripeRefundStatus,
      });
    } catch (e) {
      return res.status(500).json({
        ok: false,
        error: "admin_refund_partial_failed",
        code: "ADMIN_REFUND_PARTIAL_FAILED",
        message: "Admin refund-partial failed",
      });
    }
  }
);

app.post(
  "/api/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      __log("info", "stripe_webhook_hit", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
      if (!STRIPE_WEBHOOK_SECRET) return res.status(500).json({ message: "Server error" });

      const sig = req.headers["stripe-signature"];
      let event;
      try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
        __log("info", "stripe_webhook_verified", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });

      try {
        const evObj = (event && event.data && event.data.object) ? event.data.object : {};
        const bid = String((evObj && (evObj.client_reference_id || (evObj.metadata && evObj.metadata.bookingId))) || "");
        const so = String((evObj && (evObj.id || evObj.payment_intent || evObj.charge)) || "");
        const amt = Number((evObj && (evObj.amount_total || evObj.amount || evObj.amount_refunded)) || 0) || 0;
        const cur = String((evObj && evObj.currency) ? evObj.currency : "aud");
        await __ledgerAppendOnce({
          bookingId: bid,
          eventId: String(event.id || ""),
          eventType: String(event.type || ""),
          stripeObjectId: so,
          amountCents: amt,
          currency: cur,
          status: "verified",
          note: "stripe_webhook_verified",
          meta: { hasBookingId: Boolean(bid), hasStripeObjectId: Boolean(so) }
        });
      } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

      } catch (err) {
        __log("error", "stripe_webhook_sig_fail", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
        return res.status(400).send("Webhook signature verification failed");
      }

      if (mongoose == null || 
mongoose.connection == null || mongoose.connection.readyState !== 1) {
        return res.status(500).send("DB not ready");
      }

      const eventId = String((event && event.id) ? event.id : "");
      if (eventId.length === 0) return res.json({ received: true });

      try { await __ensureStripeWebhookIndex(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

      const __adminEmail = () => {
        const a = (process && process.env && process.env.ADMIN_EMAIL) ? String(process.env.ADMIN_EMAIL).trim() : "";
        const s = (process && process.env && process.env.SUPPORT_EMAIL) ? String(process.env.SUPPORT_EMAIL).trim() : "";
        return (a.length > 0 ? a : (s.length > 0 ? s : ""));
      };

      const __alertAdminOnce = async (BookingModel, bookingId, commsKey, eventName, category, vars) => {
        try {
          const to = __adminEmail();
          if (!to) return false;
          const when = new Date();
          const q = { _id: bookingId, $or: [ { [commsKey]: { $exists: false } }, { [commsKey]: null } ] };
          const u = { $set: { [commsKey]: when } };
          const gate = await BookingModel.findOneAndUpdate(q, u, { new: true });
          if (!gate) return false;
          __fireAndForgetEmail({ to, eventName, category, vars });
          return true;
        } catch (_) {
          return false;
        }
      };

      const evCol = mongoose.connection.db.collection("stripe_webhook_events");
      try {
        const __evDoc = {
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
        };
        const __q = { eventId: eventId };
        const __u = { $setOnInsert: __evDoc };
        const __r = await evCol.updateOne(__q, __u, { upsert: true });
        const __inserted = (
          (__r && (typeof __r.upsertedCount === "number") && (__r.upsertedCount > 0)) ||
          (__r && (__r.upsertedId !== undefined) && (__r.upsertedId !== null))
        );
        if (!__inserted) {
          __log("info", "stripe_webhook_dup_event", { rid: __ridFromReq(req), eventId: eventId });
          return res.json({ received: true });
        }

        try {
          await evCol.updateOne({ eventId }, { $set: { data: (event && event.data) ? event.data : null } });
        } catch (dataErr) {
          __log("warn", "webhook_ledger_data_update_failed", { rid: __tstsRidNow(), eventId, error: (dataErr && dataErr.message) || String(dataErr) });
        }
      } catch (e) {
        if (__isDuplicateKeyError(e)) {
          try {
            const claimed = await evCol.findOneAndUpdate(
              { eventId, processedAt: null, $or: [{ processingAt: null }, { processingAt: { $exists: false } }, { processingAt: { $lte: new Date(Date.now() - 10 * 60 * 1000) } }] },
              { $set: { processingAt: new Date(), error: "", type: String(event.type || ""), livemode: Boolean(event.livemode), createdAt: (event && event.created) ? new Date(Number(event.created) * 1000) : null, receivedAt: new Date() }, $inc: { attempts: 1 } },
              { returnDocument: "after" }
            );
            if (!claimed || !claimed.value) return res.json({ received: true, duplicate: true });
          } catch (_) {
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
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "error", error: "missing_booking_id" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "checkout.session.completed", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findById(bookingId);
        if (!booking) {
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "ignored_not_found", error: "booking_not_found" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "checkout.session.completed", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        booking.stripeSessionId = String(session.id || booking.stripeSessionId || "");

        try {
          if (session.id) {
            const full = await stripe.checkout.sessions.retrieve(String(session.id), { expand: ["payment_intent", "line_items"] });

            if (!booking.currency) booking.currency = String((full.currency || session.currency || (booking.pricing && booking.pricing.currency) || "aud")).toLowerCase();

            const amt =
              (Number.isFinite(full.amount_total) && Number(full.amount_total)) ||
              (Number.isFinite(session.amount_total) && Number(session.amount_total)) ||
              (booking.pricing && Number.isFinite(booking.pricing.totalCents) && Number(booking.pricing.totalCents)) ||
              null;

            if (amt !== null) booking.amountCents = amt;

            const piObj = full.payment_intent;
            const pi = (piObj && (piObj.id || piObj)) || session.payment_intent || null;
            if (pi) booking.stripePaymentIntentId = String(pi);
          } else {
            if (session.payment_intent) booking.stripePaymentIntentId = String(session.payment_intent);
            if (Number.isFinite(session.amount_total)) booking.amountCents = Number(session.amount_total);
            if (session.currency) booking.currency = String(session.currency).toLowerCase();
          }
        } catch (_) {
          if (session.payment_intent) booking.stripePaymentIntentId = String(session.payment_intent);
          if (Number.isFinite(session.amount_total)) booking.amountCents = Number(session.amount_total);
          if (session.currency) booking.currency = String(session.currency).toLowerCase();
        }

        booking.currency = String(booking.currency || "aud").toLowerCase();
        await booking.save();

        // BE-RED-02: Mark event as successfully processed
        try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "success", error: "" } }); } catch (ledgerErr) {
          __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "checkout.session.completed", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
        }

        try {
          if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
          const when = new Date();
          const gate = await BookingModel.findOneAndUpdate(
            { _id: booking._id, $or: [ { "comms.invoiceReceiptGuestSentAt": { $exists: false } }, { "comms.invoiceReceiptGuestSentAt": null } ] },
            { $set: { "comms.invoiceReceiptGuestSentAt": when } },
            { new: true }
          );
          if (gate) {
            const to = booking.guestEmail ? String(booking.guestEmail).trim() : "";
            const nm = booking.guestName ? String(booking.guestName).trim() : "";
            const date = booking.bookingDate ? String(booking.bookingDate).trim() : "";
            const title = booking.experienceTitle ? String(booking.experienceTitle).trim() : (booking.title ? String(booking.title).trim() : "");
            const cur = booking.currency ? String(booking.currency).trim().toUpperCase() : "AUD";
            let cents = null;
            if (Number.isFinite(Number(booking.amountCents))) cents = Number(booking.amountCents);
            else if (booking.pricing && Number.isFinite(Number(booking.pricing.totalCents))) cents = Number(booking.pricing.totalCents);
            const amt = (cents === null) ? "" : (cur + " " + (Number(cents) / 100).toFixed(2));
            if (to) __fireAndForgetEmail({ to, eventName: "INVOICE_RECEIPT_GUEST", category: "PAYMENTS", vars: { DASHBOARD_URL: __dashboardUrl(), Name: nm, DATE: date, EXPERIENCE_TITLE: title, AMOUNT: amt } });
          }
        } catch (commsErr) {
          __log("warn", "webhook_comms_failed", { rid: __tstsRidNow(), eventId, handler: "checkout.session.completed", bookingId: String(booking._id), error: (commsErr && commsErr.message) || String(commsErr) });
        }
      }

      if (event.type === "payment_intent.succeeded") {
        const paymentIntent = (event && event.data && event.data.object) ? event.data.object : {};
        const piId = paymentIntent.id;
        
        if (!piId) {
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "error", error: "missing_payment_intent_id" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "payment_intent.succeeded", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findOne({ stripePaymentIntentId: piId });
        if (!booking) {
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "ignored_not_found", error: "booking_not_found" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "payment_intent.succeeded", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        // BE-RED-03: Guard booking state transitions - do not resurrect terminal states
        const curStatus = String(booking.status || "").toLowerCase();
        const terminalStates = ["cancelled", "canceled", "refunded", "expired"];
        if (terminalStates.includes(curStatus)) {
          __log("info", "stripe_webhook_skip_terminal_state", { rid: __ridFromReq(req), bookingId: String(booking._id), status: curStatus, eventId });
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "skipped_terminal_state", error: "" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "payment_intent.succeeded", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        // BE-RED-03: Idempotent exit if already confirmed
        if (curStatus === "confirmed" && booking.paymentStatus === "paid") {
          __log("info", "stripe_webhook_already_confirmed", { rid: __ridFromReq(req), bookingId: String(booking._id), eventId });
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "success_idempotent", error: "" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "payment_intent.succeeded", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        // Update booking status to confirmed
        booking.status = "confirmed";
        booking.paymentStatus = "paid";
        booking.confirmedAt = new Date();
        
        await booking.save();

        // BE-RED-02: Mark event as successfully processed
        try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "success", error: "" } }); } catch (ledgerErr) {
          __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: "payment_intent.succeeded", error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
        }

        try {
          if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
          const when = new Date();
          const gate = await BookingModel.findOneAndUpdate(
            { _id: booking._id, $or: [ { "comms.bookingConfirmedGuestSentAt": { $exists: false } }, { "comms.bookingConfirmedGuestSentAt": null } ] },
            { $set: { "comms.bookingConfirmedGuestSentAt": when } },
            { new: true }
          );
          if (gate) {
            const to = booking.guestEmail ? String(booking.guestEmail).trim() : "";
            const nm = booking.guestName ? String(booking.guestName).trim() : "";
            const date = booking.bookingDate ? String(booking.bookingDate).trim() : "";
            const title = booking.experienceTitle ? String(booking.experienceTitle).trim() : (booking.title ? String(booking.title).trim() : "");
            if (to) __fireAndForgetEmail({ to, eventName: "BOOKING_CONFIRMED_GUEST", category: "PAYMENTS", vars: { DASHBOARD_URL: __dashboardUrl(), Name: nm, DATE: date, EXPERIENCE_TITLE: title } });
          }
        } catch (commsErr) {
          __log("warn", "webhook_comms_failed", { rid: __tstsRidNow(), eventId, handler: "payment_intent.succeeded", bookingId: String(booking._id), error: (commsErr && commsErr.message) || String(commsErr) });
        }
      }

      if (event.type === "checkout.session.async_payment_failed" || event.type === "checkout.session.expired") {
        const session = (event && event.data && event.data.object) ? event.data.object : {};
        const bookingId = session.client_reference_id || (session.metadata && session.metadata.bookingId);
        if (!bookingId) {
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "error", error: "missing_booking_id" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: event.type, error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findById(String(bookingId));
        if (!booking) {
          try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "ignored_not_found", error: "booking_not_found" } }); } catch (ledgerErr) {
            __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: event.type, error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
          }
          return res.json({ received: true });
        }

        let full = null;
        try { if (session && session.id) full = await stripe.checkout.sessions.retrieve(String(session.id), { expand: ["payment_intent"] }); } catch (stripeErr) {
          __log("warn", "webhook_stripe_retrieve_failed", { rid: __tstsRidNow(), eventId, handler: event.type, sessionId: session.id, error: (stripeErr && stripeErr.message) || String(stripeErr) });
        }

        const stripeStatus = String((session && session.payment_status) ? session.payment_status : "unpaid");
        const piObj = (full && full.payment_intent) ? full.payment_intent : (session && session.payment_intent ? session.payment_intent : null);
        const piStatus = String((piObj && piObj.status) ? piObj.status : "");

        booking.paymentLastStripeStatus = stripeStatus;
        booking.paymentLastPiStatus = piStatus;
        booking.stripeSessionId = String(session.id || booking.stripeSessionId || "");

        const now = new Date();
        const lockedUntil = booking.paymentLockedUntil ? new Date(booking.paymentLockedUntil) : null;
        if (lockedUntil && lockedUntil.getTime() > now.getTime()) {
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
          if (within30m && attempts >= 5) booking.paymentLockedUntil = new Date(now.getTime() + (30 * 60 * 1000));
        }

        if (String(booking.paymentStatus || "unpaid") !== "paid") {
          const sessionStatus = String((session && session.status) ? session.status : "");
          booking.paymentStatus = __classifyPaymentOutcome(stripeStatus, (piObj && piObj.status) ? String(piObj.status) : "", sessionStatus);
        }

        try {
          if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
          const isExpired = (event.type === "checkout.session.expired");
          const isFail2 = (piStatus === "requires_payment_method" || piStatus === "canceled" || piStatus === "cancelled");
          if (isExpired || (isFail2 && stripeStatus !== "paid")) {
            const when = new Date();
            const gate = await BookingModel.findOneAndUpdate(
              { _id: booking._id, $or: [ { "comms.paymentFailedSentAt": { $exists: false } }, { "comms.paymentFailedSentAt": null } ] },
              { $set: { "comms.paymentFailedSentAt": when } },
              { new: true }
            );
            if (gate) {
              const to = booking.guestEmail ? String(booking.guestEmail).trim() : "";
              const nm = booking.guestName ? String(booking.guestName).trim() : "";
              if (to) __fireAndForgetEmail({ to, eventName: "PAYMENT_FAILED", category: "PAYMENTS", vars: { DASHBOARD_URL: __dashboardUrl(), Name: nm } });
            }
          }
        } catch (commsErr) {
          __log("warn", "webhook_comms_failed", { rid: __tstsRidNow(), eventId, handler: event.type, bookingId: String(booking._id), error: (commsErr && commsErr.message) || String(commsErr) });
        }

        await booking.save();

        // BE-RED-02: Mark event as successfully processed
        try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, status: "success", error: "" } }); } catch (ledgerErr) {
          __log("warn", "webhook_ledger_update_failed", { rid: __tstsRidNow(), eventId, handler: event.type, error: (ledgerErr && ledgerErr.message) || String(ledgerErr) });
        }

        return res.json({ received: true });
      }

      // L4-6/L4-7: refund failure tracking + retry eligibility + admin alert
      const __markRefundFailed = async (BookingModel, booking, kind, msg, refundId, refundStatus) => {
        try {
          if (!booking.refundDecision || typeof booking.refundDecision !== "object") booking.refundDecision = {};
          const prev = Number.isFinite(Number(booking.refundDecision.attemptCount)) ? Number(booking.refundDecision.attemptCount) : 0;
          booking.refundDecision.attemptCount = prev + 1;
          booking.refundDecision.lastError = String(msg || kind || "refund_failed");
          booking.refundDecision.status = "refund_failed";
          booking.refundDecision.retryEligible = true;
          booking.refundDecision.retryAfterAt = new Date(Date.now() + 15 * 60 * 1000);
          if (refundId) booking.refundDecision.stripeRefundId = String(refundId);
          if (refundStatus) booking.refundDecision.stripeRefundStatus = String(refundStatus);

          if (!Array.isArray(booking.refundEvents)) booking.refundEvents = [];
          booking.refundEvents.push({
            at: new Date(),
            by: "stripe_webhook",
            event: String(kind || "refund_failed"),
            stripeRefundId: String(refundId || ""),
            amountCents: 0,
            status: String(refundStatus || "failed"),
            error: String(msg || ""),
          });

          await booking.save();

          try {
            const vars = {
              DASHBOARD_URL: __dashboardUrl(),
              BOOKING_ID: String(booking._id || ""),
              GUEST_EMAIL: String(booking.guestEmail || ""),
              STRIPE_PI: String(booking.stripePaymentIntentId || ""),
              REFUND_ID: String(refundId || ""),
              REFUND_STATUS: String(refundStatus || ""),
              ERROR: String(msg || kind || "refund_failed"),
            };
            await __alertAdminOnce(BookingModel, booking._id, "comms.refundFailedAdminAlertSentAt", "REFUND_FAILED_ADMIN_ALERT", "PAYMENTS", vars);
          } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      };

      if (event.type === "refund.failed") {
        const refund = (event && event.data && event.data.object) ? event.data.object : {};
        const pi = String(refund.payment_intent || "");
        const refundId = String(refund.id || "");
        const refundStatus = String(refund.status || "failed");
        const failureReason = String(refund.failure_reason || "");
        const msg = (failureReason.length > 0 ? failureReason : "refund_failed");

        if (!pi) return res.json({ received: true });
        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findOne({ stripePaymentIntentId: pi });
        if (!booking) return res.json({ received: true });

        await __markRefundFailed(BookingModel, booking, "refund_failed", msg, refundId, refundStatus);
      }

      if (event.type === "refund.updated" || event.type === "refund.created") {
        const refund = event.data.object || {};
        const amt = (refund && Number.isFinite(Number(refund.amount))) ? Number(refund.amount) : null;
        const cur = refund && refund.currency ? String(refund.currency).toLowerCase() : "";

        const pi = String(refund.payment_intent || "");
        const refundId = String(refund.id || "");
        const refundStatus = String(refund.status || "");
        if (!pi) return res.json({ received: true });

        const BookingModel = mongoose.model("Booking");
        const booking = await BookingModel.findOne({ stripePaymentIntentId: pi });
        if (!booking) return res.json({ received: true });

        if (!booking.refundDecision || typeof booking.refundDecision !== "object") booking.refundDecision = {};
        if (amt !== null) booking.refundDecision.amountCents = amt;
        if (cur) booking.refundDecision.currency = cur;
        if (refundId) booking.refundDecision.stripeRefundId = refundId;
        if (refundStatus) booking.refundDecision.stripeRefundStatus = refundStatus;

        if (refundStatus === "succeeded") {
          try {
            const rAmt = Number.isFinite(Number(amt)) ? Math.max(0, Math.floor(Number(amt))) : 0;
            const rid = String(refundId || "");

            if (!Number.isFinite(Number(booking.totalRefundedCents))) booking.totalRefundedCents = 0;
            if (!Array.isArray(booking.refundEvents)) booking.refundEvents = [];

            const already = (rid && booking.refundEvents.some((e) => e && typeof e === "object" && String(e.stripeRefundId || "") === rid));
            if (already == false && (rid || rAmt > 0)) {
              booking.refundEvents.push({ at: new Date(), by: "stripe_webhook", event: "refund_succeeded", stripeRefundId: rid, amountCents: rAmt, status: "succeeded" });
              if (rAmt > 0) booking.totalRefundedCents = Math.max(0, Math.floor(Number(booking.totalRefundedCents) || 0) + rAmt);
            }

            const totalCents = Number((((booking.feeBreakdown && booking.feeBreakdown.totalCents) != null) ? booking.feeBreakdown.totalCents : (((booking.pricingSnapshot && booking.pricingSnapshot.totalCents) != null) ? booking.pricingSnapshot.totalCents : 0))) || 0;

            if (totalCents > 0 && Number(booking.totalRefundedCents) >= Number(totalCents)) {
              booking.refundDecision.status = "refunded";
              if (booking.status !== "refunded") {
              await __releaseCapacityOnceAtomic(booking, "stripe_refund");
              await transitionBooking(booking, "refunded");
            }
            } else {
              booking.refundDecision.status = "partially_refunded";
              booking.partialRefund = true;
              booking.partialRefundCents = Math.max(0, Math.floor(Number(booking.totalRefundedCents) || 0));
            }
          } catch (_) {
            booking.refundDecision.status = "refund_succeeded";
          }
        } else if (refundStatus === "failed" || refundStatus === "canceled" || refundStatus === "cancelled") {
          const msg = String(refund.failure_reason || refundStatus || "refund_failed");
          await __markRefundFailed(BookingModel, booking, "refund_failed", msg, refundId, refundStatus);
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

        try {
          if (!Number.isFinite(Number(booking.totalRefundedCents))) booking.totalRefundedCents = 0;

          const totalCents = Number((((booking.feeBreakdown && booking.feeBreakdown.totalCents) != null) ? booking.feeBreakdown.totalCents : (((booking.pricingSnapshot && booking.pricingSnapshot.totalCents) != null) ? booking.pricingSnapshot.totalCents : 0))) || 0;

          if (totalCents > 0 && Number(booking.totalRefundedCents) >= Number(totalCents)) {
            booking.refundDecision.status = "refunded";
            if (booking.status !== "refunded") {
              await __releaseCapacityOnceAtomic(booking, "stripe_refund");
              await transitionBooking(booking, "refunded");
            }
          } else {
            booking.refundDecision.status = "partially_refunded";
            booking.partialRefund = true;
            booking.partialRefundCents = Math.max(0, Math.floor(Number(booking.totalRefundedCents) || 0));
          }
        } catch (_) {
          booking.refundDecision.status = "refund_succeeded";
        }
        await booking.save();
      }

      // L4-8/L4-9/L4-10: dispute ingestion + lifecycle + admin alert
      const __upsertDispute = async (BookingModel, dispute, eventType) => {
        const d = dispute || {};
        const disputeId = String(d.id || "");
        const chargeId = String(d.charge || "");
        const status = String(d.status || "");
        const reason = String(d.reason || "");
        const cur = d.currency ? String(d.currency).toLowerCase() : "";
        const amt = Number.isFinite(Number(d.amount)) ? Number(d.amount) : null;
        const livemode = Boolean(d.livemode);

        let pi = String(d.payment_intent || "");
        if (!pi && chargeId) {
          try {
            const ch = await stripe.charges.retrieve(String(chargeId), { expand: ["payment_intent"] });
            if (ch && ch.payment_intent) pi = String((ch.payment_intent && (ch.payment_intent.id || ch.payment_intent)) || "");
          } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
        }

        if (!pi) return null;

        const booking = await BookingModel.findOne({ stripePaymentIntentId: pi });
        if (!booking) return null;

        if (!booking.dispute || typeof booking.dispute !== "object") booking.dispute = {};
        if (!Array.isArray(booking.disputeEvents)) booking.disputeEvents = [];

        booking.dispute.stripeDisputeId = disputeId || booking.dispute.stripeDisputeId || "";
        booking.dispute.stripeChargeId = chargeId || booking.dispute.stripeChargeId || "";
        booking.dispute.status = status || booking.dispute.status || "";
        booking.dispute.reason = reason || booking.dispute.reason || "";
        if (amt !== null) booking.dispute.amountCents = amt;
        if (cur) booking.dispute.currency = cur;
        booking.dispute.livemode = livemode;
        booking.dispute.lastEventType = String(eventType || "");
        booking.dispute.updatedAt = new Date();

        const active = (status && status !== "won" && status !== "lost" && status !== "closed");
        booking.dispute.active = Boolean(active);

        try {
          if (Number.isFinite(Number(d.created))) booking.dispute.createdAt = new Date(Number(d.created) * 1000);
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

        try {
          const due = (d.evidence_details && Number.isFinite(Number(d.evidence_details.due_by))) ? Number(d.evidence_details.due_by) : null;
          if (due !== null) booking.dispute.evidenceDueBy = new Date(due * 1000);
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

        booking.disputeEvents.push({
          at: new Date(),
          by: "stripe_webhook",
          event: String(eventType || ""),
          stripeDisputeId: disputeId,
          stripeChargeId: chargeId,
          status: status,
          reason: reason,
          amountCents: (amt !== null ? amt : 0),
          currency: cur,
        });

        await booking.save();

        try {
          const vars = {
            DASHBOARD_URL: __dashboardUrl(),
            BOOKING_ID: String(booking._id || ""),
            STRIPE_PI: String(booking.stripePaymentIntentId || ""),
            DISPUTE_ID: disputeId,
            CHARGE_ID: chargeId,
            STATUS: status,
            REASON: reason,
            AMOUNT_CENTS: (amt === null ? "" : String(amt)),
            CURRENCY: cur,
            EVENT_TYPE: String(eventType || ""),
          };

          const key = (eventType === "charge.dispute.created") ? "comms.disputeCreatedAdminAlertSentAt" :
                      (eventType === "charge.dispute.closed") ? "comms.disputeClosedAdminAlertSentAt" :
                      "comms.disputeUpdatedAdminAlertSentAt";

          await __alertAdminOnce(BookingModel, booking._id, key, "DISPUTE_ADMIN_ALERT", "PAYMENTS", vars)
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

        return booking;
      };

      if (event.type === "charge.dispute.created" || event.type === "charge.dispute.updated" || event.type === "charge.dispute.closed") {
        const dispute = (event && event.data && event.data.object) ? event.data.object : {};
        try {
          const BookingModel = mongoose.model("Booking");
          await __upsertDispute(BookingModel, dispute, String(event.type || ""));
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      }

      try { await evCol.updateOne({ eventId }, { $set: { processedAt: new Date(), processingAt: null, error: "" } }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      return res.json({ received: true });
    } catch (e) {
      try {
        if (mongoose && mongoose.connection && mongoose.connection.readyState === 1) {
          const evCol2 = mongoose.connection.db.collection("stripe_webhook_events");
          if (typeof eventId === "string" && eventId.length > 0) {
            await evCol2.updateOne({ eventId }, { $set: { error: String((e && e.message) ? e.message : "webhook_error"), processingAt: null } });
          }
        }
      } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      __log("error", "stripe_webhook_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? String(req.originalUrl) : undefined });
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
        return res.status(400).json({ ok: false, error: "invalid_json_body", code: "INVALID_JSON_BODY", message: "Invalid JSON body" });
      }
    }
    return next();
  } catch (_) {
    return res.status(400).json({ ok: false, error: "invalid_request", code: "INVALID_REQUEST", message: "Invalid request" });
  }
});

// JSON parse / body size errors (clean response)
app.use((err, req, res, next) => {
  const msg = String((err && err.message) ? err.message : "").toLowerCase();
  const typeStr = String((err && err.type) ? err.type : "");
  const tooLarge = (typeStr === "entity.too.large") || (msg.indexOf("request entity too large") >= 0);

  if (tooLarge) {
    return res.status(413).json({ ok: false, error: "payload_too_large", code: "PAYLOAD_TOO_LARGE", message: "Payload too large" });
  }

  const looksJson = (msg.indexOf("unexpected token") >= 0) || (msg.indexOf("json") >= 0);
  if (looksJson) {
    return res.status(400).json({ ok: false, error: "invalid_json", code: "INVALID_JSON", message: "Invalid JSON" });
  }

  return next(err);
});


app.use("/api", apiLimiter);
app.use("/api/auth", authLimiter);
app.use("/api/admin", adminLimiter);

// CORS error handler (clean response)
app.use((err, req, res, next) => {
  if (err && String(err.message || "").startsWith("CORS blocked")) {
    return res.status(403).json({ ok: false, error: "CORS blocked", code: "CORS_BLOCKED", message: "CORS blocked" });
  }
  return next(err);
});

// BUILD FINGERPRINT (deploy verification)
app.get("/sha", (req, res) => {
  const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
  try { if (rid) res.set("X-Request-Id", rid); } catch (_) {}
  const sha = (process.env.RENDER_GIT_COMMIT || process.env.COMMIT_SHA || process.env.GIT_SHA || process.env.SHA || "unknown");
  return res.status(200).json({ ok: true, sha: String(sha), rid: rid });
});

// L11_JSON_404_HANDLER_V1
// Ensure missing routes return JSON when caller expects JSON (or for /api/*).
// This allows the res.json shim to inject rid + stable code (NOT_FOUND).
app.use((req, res, next) => {
  try {
    const p = String((req && (req.path || req.originalUrl)) || "");
    const accept = String((req && req.headers && req.headers["accept"]) || "");
    const wantsJson = (accept.toLowerCase().indexOf("application/json") >= 0);
    const isApi = (p.indexOf("/api") == 0);
    if (wantsJson || isApi) {
      return res.status(404).json({ ok: false, error: "NOT_FOUND", code: "NOT_FOUND", message: "Not found" });
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  return res.status(404).send("Not found");
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

    return res.status(500).json({ ok: false, error: "server_error", code: "SERVER_ERROR", message: "Server error", rid: rid });
  } catch (_) {
    return res.status(500).json({ ok: false, error: "server_error", code: "SERVER_ERROR", message: "Server error" });
  }
});



// Stripe webhook idempotency: dedupe by Stripe event.id
let __stripeWebhookIndexPromise = null;
async function __ensureStripeWebhookIndex() {
  try {
    if (__stripeWebhookIndexPromise) return __stripeWebhookIndexPromise;
    if (mongoose == null) return null;
    if (mongoose.connection == null) return null;

    const col = mongoose.connection.collection("stripe_webhook_events");

    // 1) Unique idempotency key
    const p1 = col.createIndex({ eventId: 1 }, { unique: true, background: true });

    // 2) TTL hygiene: auto-expire old webhook event docs (90 days)
    // TTL works only when the indexed field is a Date; docs without receivedAt are not affected.
    const ttlSeconds = 90 * 24 * 60 * 60;
    const p2 = col.createIndex({ receivedAt: 1 }, { expireAfterSeconds: ttlSeconds, background: true });

    __stripeWebhookIndexPromise = Promise.all([p1, p2]).then(function () { return true; });
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
  try { await ensureDefaultPolicyExists(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  try { await __ensureStripeWebhookIndex(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
__dbReady = true;
  __log("info", "db_connected", { rid: undefined, path: undefined });
  try { global.__tsts_db_connected = true; } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }


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

// L11_EMAIL_IDEMPOTENT_WRAPPER_V1
async function sendEmailWithInfo_Idempotent(db, args) {
  try {
    const crypto = require("crypto");
    const toKey = String((args && args.to) || "").trim().toLowerCase();
    const subKey = String((args && args.subject) || "").trim();
    const htmlKey = String((args && args.html) || "");
    const textKey = String((args && args.text) || "");
    const keySrc = JSON.stringify({ to: toKey, subject: subKey, html: htmlKey, text: textKey });
    const idemKey = crypto.createHash("sha256").update(keySrc).digest("hex");
    if (db && db.collection) {
      const emails = db.collection("email_idempotency");
      const now = new Date();
      try {
        await emails.insertOne({ _id: idemKey, at: now, to: toKey, subject: subKey });
      } catch (e) {
        const msg = String((e && e.message) || "").toLowerCase();
        if (msg.includes("duplicate")) return { skipped: true };
      }
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  return await sendEmailWithInfo(args);
}

async function sendEmailWithInfo({ to, subject, html, text }) {
  const mailer = getMailer();
  if (!mailer) return { ok: false, providerMessageId: "", error: "mailer_not_configured" };

  const from = String(process.env.FROM_EMAIL || process.env.SMTP_USER || "");
  try {
    const info = await mailer.sendMail({
      from,
      to,
      subject,
      ...(html ? { html } : {}),
      ...(text ? { text } : {}),
    });
    const mid = (info && info.messageId) ? String(info.messageId) : "";
    return { ok: true, providerMessageId: mid, error: "" };
  } catch (err) {
    const msg = (err && err.message) ? String(err.message) : "email_send_failed";
    __log("error", "email_send_failed", { err: msg });
    return { ok: false, providerMessageId: "", error: msg };
  }
}

async function sendEmail({ to, subject, html, text }) {
  const r = await sendEmailWithInfo({ to, subject, html, text });
  return r && r.ok === true;
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
    mutedUntil: { type: Date, default: null },
    abuseStrikeCount: { type: Number, default: 0 },
    abuseStrikeWindowStart: { type: Date, default: null },
    blockedUserIds: { type: [String], default: [] },
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
    deletedBy: { type: String, default: "" },
    tokenVersion: { type: Number, default: 0 },
    emailVerificationTokenHash: { type: String, default: "" },
    emailVerificationRequestedAt: { type: Date, default: null },
    emailVerificationExpiresAt: { type: Date, default: null },
    passwordResetExpiresAt: { type: Date, default: null },
    passwordResetRequestedAt: { type: Date, default: null },

    // Social foundation (privacy-preserving)
    handle: { type: String, unique: true, sparse: true }, // exact-match lookup only
    allowHandleSearch: { type: Boolean, default: false }, // opt-in
    discoverable: { type: Boolean, default: false }, // opt-in discovery
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
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
    deletedBy: { type: String, default: "" },
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
    // Capacity release idempotency marker
    capacityReleasedAt: { type: Date, default: null },

    pricing: Object,

    // L3: immutable-ish pricing snapshot (stored at booking time)
    pricingSnapshot: { type: Object, default: null },
    pricingLockedAt: { type: Date, default: null },
    pricingHash: { type: String, default: "" },

    // L3: fee components (all cents)
    feeBreakdown: { type: Object, default: {} },

    // L3: promo applied snapshot (if any)
    promoApplied: { type: Object, default: null },

    // L3: cancellation audit trail (append-only events)
    cancellationAudit: { type: Array, default: [] },

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

    // Partial + multi-stage refund support (deterministic + auditable)
    partialRefund: { type: Boolean, default: false },
    partialRefundCents: { type: Number, default: 0 },
    partialRefundReason: { type: String, default: "" },

    // Cumulative refunded cents + append-only event trail (paper trail)
    totalRefundedCents: { type: Number, default: 0 },
    refundEvents: { type: Array, default: [] },

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


const promoCodeSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true, index: true },
    active: { type: Boolean, default: true },

    percentOff: { type: Number, default: 0 },
    fixedOffCents: { type: Number, default: 0 },

    currency: { type: String, default: "aud" },

    minSubtotalCents: { type: Number, default: 0 },
    minGuests: { type: Number, default: 0 },

    validFrom: { type: Date, default: null },
    validTo: { type: Date, default: null },

    maxUsesTotal: { type: Number, default: 0 },
    maxUsesPerUser: { type: Number, default: 0 },

    appliesToExperienceIds: { type: Array, default: [] },
    appliesToHostIds: { type: Array, default: [] },

    note: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const promoRedemptionSchema = new mongoose.Schema(
  {
    promoCode: { type: String, required: true, index: true },
    userId: { type: String, default: "", index: true },
    bookingId: { type: String, default: "" },
    ok: { type: Boolean, default: false },
    reason: { type: String, default: "" },
    amountOffCents: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const PromoCode = mongoose.models.PromoCode || mongoose.model("PromoCode", promoCodeSchema);
const PromoRedemption = mongoose.models.PromoRedemption || mongoose.model("PromoRedemption", promoRedemptionSchema);


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

// Deterministic partial refund calculator.
// Inputs are integer cents only. Output is integer cents only.
// Does NOT call Stripe; it only computes the refund amount for later execution/audit.
function __computePartialRefundCents(totalCents, percent) {
  const t = Number.isFinite(Number(totalCents)) ? Math.floor(Number(totalCents)) : 0;
  const p = Number.isFinite(Number(percent)) ? Number(percent) : 0;
  if (!(t > 0)) return 0;
  const pct = Math.max(0, Math.min(100, p));
  const out = Math.floor((t * pct) / 100);
  return Math.max(0, Math.min(t, out));
}

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

// --- ADMIN PRICING POLICY (platform fee + admin pct defaults/caps) ---
const adminPricingPolicySchema = new mongoose.Schema(
  {
    version: { type: String, default: "" },
    status: { type: String, enum: ["draft", "published"], default: "published" },
    active: { type: Boolean, default: true },
    effectiveFrom: { type: Date, default: Date.now },
    publishedAt: { type: Date, default: Date.now },

    rules: {
      // platform fee policy object passed into pricing.js
      platformFeePolicy: { type: Object, default: null },

      // admin discount tier defaults/caps (percentage points, 0..50)
      adminPctDefault: { type: Number, default: 0 },
      adminPctCap: { type: Number, default: 0 },
    },
  },
  schemaOpts
);
adminPricingPolicySchema.index({ active: 1, effectiveFrom: -1 });

const AdminPricingPolicy =
  mongoose.models.AdminPricingPolicy || mongoose.model("AdminPricingPolicy", adminPricingPolicySchema);

async function getActiveAdminPricingPolicyDoc() {
  const now = new Date();
  return await AdminPricingPolicy.findOne({ active: true, effectiveFrom: { $lte: now } })
    .sort({ effectiveFrom: -1 })
    .lean();
}

function adminPricingPolicySnapshotFromDoc(doc) {
  if (!doc) return null;
  const r = (doc.rules && typeof doc.rules === "object") ? doc.rules : {};
  const pfp = (r.platformFeePolicy && typeof r.platformFeePolicy === "object") ? r.platformFeePolicy : null;

  const dfltRaw = Number(r.adminPctDefault);
  const capRaw = Number(r.adminPctCap);

  const dflt = Number.isFinite(dfltRaw) ? dfltRaw : 0;
  const cap = Number.isFinite(capRaw) ? capRaw : 0;

  return {
    version: String(doc.version || ""),
    effectiveFrom: doc.effectiveFrom || null,
    publishedAt: doc.publishedAt || null,
    rules: {
      platformFeePolicy: pfp,
      adminPctDefault: dflt,
      adminPctCap: cap,
    },
  };
}

async function ensureDefaultAdminPricingPolicyExists() {
  const any = await AdminPricingPolicy.findOne({}).select("_id").lean();
  if (any) return;

  const now = new Date();
  const ver = now.toISOString();

  await AdminPricingPolicy.create({
    version: ver,
    status: "published",
    active: true,
    effectiveFrom: now,
    publishedAt: now,
    rules: {
      platformFeePolicy: null,
      adminPctDefault: 0,
      adminPctCap: 0,
    },
  });
}


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

try {
  userSchema.pre("save", function(next) {
    try {
      if (this && this.isDeleted === true && (this.deletedAt == null)) {
        this.deletedAt = new Date();
      }
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return next();
  });
} catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
const User = mongoose.model("User", userSchema);

// === L7_SOCIAL_AUDIT_V1 (append-only) ===
const socialAuditSchema = new mongoose.Schema({
  actorId: String,
  targetType: String,
  targetId: String,
  action: String,
  meta: Object,
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });
socialAuditSchema.index({ createdAt: -1 });
const SocialAudit = mongoose.models.SocialAudit || mongoose.model("SocialAudit", socialAuditSchema);
// === END L7_SOCIAL_AUDIT_V1 ===

try {
  experienceSchema.pre("save", function(next) {
    try {
      if (this && this.isDeleted === true && (this.deletedAt == null)) {
        this.deletedAt = new Date();
      }
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return next();
  });
} catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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
const financialLedgerSchema = new mongoose.Schema(
  {
    bookingId: { type: String, default: "" },
    eventId: { type: String, default: "" },
    eventType: { type: String, default: "" },
    stripeObjectId: { type: String, default: "" },
    amountCents: { type: Number, default: 0 },
    currency: { type: String, default: "aud" },
    status: { type: String, default: "" },
    note: { type: String, default: "" },
    meta: { type: Object, default: {} },
  },
  { timestamps: true }
);
try { financialLedgerSchema.index({ eventId: 1, eventType: 1 }, { unique: true, sparse: true }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
const FinancialLedger = mongoose.model("FinancialLedger", financialLedgerSchema);

async function __ledgerAppendOnce(entry) {
  try {
    const e = (entry && typeof entry === "object") ? entry : {};
    const eventId = String(e.eventId || "").trim();
    const eventType = String(e.eventType || "").trim();
    if (!eventId || !eventType) return false;

    const doc = {
      bookingId: String(e.bookingId || ""),
      eventId: eventId,
      eventType: eventType,
      stripeObjectId: String(e.stripeObjectId || ""),
      amountCents: Number.isFinite(Number(e.amountCents)) ? Number(e.amountCents) : 0,
      currency: String(e.currency || "aud"),
      status: String(e.status || ""),
      note: String(e.note || ""),
      meta: (e.meta && typeof e.meta === "object") ? e.meta : {},
    };

    try {
      await FinancialLedger.create(doc);
      return true;
    } catch (err) {
      const msg = (err && err.message) ? String(err.message) : "";
      if (msg.toLowerCase().indexOf("duplicate") >= 0) return true;
      return false;
    }
  } catch (_) {
    return false;
  }
}

// L7_DISCOVERY_GUARD_V1
function __canDiscoverUser(u) {
  try {
    return !!(u && u.discoverable === true);
  } catch (_) {
    return false;
  }
}

// L7_BLOCK_PAIR_GUARD_V1
function __isBlockedPair(meDoc, targetDoc, meId, targetId) {
  try {
    const A = String(meId || "");
    const B = String(targetId || "");
    if (!A || !B) return true;
    const a = (meDoc && Array.isArray(meDoc.blockedUserIds)) ? meDoc.blockedUserIds.map(String) : [];
    const b = (targetDoc && Array.isArray(targetDoc.blockedUserIds)) ? targetDoc.blockedUserIds.map(String) : [];
    if (a.includes(B)) return true;
    if (b.includes(A)) return true;
    return false;
  } catch (_e) {
    return true;
  }
}

// === L7_SOCIAL_GUARD_V1 ===
async function socialGuard(req, res, next) {
  const me = req.user && (req.user._id || req.user.id);
  const target =
    (req.params && (req.params.userId || req.params.id)) ||
    (req.body && req.body.userId);
  if (!me) return res.status(401).end();

  if (!target) return next();

  const UserModel = mongoose.model("User");
  try {
    const meDoc = await UserModel.findById(me).select("blockedUserIds").lean();
    const targetDoc = await UserModel.findById(target).select("blockedUserIds").lean();
    if (__isBlockedPair(meDoc, targetDoc, me, target) === true) {
      return res.status(403).json({ message: "Blocked" });
    }
  } catch (_e) {
    return res.status(403).json({ message: "Blocked" });
  }

  return next();
}
// === END L7_SOCIAL_GUARD_V1 ===

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
    try { __log("error", "comms_confirm_err", { rid: __tstsRidNow(), msg: String(msg) }); } catch (_) {}
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
    try { __log("error", "comms_cancel_err", { rid: __tstsRidNow(), msg: String(msg) }); } catch (_) {}
  }
}


async function maybeSendBookingExpiredComms(booking) {
  // claim-before-send enabled
  try {
    if (!booking) return;
    try {
      if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    let __expiredGuestAlready = false;
    let __expiredHostAlready = false;
    try {
      __expiredGuestAlready = Boolean(booking.comms.bookingExpiredGuestSentAt);
      __expiredHostAlready = Boolean(booking.comms.bookingExpiredHostSentAt);
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

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
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
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
      } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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
      } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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
    try { __log("error", "comms_expired_err", { rid: __tstsRidNow(), error: String((e && e.message) ? e.message : String(e)) }); } catch (_) {}
  }
}

async function maybeSendRefundProcessedComms(booking) {
  try {
    if (!booking) return;
    try {
      if (!booking.comms || typeof booking.comms !== "object") booking.comms = {};
      const already = booking.comms.refundProcessedGuestSentAt ? new Date(booking.comms.refundProcessedGuestSentAt) : null;
      if (already) return;
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

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
      } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    }

    void hostEmail;
    void hostName;
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    try { __log("error", "comms_refund_err", { rid: __tstsRidNow(), msg: String(msg) }); } catch (_) {}
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
    try { __log("error", "comms_cancel_host_err", { rid: __tstsRidNow(), msg: String(msg) }); } catch (_) {}
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

    if (user && user.isDeleted === true) {
      return res.status(403).json({ message: "Account deleted" });
    }

    const __stDel = String(user.accountStatus || "active");
    if (__stDel === "deleted") {
      return res.status(403).json({ message: "Account deleted" });
    }

    if (user.emailVerified !== true) {
      return res.status(403).json({ message: "Email not verified" });
    }

    const st = String(user.accountStatus || "active");
    if (st && st !== "active") {
      return res.status(403).json({ message: "Account not active" });
    }

    const mu = (user.mutedUntil instanceof Date && !Number.isNaN(user.mutedUntil.getTime())) ? user.mutedUntil : null;
    if (mu && mu.getTime() > Date.now()) {
      return res.status(403).json({ message: "Account muted" });
    }

    const tv =  Number.isFinite(Number(user.tokenVersion)) ? Number(user.tokenVersion) : 0;
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

async function optionalAuthMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return next();

  const parts = String(authHeader).split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return next();

  const token = parts[1];
  try {
    if (!JWT_SECRET) return next();
    const payload = jwt.verify(token, JWT_SECRET);
    const userId = String(payload.userId || "");
    if (!userId) return next();

    const user = await User.findById(userId);
    if (!user) return next();
    if (user.isDeleted === true) return next();
    if (user.emailVerified !== true) return next();

    const st = String(user.accountStatus || "active");
    if (st && st !== "active") return next();

    const tv = Number.isFinite(Number(user.tokenVersion)) ? Number(user.tokenVersion) : 0;
    const ptv = Number.isFinite(Number(payload.tv)) ? Number(payload.tv) : 0;
    if (ptv !== tv) return next();

    req.user = user;
    req.auth = { userId };
  } catch (_) {}
  next();
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

// Note: requireAdminReason is intentionally applied at route-level for admin access and admin mutations.
 // --- ADMIN: PROMO CODES ---
// Universal promo: appliesToExperienceIds=[] and appliesToHostIds=[].
// Experience-specific (including multi-experience): appliesToExperienceIds=[...]
// Host-specific: appliesToHostIds=[...]
// Can combine both (host + experience scoping).
function __promoNormIdArray(v) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const x of v) {
    const t = String(x || "").trim();
    if (t) out.push(t);
  }
  const seen = new Set();
  const uniq = [];
  for (const t of out) {
    if (seen.has(t)) continue;
    seen.add(t);
    uniq.push(t);
  }
  return uniq;
}

function __promoCodeClean(v) {
  return String(v || "").trim().toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 40);
}

function __promoGenerateCode(prefix) {
  const pre = String(prefix || "PROMO").trim().toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12) || "PROMO";
  const rnd = require("crypto").randomBytes(6).toString("hex").toUpperCase();
  return (pre + "-" + rnd).slice(0, 40);
}

// Create promo
app.post("/api/admin/promo-codes", adminMiddleware, requireAdminReason, promoCreateLimiter, async (req, res) => {
  try {
    const body = (req && req.body) ? req.body : {};
    const now = new Date();

    const pct = Number(body.percentOff) || 0;
    const fixed = Number(body.fixedOffCents) || 0;

    if (pct < 0 || pct > 100) return res.status(400).json({ message: "percentOff must be 0..100" });
    if (fixed < 0) return res.status(400).json({ message: "fixedOffCents must be >= 0" });
    if (pct <= 0 && fixed <= 0) return res.status(400).json({ message: "Provide percentOff or fixedOffCents" });

    const codeIn = __promoCodeClean(body.code);
    const code = codeIn || __promoGenerateCode(body.prefix);

    const minSubtotalCents = Math.max(0, Number(body.minSubtotalCents) || 0);
    const minGuests = Math.max(0, Number(body.minGuests) || 0);

    const maxUsesTotal = Math.max(0, Number(body.maxUsesTotal) || 0);
    const maxUsesPerUser = Math.max(0, Number(body.maxUsesPerUser) || 0);

    const validFrom = body.validFrom ? new Date(body.validFrom) : null;
    if (validFrom && Number.isNaN(validFrom.getTime())) return res.status(400).json({ message: "Invalid validFrom" });

    const validTo = body.validTo ? new Date(body.validTo) : null;
    if (validTo && Number.isNaN(validTo.getTime())) return res.status(400).json({ message: "Invalid validTo" });

    if (validFrom && validTo && validTo.getTime() < validFrom.getTime()) {
      return res.status(400).json({ message: "validTo must be >= validFrom" });
    }

    const appliesToExperienceIds = __promoNormIdArray(body.appliesToExperienceIds);
    const appliesToHostIds = __promoNormIdArray(body.appliesToHostIds);

    const exists = await PromoCode.findOne({ code: code }).lean();
    if (exists) return res.status(409).json({ message: "Promo code already exists", code: code });

    const doc = await PromoCode.create({
      code: code,
      active: (typeof body.active === "boolean") ? Boolean(body.active) : true,

      percentOff: pct,
      fixedOffCents: Math.floor(fixed),

      currency: String(body.currency || "aud").toLowerCase(),

      minSubtotalCents: Math.floor(minSubtotalCents),
      minGuests: Math.floor(minGuests),

      validFrom: validFrom,
      validTo: validTo,

      maxUsesTotal: Math.floor(maxUsesTotal),
      maxUsesPerUser: Math.floor(maxUsesPerUser),

      appliesToExperienceIds: appliesToExperienceIds,
      appliesToHostIds: appliesToHostIds,

      note: String(body.note || ""),
      createdAt: now,
      updatedAt: now
    });

    return res.json({ ok: true, promo: doc });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// List promos (latest 200)
app.get("/api/admin/promo-codes", adminMiddleware, requireAdminReason, async (req, res) => {
  try {
    const q = (req && req.query) ? req.query : {};
    const activeRaw = (typeof q.active === "string") ? String(q.active).trim().toLowerCase() : "";
    const codeRaw = (typeof q.code === "string") ? __promoCodeClean(q.code) : "";
    const filt = {};
    if (activeRaw == "true") filt["active"] = true;
    if (activeRaw == "false") filt["active"] = false;
    if (codeRaw) filt["code"] = codeRaw;

    const docs = await PromoCode.find(filt).sort({ createdAt: -1 }).limit(200).lean();
    return res.json({ ok: true, promos: docs });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Toggle active
app.put("/api/admin/promo-codes/:code/active", adminMiddleware, requireAdminReason, async (req, res) => {
  try {
    const code = __promoCodeClean((req && req.params && req.params.code) ? req.params.code : "");
    if (!code) return res.status(400).json({ message: "code required" });

    const body = (req && req.body) ? req.body : {};
    const active = (typeof body.active === "boolean") ? Boolean(body.active) : Boolean(body && body.active);

    const __D = String.fromCharCode(36);
    const upd = { };
    upd[__D + "set"] = { active: active, updatedAt: new Date() };

    const doc = await PromoCode.findOneAndUpdate(
      { code: code },
      upd,
      { new: true }
    ).lean();

    if (!doc) return res.status(404).json({ message: "Promo not found" });
    return res.json({ ok: true, promo: doc });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});


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

app.post("/api/policy/draft", adminMiddleware, requireAdminReason, async (req, res) => {
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

app.post("/api/policy/publish", adminMiddleware, requireAdminReason, async (req, res) => {
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
  const roleLower = String(role || "").toLowerCase();
  const roleIsHost = roleLower === "host";
  const roleIsAdmin = roleLower === "admin";
  const isAdmin = (!!obj.isAdmin) || (obj.admin === true) || roleIsAdmin;

  // SELF DTO ONLY (PRIVATE): allowlist fields; DO NOT leak internal/security fields
  return {
    _id: obj._id,
    id: obj.id || (obj._id ? String(obj._id) : ""),

    name: String(obj.name || ""),
    email: String(obj.email || ""),     // PRIVATE (self only)
    mobile: String(obj.mobile || ""),   // PRIVATE (self only)

    role,
    isHost: roleIsHost,
    isAdmin: isAdmin,
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



// --- TIME SLOT NORMALIZATION (prevents 10:00 vs 10:00 AM mismatches) ---
// Canonical key: "HH:MM" in 24h (e.g., "10:00", "18:30").
// Accepts inputs like "10:00", "10:00 AM", "10:00AM", "6:30 pm", "18:30".
function __normalizeTimeSlotKey(raw) {
  try {
    const s0 = String(raw || "").trim();
    if (!s0) return "";
    let t = s0.toLowerCase().replace(/\./g, "").replace(/\s+/g, " ").trim();
    const m = t.match(/^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/i);
    if (!m) return s0.trim();
    let hh = Number(m[1]);
    let mm = (m[2] != null) ? Number(m[2]) : 0;
    const ap = (m[3] || "").toLowerCase();
    if (!(hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59)) return s0.trim();
    if (ap === "am" || ap === "pm") {
      if (hh === 12) hh = (ap === "am") ? 0 : 12;
      else if (ap === "pm") hh = hh + 12;
    }
    if (!(hh >= 0 && hh <= 23)) return s0.trim();
    const pad2 = (n) => (n < 10 ? "0" : "") + String(n);
    return pad2(hh) + ":" + pad2(mm);
  } catch (_) {
    return String(raw || "").trim();
  }
}

function __normalizeSlotsArray(arr) {
  try {
    if (Array.isArray(arr) == false) return [];
    const out = [];
    const seen = new Set();
    for (const it of arr) {
      const k = __normalizeTimeSlotKey(it);
      if (!k) continue;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(k);
    }
    return out;
  } catch (_) {
    return [];
  }
}



function __getBookingGuestCount(booking) {
  try {
    if (!booking) return 0;

    const a = Number.parseInt(String((booking && booking.numGuests) || "0"), 10) || 0;
    if (a > 0) return a;

    const b = Number.parseInt(String((booking && booking.guests) || "0"), 10) || 0;
    if (b > 0) return b;

    return 0;
  } catch (_) {
    return 0;
  }
}

async function reserveCapacitySlot(experienceId, dateStr, timeSlot, guests) {
  const expId = String(experienceId || "").trim();
  const d = String(dateStr || "").trim();
  const slotRaw = String(timeSlot || "").trim();
  const slotKey = __normalizeTimeSlotKey(slotRaw);
  const slotAlt = slotRaw;
  const slot = slotKey || slotAlt;
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
  let did = Boolean(matched > 0 || upserted > 0);


// L2_LEGACY_SLOT_FALLBACK_RESERVE_V1: if normalized key did not match any row, try raw slot
// This reduces duplicate CapacitySlot rows when old data uses a different representation.
if (!did && slotAlt && slot && slotAlt !== slot) {
  try {
    const qLegacy = { experienceId: String(expId), bookingDate: d, timeSlot: slotAlt };
    qLegacy[OR] = q[OR];
    const rL = await CapacitySlot.updateOne(qLegacy, upd, { upsert: false });
    const matchedL = Number(rL && rL.matchedCount) || 0;
    did = Boolean(matchedL > 0);
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
}
  if (did) return { ok: true, maxGuests: maxGuests };

  const cur = await CapacitySlot.findOne({ experienceId: String(expId), bookingDate: d, timeSlot: slot }).lean();
  const curReserved = cur && (typeof cur.reservedGuests === "number") ? Number(cur.reservedGuests) : 0;
  const remaining = maxGuests - curReserved;
  return { ok: false, remaining: remaining, message: remaining > 0 ? ("Only " + String(remaining) + " spots left.") : "Fully booked." };
}

async function releaseCapacitySlot(experienceId, dateStr, timeSlot, guests) {
  const expId = String(experienceId || "").trim();
  const d = String(dateStr || "").trim();
  const slotRaw = String(timeSlot || "").trim();
  const slotKey = __normalizeTimeSlotKey(slotRaw);
  const slotAlt = slotRaw;
  const slot = slotKey || slotAlt;
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
    { reservedGuests: (function(){ const x={}; x[EXISTS]=true; x[GTE]=g; return x; })() }
  ];

  const upd = {};
  upd[INC] = { reservedGuests: (0 - g) };
  upd[SET] = { updatedAt: new Date() };

  await CapacitySlot.updateOne(q, upd);

// L2_LEGACY_SLOT_FALLBACK_RELEASE_V1: if normalized key did not match any row, try raw slot
if (slotAlt && slot && slotAlt !== slot) {
  try {
    const qLegacy = { experienceId: String(expId), bookingDate: d, timeSlot: slotAlt };
    qLegacy[OR] = q[OR];
    await CapacitySlot.updateOne(qLegacy, upd);
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
}


  const q2 = { experienceId: String(expId), bookingDate: d, timeSlot: slot, reservedGuests: (function(){ const x={}; x[LT]=0; return x; })() };
  const upd2 = {};
  upd2[SET] = { reservedGuests: 0, updatedAt: new Date() };
  await CapacitySlot.updateOne(q2, upd2);
}


// L2_HOST_CANCEL_CAPACITY_HELPER: single canonical atomic release guard
// - Claims capacityReleasedAt atomically (prevents double release across retries/instances)
// - Releases capacity only when claim succeeded
// - Reverts claim if release fails
async function __releaseCapacityOnceAtomic(booking, reasonTag) {
  try {
    if (!booking) return;
    if (booking.capacityReleasedAt) return;

    const SET = String.fromCharCode(36) + "set";
    const UNSET = String.fromCharCode(36) + "unset";
    const now = new Date();

    const claimUpd = {};
    claimUpd[SET] = { capacityReleasedAt: now };

    const rClaim = await Booking.updateOne({ _id: booking._id, capacityReleasedAt: null }, claimUpd);
    const claimed = Boolean((Number(rClaim && rClaim.matchedCount) || 0) > 0);
    if (!claimed) return;

    try {
      const expId = String((booking && (booking.experienceId || booking.experience)) || "");
      const dateStr = String((booking && (booking.bookingDate || "")) || "");
      const slotRaw = String((booking && (booking.timeSlot || "")) || "");
      const slotKey = __normalizeTimeSlotKey(slotRaw);
      const slot = slotKey || slotRaw;

      const g = __getBookingGuestCount(booking);
      if (!expId || !dateStr || !slot || g <= 0) {
        try { booking.capacityReleasedAt = booking.capacityReleasedAt || now; } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
        return;
      }

      let cur = null;
      try { cur = await CapacitySlot.findOne({ experienceId: expId, bookingDate: dateStr, timeSlot: slot }).lean(); } catch (_) { cur = null; }
      if (cur == null && slotKey && slotKey != slotRaw) {
        try { cur = await CapacitySlot.findOne({ experienceId: expId, bookingDate: dateStr, timeSlot: slotRaw }).lean(); } catch (_) { cur = null; }
      }

      const curR = (cur && typeof cur.reservedGuests === "number") ? Number(cur.reservedGuests) : 0;
      if (curR >= g) {
        try {
          await releaseCapacitySlot(expId, dateStr, slot, g);
        } catch (_) {
          const rev = {};
          rev[UNSET] = { capacityReleasedAt: 1 };
          try { await Booking.updateOne({ _id: booking._id, capacityReleasedAt: now }, rev); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
        }
      }
    } catch (_) {
      // keep claim; do not risk double-release later
      return;
    }

    try { booking.capacityReleasedAt = booking.capacityReleasedAt || now; } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
}

// L2_HOST_CANCEL_CANONICAL_V1:
// Always release capacity atomically before setting cancelled_by_host.
// Use this for ALL host cancellation paths (single reject, bulk delete, admin ops, etc).
async function __hostCancelBookingAtomic(booking, reasonTag, meta) {
  try {
    await __releaseCapacityOnceAtomic(booking, reasonTag || "host_cancel");
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  try {
    if (meta && typeof meta === "object") {
      return await transitionBooking(booking, "cancelled_by_host", meta);
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  return await transitionBooking(booking, "cancelled_by_host");
}





async function checkCapacity(experienceId, date, timeSlot, newGuests) {
  const dateStr = String(date || "").trim();
  const slotRaw = String(timeSlot || "").trim();
  const slotKey = __normalizeTimeSlotKey(slotRaw);
  const slot = slotKey || slotRaw;

  const isoOk = /^\d{4}-\d{2}-\d{2}$/.test(dateStr);
  if (!isoOk) return { available: false, message: "Invalid bookingDate (YYYY-MM-DD required)." };
  if (!slot) return { available: false, message: "timeSlot is required." };

  const exp = await Experience.findById(experienceId);
  if (!exp) return { available: false, message: "Experience not found." };

  if (exp.isPaused) return { available: false, message: "Host is paused." };
  if (exp.blockedDates && exp.blockedDates.includes(dateStr)) return { available: false, message: "Date blocked." };

  const allowedSlots = __normalizeSlotsArray(exp.timeSlots);
  if (allowedSlots.length > 0 && !allowedSlots.includes(slot)) {
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

  const currentCount = existing.reduce((sum, b) => sum + (__getBookingGuestCount(b) || 0), 0);
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
    if (typeof clean.name !== "undefined") clean.name = String(clean.name || "").trim().slice(0, 100);
    if (typeof clean.handle !== "undefined") clean.handle = String(clean.handle || "").trim().slice(0, 32);
    if (typeof clean.mobile !== "undefined") clean.mobile = String(clean.mobile || "").trim().slice(0, 40);
    if (typeof clean.profilePic !== "undefined") clean.profilePic = String(clean.profilePic || "").trim().slice(0, 600);
    if (typeof clean.email !== "undefined") clean.email = String(clean.email).toLowerCase().trim();
    const emailNorm = String(body.email || "").toLowerCase().trim();
    const pwRaw = (typeof body.password === "undefined") ? "" : String(body.password || "");
    const pwConf = (typeof body.confirmPassword === "undefined") ? "" : String(body.confirmPassword || "");
    if (!emailNorm || !pwRaw || !pwConf) return res.status(400).json({ message: "Email, password and confirmPassword required" });
    if (pwRaw !== pwConf) return res.status(400).json({ message: "Passwords do not match", code: "password_confirm_register" });
    const __pp = __passwordPolicyOk(pwRaw);
    if (!__pp.ok) return res.status(400).json({ message: __pp.reason, code: "password_policy_register" });
    const __existing = await User.findOne({ email: emailNorm });
    if (__existing) {
      if (__existing.isDeleted === true) {
        return res.status(409).json({ message: "Account deleted", code: "account_deleted" });
      }
      return res.status(400).json({ message: "Taken" });
    }

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
      const verifyUrlBackend = (__apiBase || "") + "/api/auth/verify-email?email=" + encodeURIComponent(String(user.email || "")) + "#token=" + encodeURIComponent(String(vtoken || ""));
      const verifyUrlFrontend = __frontendBaseUrl() + "/verify-email.html?email=" + encodeURIComponent(String(user.email || "")) + "#token=" + encodeURIComponent(String(vtoken || ""));
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
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    const __t = signToken(user);
    const __u = sanitizeUser(user);
    const __resp = { ok: true, data: { token: __t, user: __u }, token: __t, user: __u };

    const __vdbgSecret = String(process.env.VERIFY_DEBUG_SECRET || "").trim();
    const __vdbgHeader = String((req.headers && (req.headers["x-verify-debug-secret"] || req.headers["X-Verify-Debug-Secret"])) || "").trim();
    const __isProd = (String(process.env.NODE_ENV || "").toLowerCase() == "production");

    if (!__isProd && __vdbgSecret.length >= 24 && __vdbgHeader) {
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
    if (__isDuplicateKeyError(e)) {
      __log("warn", "auth_register_duplicate", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
      return res.status(400).json({ message: "Handle taken", code: "handle_taken" });
    }
    __log("error", "auth_register_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    res.status(500).json({ message: "Error" });
  }
});

// Auth: Login

// Auth: Verify Email
// Auth: Verify Email (STATE CHANGE MUST BE POST)
app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const emailRaw = (req.body && req.body.email) ? String(req.body.email) : "";
    const tokenRaw = (req.body && req.body.token) ? String(req.body.token) : "";
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
    } catch (_) {
      try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Back-compat: GET must NOT change state (email prefetchers may hit GET links)
app.get("/api/auth/verify-email", async (req, res) => {
  return res.status(405).json({ message: "Use POST /api/auth/verify-email" });
});

// Auth: Resend Verification Email
app.post("/api/auth/resend-verification", forgotPasswordLimiter, async (req, res) => {
  try {
    const emailRaw = (req.body && req.body.email) ? String(req.body.email) : "";
    const email = emailRaw.toLowerCase().trim();

    // Always respond OK (do not leak account existence)
    if (!email) {
      return res.json({ ok: true, message: "If your email is registered, you will receive a new verification link." });
    }

    const user = await User.findOne({ email });

    // Privacy-safe: always return same message regardless of user existence
    if (!user) {
      return res.json({ ok: true, message: "If your email is registered, you will receive a new verification link." });
    }

    // If already verified, no need to resend
    if (user.emailVerified === true) {
      return res.json({ ok: true, message: "If your email is registered, you will receive a new verification link." });
    }

    // If account is deleted or not active, still return generic message
    if (user.isDeleted === true) {
      return res.json({ ok: true, message: "If your email is registered, you will receive a new verification link." });
    }
    const st = String(user.accountStatus || "active");
    if (st && st !== "active") {
      return res.json({ ok: true, message: "If your email is registered, you will receive a new verification link." });
    }

    // Generate new verification token
    const vtoken = crypto.randomBytes(32).toString("hex");
    const vhash = crypto.createHash("sha256").update(vtoken).digest("hex");
    user.emailVerificationTokenHash = vhash;
    user.emailVerificationRequestedAt = new Date();
    user.emailVerificationExpiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    await user.save();

    // Send verification email (non-blocking)
    try {
      const verifyUrlFrontend = __frontendBaseUrl() + "/verify-email.html?email=" + encodeURIComponent(String(user.email || "")) + "#token=" + encodeURIComponent(String(vtoken || ""));

      const __p = __sendEventEmailTracked({
        eventName: "EMAIL_VERIFICATION",
        category: "SECURITY",
        to: String(user.email || ""),
        vars: { Name: String(user.name || "there"), VERIFY_EMAIL_URL: String(verifyUrlFrontend || "") }
      }, { rid: __ridFromReq(req), source: "auth_resend_verification" });
      const __t = new Promise((_, rej) => setTimeout(() => rej(new Error("email_timeout")), 6000));
      Promise.race([__p, __t]).catch(() => {});
    } catch (_) {
      try { __log("warn", "resend_verification_email_error", { rid: __ridFromReq(req) }); } catch (_) {}
    }

    return res.json({ ok: true, message: "If your email is registered, you will receive a new verification link." });
  } catch (e) {
    __log("error", "auth_resend_verification_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    if (user && user.isDeleted === true) {
      return res.status(403).json({ message: "Account deleted" });
    }
    const st = String(user.accountStatus || "active");
    if (st && st !== "active") {
      return res.status(403).json({ message: "Account not active" });
    }

    if (user.emailVerified !== true) {
      return res.status(403).json({ message: "Please verify your email.", code: "email_not_verified" });
    }


    const ok = await bcrypt.compare(String(password), String(user.password || ""));
    if (!ok) return res.status(401).json({ ok: false, error: "INVALID_CREDENTIALS", message: "Invalid credentials" });

    const __t = signToken(user);
    const __u = sanitizeUser(user);
    return res.json({ ok: true, data: { token: __t, user: __u }, token: __t, user: __u });
  } catch (e) {
    __log("error", "auth_login_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    return res.status(500).json({ ok: false, error: "LOGIN_FAILED", message: "Login failed" });
  }
});

// Auth: Current user

// Auth: Forgot Password (privacy-safe)
app.post("/api/auth/forgot-password", forgotPasswordLimiter, forgotPasswordEmailLimiter, async (req, res) => {
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
      const hasSmtp = !!process.env.SMTP_HOST && !!process.env.SMTP_USER && !!process.env.SMTP_PASS;
      const hasResend = String(process.env.RESEND_API_KEY || "").trim().length > 0;
      const canEmail = hasSmtp || hasResend;
      const frontendBase = String(process.env.FRONTEND_BASE_URL || "http://localhost:3000").replace(/\/$/, "");
      const resetUrl = `${frontendBase}/reset-password.html?email=${encodeURIComponent(email)}#token=${encodeURIComponent(token)}`;
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
      const __isProd = (String(process.env.NODE_ENV || "").toLowerCase() == "production");
      if (!__isProd && __dbgSecret.length >= 24 && __dbgHeader) {
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
        const __isProdDbg = (String(process.env.NODE_ENV || "").toLowerCase() == "production");
        if (!__isProdDbg && __hdrPresent) {
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
      } catch (e) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    return res.json({ ok: true, message: "If an account exists, you will receive instructions." });
  } catch (e) {
    return res.json({ ok: true, message: "If an account exists, you will receive instructions." });
  }
});

// Auth: Reset Password
app.post("/api/auth/reset-password", resetPasswordLimiter, resetPasswordEmailLimiter, async (req, res) => {
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
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

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

// G2: Cloudinary signed upload signature endpoint
app.post("/api/uploads/cloudinary-signature", authMiddleware, async (req, res) => {
  try {
    const timestamp = Math.round(Date.now() / 1000);
    const cloudName = String(process.env.CLOUDINARY_CLOUD_NAME || "").trim();
    const apiKey = String(process.env.CLOUDINARY_API_KEY || "").trim();
    const apiSecret = String(process.env.CLOUDINARY_API_SECRET || "").trim();

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).json({ message: "Cloudinary not configured" });
    }

    const paramsToSign = {
      timestamp: timestamp,
      folder: "shared-table-uploads",
      resource_type: "image"
    };

    const signature = cloudinary.utils.api_sign_request(paramsToSign, apiSecret);

    return res.json({
      timestamp: timestamp,
      signature: signature,
      apiKey: apiKey,
      cloudName: cloudName,
      folder: "shared-table-uploads"
    });
  } catch (e) {
    __log("error", "cloudinary_signature_error", { rid: __ridFromReq(req), error: (e && e.message) || String(e) });
    return res.status(500).json({ message: "Signature generation failed" });
  }
});

// Auth: Update profile (allowlist)
app.put("/api/auth/update", authMiddleware, authLimiter, async (req, res) => {
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

    if (typeof updates.name !== "undefined") updates.name = __toStrSafe(updates.name).slice(0, 100);
    if (typeof updates.bio !== "undefined") updates.bio = __toStrSafe(updates.bio).slice(0, 500);
    if (typeof updates.location !== "undefined") updates.location = __toStrSafe(updates.location).slice(0, 120);
    if (typeof updates.mobile !== "undefined") updates.mobile = __toStrSafe(updates.mobile).slice(0, 40);
    if (typeof updates.profilePic !== "undefined") updates.profilePic = __toStrSafe(updates.profilePic).slice(0, 600);

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
    if (__isDuplicateKeyError(e)) {
      __log("warn", "auth_update_duplicate", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
      return res.status(400).json({ message: "Handle taken", code: "handle_taken" });
    }
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
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

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

    const __toArrStr = (v) => {
      let a = [];
      if (Array.isArray(v)) a = v;
      else if (typeof v !== "undefined" && v !== null) a = [v];
      return a.map((x) => __toStr(x)).filter((x) => x);
    };

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
      "timeSlots",
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


    if (typeof expData.timeSlots !== "undefined") {
      expData.timeSlots = __toArrStr(expData.timeSlots);
    }
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
    if (exp.isDeleted) return res.status(404).json({ message: "Not found" });
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
      try { await __releaseCapacityOnceAtomic(b, "experience_delete"); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      try { await __hostCancelBookingAtomic(b, "host_cancel"); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  exp.isDeleted = true;
  exp.deletedAt = new Date();
  exp.deletedBy = String((req.user && (req.user._id || req.user.id)) || "");
  exp.isPaused = true;
  await exp.save();
  res.json({ message: "Deleted" });
});

// Experiences: Search (filters + pillars)
app.get("/api/experiences", async (req, res) => {
  const rid = __ridFromReq(req);
  try {
    const qv = (req && req.query) ? req.query : {};
    const city = qv.city;
    const q = qv.q;
    const sort = qv.sort;
    const date = qv.date;
    const minPrice = qv.minPrice;
    const maxPrice = qv.maxPrice;
    const category = qv.category;
    const hostId = qv.hostId;
    const page = qv.page;
    const limit = qv.limit;

    let query = { isPaused: false, isDeleted: false };

    const __safeTok = (v, maxLen) => {
      const t = String(v || "").trim();
      if (!t) return "";
      return t.slice(0, maxLen);
    };

    const __escapeRegexLiteral = (s) => {
      return String(s).replace(/[.*+?^${}()|[\]\\]/g, (m) => "\\" + m);
    };

    const cityTok = __safeTok(city, 60);
    if (cityTok) query.city = { $regex: __escapeRegexLiteral(cityTok), $options: "i" };

    const qTok = __safeTok(q, 80);
    if (qTok) query.title = { $regex: __escapeRegexLiteral(qTok), $options: "i" };

    if (category && CATEGORY_PILLARS.includes(category)) query.tags = { $in: [category] };

    const hostTok = __cleanId(hostId, 64);
    if (hostTok) {
      if (!/^[a-fA-F0-9]{24}$/.test(hostTok)) return res.status(400).json({ message: "Invalid hostId" });
      query.hostId = hostTok;
    }

    const minP = Number(minPrice);
    const maxP = Number(maxPrice);
    if (Number.isFinite(minP) || Number.isFinite(maxP)) {
      query.price = {};
      if (Number.isFinite(minP)) query.price.$gte = minP;
      if (Number.isFinite(maxP)) query.price.$lte = maxP;
      if (Object.keys(query.price).length === 0) delete query.price;
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

    const pageN = Number.isFinite(Number(page)) ? Math.max(1, Math.floor(Number(page))) : 1;
    const limitN = Number.isFinite(Number(limit)) ? Math.min(50, Math.max(1, Math.floor(Number(limit)))) : 50;
    const skipN = (pageN - 1) * limitN;

    const exps = await Experience.find(query)
      .sort(sortObj)
      .skip(skipN)
      .limit(limitN)
      .maxTimeMS(5000)
      .lean();

    const safe = (exps || []).map((e) => stripExperiencePrivateFields(e));
    return res.json(safe);
  } catch (err) {
    try { __log("error", "experiences_list_failed", { rid: rid, path: "/api/experiences", error: String((err && err.message) ? err.message : err) }); } catch (_) {}
    return res.status(500).json({ message: "Failed to load experiences" });
  }
});

// Experience detail
app.get("/api/experiences/:id", async (req, res) => {
  try {
    const expId = __cleanId(req.params.id, 64);
    if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
    const exp = await Experience.findById(expId);
    if (!exp) return res.status(404).json({ message: "Not found" });
    if (exp.isDeleted) return res.status(404).json({ message: "Not found" });
    if (exp.isPaused) return res.status(404).json({ message: "Not found" });
    const safe = stripExperiencePrivateFields((exp.toObject ? exp.toObject() : exp));
    return res.json(safe);
  } catch (err) {
    try { __log("warn", "experience_detail_error", { rid: __ridFromReq(req), error: String((err && err.message) ? err.message : err) }); } catch (_) {}
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
      isDeleted: false,
      $or: [{ tags: { $in: currentExp.tags } }, { city: currentExp.city }],
    })
      .limit(3)
      .select("title price images imageUrl city averageRating");

    if (similar.length === 0) {
      const fallback = await Experience.find({ _id: { $ne: currentExp._id }, isPaused: false, isDeleted: false })
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
    }).populate("guestId", "name profilePic bio handle publicProfile isDeleted accountStatus");

    const seen = new Set();
    const publicGuests = [];
    for (const b of bookings) {
      if (!b.guestId) continue;
      const u = b.guestId;
      if (u.isDeleted === true) continue;
      if (String(u.accountStatus || "") !== "active") continue;
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
app.post("/api/experiences/:id/book", authMiddleware, bookingCreateLimiter, async (req, res) => {
  const expId = __cleanId(req.params.id, 64);
  if (!expId || !/^[a-fA-F0-9]{24}$/.test(expId)) return res.status(400).json({ message: "Invalid experienceId" });
  const exp = await Experience.findById(expId);
  if (!exp) return res.status(404).json({ message: "Experience not found" });
  if (exp.isDeleted) return res.status(404).json({ message: "Experience not found" });
  if (exp.isPaused) return res.status(400).json({ message: "Host is paused." });
  const meId = String(((req.user && (req.user._id || req.user.id)) || (req.user && req.user.userId) || ""));
  const hostId = String(exp.hostId || "");
  if (meId && hostId && meId === hostId) {
    return res.status(403).json({ message: "Hosts cannot book their own experience." });
  }

  // L7_SOCIAL_BOOKING_GUARD_V1: blocked users cannot transact (guest<->host) via booking route
  try {
    const u = await UserModel.findById(meId).select("blockedUserIds").lean();
    const blocked = (u && Array.isArray(u.blockedUserIds)) ? u.blockedUserIds.map(String) : [];
    if (meId && hostId && blocked.includes(String(hostId))) {
      return res.status(403).json({ message: "Blocked" });
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  try {
    const h = await UserModel.findById(hostId).select("blockedUserIds").lean();
    const hBlocked = (h && Array.isArray(h.blockedUserIds)) ? h.blockedUserIds.map(String) : [];
    if (meId && hostId && hBlocked.includes(String(meId))) {
      return res.status(403).json({ message: "Blocked" });
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  const { numGuests, isPrivate, bookingDate, timeSlot, guestNotes, promoCode } = req.body || {};
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
  const timeSlotRaw = String(timeSlot || "").trim();
  const timeSlotKey = __normalizeTimeSlotKey(timeSlotRaw);
  const timeSlotStr = timeSlotKey || timeSlotRaw;

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

    // FINAL LOCKED MARKETPLACE PRICING (pricing.js)
  // Discounts apply ONLY to host base. Platform fee is computed on host base and never discounted.
  const dd = (exp && exp.dynamicDiscounts && typeof exp.dynamicDiscounts === "object") ? exp.dynamicDiscounts : {};
  const ddGroup = (dd && dd.group && typeof dd.group === "object") ? dd.group : {};

  const hostCfg = (ddGroup && ddGroup.host && typeof ddGroup.host === "object") ? ddGroup.host : {};
  const adminCfg = (ddGroup && ddGroup.admin && typeof ddGroup.admin === "object") ? ddGroup.admin : {};

  const hostEnabled = Boolean(hostCfg && hostCfg.enabled);
  const adminEnabled = Boolean(adminCfg && adminCfg.enabled);

  const hostTier = hostEnabled ? __pickTier(hostCfg.tiers, guests) : null;
  const adminTier = adminEnabled ? __pickTier(adminCfg.tiers, guests) : null;

  const hostPctRequested = hostTier ? (Number(hostTier.percent) || 0) : 0;
  const adminPricingDoc = await getActiveAdminPricingPolicyDoc();
  const adminPricingSnap = adminPricingPolicySnapshotFromDoc(adminPricingDoc);

  const adminPctDefault =
    (adminPricingSnap && adminPricingSnap.rules && Number.isFinite(Number(adminPricingSnap.rules.adminPctDefault)))
      ? Number(adminPricingSnap.rules.adminPctDefault)
      : 0;

  const adminPctCap =
    (adminPricingSnap && adminPricingSnap.rules && Number.isFinite(Number(adminPricingSnap.rules.adminPctCap)))
      ? Number(adminPricingSnap.rules.adminPctCap)
      : 0;

  const adminPctRaw = adminTier ? (Number(adminTier.percent) || 0) : adminPctDefault;
  const adminPctRequested = Math.max(0, Math.min(50, Math.min(adminPctCap > 0 ? adminPctCap : 50, adminPctRaw)));

  let hostBasePriceCents = totalCents;
  let preDiscountCents = hostBasePriceCents;
  let discountSource = "";
  let discountPct = 0;
  let discountMinGuests = 0;

  // Private booking: fixed host base, no discounts/promos/subsidy mechanics
  if (__isPrivate && exp.privatePrice) {
    hostBasePriceCents = toCents(exp.privatePrice);
    preDiscountCents = hostBasePriceCents;
    description = "Private Booking";
  }

  const disc = pricing.computeDiscountsAndPromo({
    hostBasePriceCents: hostBasePriceCents,
    hostPct: hostPctRequested,
    adminPct: adminPctRequested,
    promoPctRequested: 0
  });

  const pf = pricing.computePlatformFeeCentsGross({
    hostBasePriceCents: hostBasePriceCents,
    platformFeePolicy: (adminPricingSnap && adminPricingSnap.rules) ? adminPricingSnap.rules.platformFeePolicy : null
  });

  const guestDisplayedPriceCents = pricing.computeGuestDisplayedPriceCents({
    finalHostChargeCents: disc.finalHostChargeCents,
    platformFeeCentsGross: pf.platformFeeCentsGross
  });

  const acct = pricing.computeHostPayoutAndSubsidy({
    hostBasePriceCents: hostBasePriceCents,
    hostPctApplied: disc.hostPctApplied,
    finalHostChargeCents: disc.finalHostChargeCents
  });

  // Map to legacy locals used downstream
  totalCents = guestDisplayedPriceCents;
  hostPayoutCents = acct.hostPayoutCents;
  adminSubsidyCents = acct.adminSubsidyCents;

  discountPct = Number(disc.priceDiscountPctApplied) || 0;
  if (discountPct > 0) {
    description += " (" + String(discountPct) + "% Discount Applied)";
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
          const slRaw = String(sl || "").trim();
          if (!slRaw) continue;

          const slKey = __normalizeTimeSlotKey(slRaw);
          const slCanon = slKey || slRaw;

          let cur = await CapacitySlot.findOne({ experienceId: String(exp._id), bookingDate: d2, timeSlot: slCanon }).lean();
          if (cur == null && slKey && slKey != slRaw) {
            cur = await CapacitySlot.findOne({ experienceId: String(exp._id), bookingDate: d2, timeSlot: slRaw }).lean();
          }

          const rsv = (cur && typeof cur.reservedGuests === "number") ? Number(cur.reservedGuests) : 0;
          if (rsv === 0) {
            next = { bookingDate: d2, timeSlot: slCanon };
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


  const promoRaw = String(promoCode || "").trim();
  let promoApplied = null;
  let promoOffCents = 0;
  let promoRedemptionPending = null;

  if (promoRaw) {
    const code = promoRaw.toUpperCase();
    const now = new Date();
    const meId = String(((req.user && (req.user._id || req.user.id)) || ""));

    let ok = true;
    let reason = "";

    const promo = await PromoCode.findOne({ code: code, active: true }).lean();
    if (!promo) {
      ok = false;
      reason = "not_found";
    }

    if (ok) {
      const vf = promo.validFrom ? new Date(promo.validFrom) : null;
      const vt = promo.validTo ? new Date(promo.validTo) : null;
      if (vf && now < vf) { ok = false; reason = "outside_window"; }
      if (vt && now > vt) { ok = false; reason = "outside_window"; }
    }

    if (ok && promo.minGuests && Number(promo.minGuests) > 0) {
      if (Number(guests) < Number(promo.minGuests)) { ok = false; reason = "min_guests"; }
    }

    if (ok && promo.minSubtotalCents && Number(promo.minSubtotalCents) > 0) {
      if (Number(totalCents) < Number(promo.minSubtotalCents)) { ok = false; reason = "min_subtotal"; }
    }

    if (ok && promo.maxUsesTotal && Number(promo.maxUsesTotal) > 0) {
      const used = await PromoRedemption.countDocuments({ promoCode: code, ok: true });
      if (used >= Number(promo.maxUsesTotal)) { ok = false; reason = "max_total_reached"; }
    }

    if (ok && promo.maxUsesPerUser && Number(promo.maxUsesPerUser) > 0 && meId) {
      const usedU = await PromoRedemption.countDocuments({ promoCode: code, ok: true, userId: meId });
      if (usedU >= Number(promo.maxUsesPerUser)) { ok = false; reason = "max_user_reached"; }
    }

    if (ok && promo.appliesToExperienceIds && Array.isArray(promo.appliesToExperienceIds) && promo.appliesToExperienceIds.length > 0) {
      const okExp = promo.appliesToExperienceIds.map((x) => String(x)).includes(String(exp._id));
      if (!okExp) { ok = false; reason = "not_eligible_experience"; }
    }

    if (ok && promo.appliesToHostIds && Array.isArray(promo.appliesToHostIds) && promo.appliesToHostIds.length > 0) {
      const okHost = promo.appliesToHostIds.map((x) => String(x)).includes(String(exp.hostId || ""));
      if (!okHost) { ok = false; reason = "not_eligible_host"; }
    }

    if (ok) {
      const pct = Number(promo.percentOff) || 0;
      const fixed = Number(promo.fixedOffCents) || 0;

      // Kernel owns totals; this block only records promo intent.
      promoApplied = { code: code, percentOff: pct, fixedOffCents: fixed, amountOffCents: 0, appliedAt: new Date() };
    }

    promoRedemptionPending = {
      promoCode: code,
      userId: meId,
      ok: Boolean(ok),
      reason: String(reason || ""),
      amountOffCents: Number(promoOffCents) || 0,
      createdAt: new Date()
    };
  }

  const pricingSnapshot = pricing.computeBookingPricingSnapshot({
    unitCents: unitCents,
    guests: guests,

    isPrivate: Boolean(__isPrivate),
    privateHostBaseCents: (__isPrivate && exp && exp.privatePrice) ? toCents(exp.privatePrice) : null,

    hostPctRequested: hostPctRequested,
    adminPctRequested: adminPctRequested,

    promoPercentOff: (promoApplied && promoApplied.percentOff != null) ? Number(promoApplied.percentOff) : 0,
    promoFixedOffCents: (promoApplied && promoApplied.fixedOffCents != null) ? Number(promoApplied.fixedOffCents) : 0,

    platformFeePolicy: (adminPricingSnap && adminPricingSnap.rules) ? adminPricingSnap.rules.platformFeePolicy : null,

    description: String(description || "")
  });

  // Canonicalize legacy locals from kernel (single source of truth)
  preDiscountCents = Number(pricingSnapshot.preDiscountCents) || 0;
  discountSource = (pricingSnapshot.discount && pricingSnapshot.discount.source != null) ? String(pricingSnapshot.discount.source) : "";
  discountPct = (pricingSnapshot.discount && pricingSnapshot.discount.percent != null) ? Number(pricingSnapshot.discount.percent) : 0;
  discountMinGuests = (pricingSnapshot.discount && pricingSnapshot.discount.minGuests != null) ? Number(pricingSnapshot.discount.minGuests) : 0;

  promoOffCents = Number(pricingSnapshot.promoOffCents) || 0;
  totalCents = Number(pricingSnapshot.totalCents) || 0;
  hostPayoutCents = Number(pricingSnapshot.hostPayoutCents) || 0;
  adminSubsidyCents = Number(pricingSnapshot.adminSubsidyCents) || 0;

  try { if (promoApplied && typeof promoApplied === "object") promoApplied.amountOffCents = promoOffCents; } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  try { if (promoRedemptionPending && typeof promoRedemptionPending === "object") promoRedemptionPending.amountOffCents = promoOffCents; } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  const pricingHash = require("crypto").createHash("sha256").update(JSON.stringify(pricingSnapshot)).digest("hex");

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

    // pricing breakdown (KERNEL_CANON_V1)
    pricing: {
      currency: "aud",
      unitCents: Number(pricingSnapshot.unitCents) || 0,
      guests: Number(pricingSnapshot.guests) || 0,
      subtotalCents: Number(pricingSnapshot.subtotalCents) || 0,
      hostBasePriceCents: Number(pricingSnapshot.hostBasePriceCents) || 0,
      preDiscountCents: Number(pricingSnapshot.preDiscountCents) || 0,
      platformFeeCentsGross: Number(pricingSnapshot.platformFeeCentsGross) || 0,
      promoOffCents: Number(pricingSnapshot.promoOffCents) || 0,
      discount: (pricingSnapshot.discount && typeof pricingSnapshot.discount === "object") ? pricingSnapshot.discount : { source: "", percent: 0, minGuests: 0 },
      totalCents: Number(pricingSnapshot.totalCents) || 0,
      hostPayoutCents: Number(pricingSnapshot.hostPayoutCents) || 0,
      adminSubsidyCents: Number(pricingSnapshot.adminSubsidyCents) || 0,
      description: String(pricingSnapshot.description || "")
    },

    pricingSnapshot: pricingSnapshot,
    pricingLockedAt: new Date(),
    pricingHash: pricingHash,

    feeBreakdown: {
      currency: "aud",
      unitCents: unitCents,
      guests: guests,
      subtotalCents: unitCents * guests,
      preDiscountCents: preDiscountCents,
      discountCents: Math.max(0, Number(preDiscountCents) - Math.max(0, (Number(totalCents) + Number(promoOffCents)) - Number((pricingSnapshot && pricingSnapshot.platformFeeCentsGross) || 0))),
      promoOffCents: Number(promoOffCents) || 0,
      totalCents: totalCents,
      hostPayoutCents: hostPayoutCents,
      adminSubsidyCents: adminSubsidyCents
    },

    promoApplied: promoApplied,
    cancellationAudit: [],

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
    try { await releaseCapacitySlot(String(exp._id), bookingDateStr, timeSlotStr, guests); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    throw e;
  }

  try {
    if (promoRedemptionPending && booking && booking._id) {
      await PromoRedemption.create({
        promoCode: String(promoRedemptionPending.promoCode || ""),
        userId: String(promoRedemptionPending.userId || ""),
        bookingId: String(booking._id),
        ok: Boolean(promoRedemptionPending.ok),
        reason: String(promoRedemptionPending.reason || ""),
        amountOffCents: Number(promoRedemptionPending.amountOffCents) || 0,
        createdAt: promoRedemptionPending.createdAt ? new Date(promoRedemptionPending.createdAt) : new Date()
      });
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
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
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  try {
    const baseUrl = __requirePublicUrl();
    const __currency = "aud";
    const __amountCents = Number(totalCents) || 0;
    const __pricingHash = String(booking.pricingHash || pricingHash || "");
    const __meta = {
      bookingId: String(booking._id),
      experienceId: String(exp._id),
      guestId: String(req.user._id),
      currency: __currency,
      amountCents: String(__amountCents),
      pricingHash: __pricingHash
    };

    const __expiresAtMs = (booking && booking.expiresAt) ? new Date(booking.expiresAt).getTime() : (Date.now() + (15 * 60 * 1000));
    const __expiresAt = Math.floor(__expiresAtMs / 1000);

    const session = await stripe.checkout.sessions.create({
      client_reference_id: String(booking._id),
      metadata: __meta,
      payment_intent_data: { metadata: __meta },
      payment_method_types: ["card"],
      expires_at: __expiresAt,
      line_items: [
        {
          price_data: {
            currency: __currency,
            product_data: { name: exp.title, description },
            unit_amount: __amountCents,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${baseUrl}/success.html?sessionId={CHECKOUT_SESSION_ID}&bookingId=${booking._id}`,
      cancel_url: `${baseUrl}/experience.html?id=${exp._id}&bookingId=${booking._id}`,
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
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    // Do not leave an orphan pending_payment booking without a Stripe session.
    try {
      booking.paymentStatus = "unpaid";
      booking.expiredAt = new Date();
      await booking.save();
      await transitionBooking(booking, "expired", { reason: "stripe_checkout_error", suppressComms: true });
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    __log("error", "stripe_checkout_error", { rid: __ridFromReq(req), path: (req && req.originalUrl) ? req.originalUrl : undefined });
    res.status(500).json({ message: "Payment initialization failed" });
  }
});

// Booking verify
app.post("/api/bookings/verify", optionalAuthMiddleware, bookingVerifyLimiter, async (req, res) => {
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
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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
        return res.status(400).json({ ok: false, error: "booking_session_mismatch", code: "BOOKING_SESSION_MISMATCH", message: "Session does not match booking" });
      }
    }

    const currency = String(session.currency || "aud").toLowerCase();
    const amountTotal = Number.isFinite(session.amount_total) ? Number(session.amount_total) : null;

    const expectedCents =
      (booking.feeBreakdown && Number.isFinite(booking.feeBreakdown.totalCents)) ? Number(booking.feeBreakdown.totalCents)
      : (booking.pricingSnapshot && Number.isFinite(booking.pricingSnapshot.totalCents)) ? Number(booking.pricingSnapshot.totalCents)
      : (booking.pricing && Number.isFinite(booking.pricing.totalCents)) ? Number(booking.pricing.totalCents)
      : null;

    if (expectedCents !== null && amountTotal !== null && amountTotal !== expectedCents) return res.status(400).json({ ok: false, error: "booking_amount_mismatch", code: "BOOKING_AMOUNT_MISMATCH", message: "Amount mismatch" });

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
      .select("-capacityReleasedAt")
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
  const bookings = await Booking.find({ guestId: req.user._id }).select("-capacityReleasedAt").populate("experience").sort({ bookingDate: -1 });
  res.json(bookings);
}

app.get("/api/bookings/my-bookings", authMiddleware, async (req, res) => getMyBookings(req, res));
app.get("/api/my/bookings", authMiddleware, async (req, res) => {
  try {
    res.set("Deprecation", "true");
    res.set("Sunset", "Sat, 01 Feb 2026 00:00:00 GMT");
    res.set("Link", "</api/bookings/my-bookings>; rel=\"canonical\"");
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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
      // L2_CANCEL_RELEASE_CAPACITY_ALREADY_CANCELLED
      // L2_CANCEL_RELEASE_CAPACITY: release reserved capacity once (idempotent)

      // L2_CANCEL_RELEASE_CAPACITY: release reserved capacity once (idempotent + atomic claim)
      await __releaseCapacityOnceAtomic(booking, "guest_cancel");
      try { booking.capacityReleasedAt = booking.capacityReleasedAt || new Date(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      try { await booking.save(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      return res.json({
        message: "Already cancelled",
        refund: booking.refundDecision || { status: "none", amountCents: 0, currency: "aud", percent: 0 },
      });
    }

    // L2_GUEST_CANCEL_STATE_GUARD_V1
    // Protect terminal/settled states from being overwritten by a guest cancel call.
    // (Host cancel/idempotent cases are handled above.)
    const curStatus = String(booking.status || "");
    const terminal = new Set(["refunded", "completed"]);
    if (terminal.has(curStatus)) {
      return res.status(409).json({ message: "Booking cannot be cancelled in its current state", status: curStatus });
    }

    const wasConfirmed = (curStatus == "confirmed");

    // L7_FIX_CANCEL_ORDER_V1: release reserved capacity BEFORE status transition (idempotent + atomic claim)
    await __releaseCapacityOnceAtomic(booking, "guest_cancel");
    try { booking.capacityReleasedAt = booking.capacityReleasedAt || new Date(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

    await transitionBooking(booking, "cancelled");
    booking.cancellationReason = "User requested cancellation";
    booking.cancellation = { by: "guest", at: new Date(), reasonCode: "guest_cancel", note: "" };


    const totalCents =
      (booking.pricingSnapshot && Number.isFinite(booking.pricingSnapshot.totalCents)) ? Number(booking.pricingSnapshot.totalCents)
      : (booking.feeBreakdown && Number.isFinite(booking.feeBreakdown.totalCents)) ? Number(booking.feeBreakdown.totalCents)
      : (booking.pricing && Number.isFinite(booking.pricing.totalCents)) ? Number(booking.pricing.totalCents)
      : null;

    const snap = booking.policySnapshot || null;
    const rules = (snap && snap.rules && typeof snap.rules === "object") ? snap.rules : null;

    // Prefer a platform-fee-safe refund base (finalHostChargeCents) when available.
    // Fall back to subtracting platformFeeCentsGross if present; otherwise fall back to totalCents.
    const pfCents =
      (booking.pricingSnapshot && Number.isFinite(booking.pricingSnapshot.platformFeeCentsGross)) ? Number(booking.pricingSnapshot.platformFeeCentsGross)
      : (booking.feeBreakdown && Number.isFinite(booking.feeBreakdown.platformFeeCentsGross)) ? Number(booking.feeBreakdown.platformFeeCentsGross)
      : null;

    const refundBaseCents =
      (booking.pricingSnapshot && Number.isFinite(booking.pricingSnapshot.finalHostChargeCents)) ? Number(booking.pricingSnapshot.finalHostChargeCents)
      : (totalCents !== null && pfCents !== null) ? Math.max(0, Number(totalCents) - Number(pfCents))
      : (totalCents !== null) ? Number(totalCents)
      : null;

    let refundCents = 0;
    let refundPercent = 0;
    let decisionStatus = "manual";

    if (refundBaseCents !== null && rules) {
      const cap = Number.isFinite(rules.absoluteMaxGuestRefundPercent) ? Number(rules.absoluteMaxGuestRefundPercent) : 0.95;
      const pRaw = Number.isFinite(rules.guestMaxRefundPercent) ? Number(rules.guestMaxRefundPercent) : 0.95;
      refundPercent = Math.max(0, Math.min(cap, pRaw));
      const refundPctInt = Math.round(refundPercent * 100);

      try {
        const out = pricing.computeRefundCents({ refundBaseCents: refundBaseCents, refundPct: refundPctInt });
        refundCents = Number.isFinite(Number(out && out.refundCents)) ? Number(out.refundCents) : 0;
      } catch (_) {
        refundCents = 0;
      }

      decisionStatus = "computed";
      booking.refundAmount = Number((refundCents / 100).toFixed(2)); // LEGACY UI MIRROR ONLY (do not use for logic)
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

    // L3: append-only cancellation audit (no dead fields)
    try {
      if (!Array.isArray(booking.cancellationAudit)) booking.cancellationAudit = [];
      booking.cancellationAudit.push({
        at: new Date(),
        by: "guest",
        event: "cancel_requested",
        reasonCode: (booking.cancellation && booking.cancellation.reasonCode) ? String(booking.cancellation.reasonCode) : "",
        refundBaseCents: refundBaseCents,
        refundCents: refundCents,
        refundPercent: refundPercent,
      });
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

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
      } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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
app.get("/api/reviews", async (req, res) => {
  try {
    const hostId = String(req.query.hostId || "").trim();
    const experienceId = String(req.query.experienceId || "").trim();
    const excludeExperienceId = String(req.query.excludeExperienceId || "").trim();
    const ratingRaw = String(req.query.rating || "").trim();
    const sort = String(req.query.sort || "top").trim().toLowerCase();
    const limitRaw = String(req.query.limit || "5").trim();
    const pageRaw = String(req.query.page || "1").trim();

    if (!hostId && !experienceId) {
      return res.status(400).json({ ok: false, error: "MISSING_FILTER", message: "hostId or experienceId required" });
    }

    const limit = Math.max(1, Math.min(50, parseInt(limitRaw, 10) || 5));
    const page = Math.max(1, parseInt(pageRaw, 10) || 1);
    const skip = (page - 1) * limit;

    const q = { type: "guest_to_host" };
    if (hostId) q.hostId = hostId;
    if (experienceId) q.experienceId = experienceId;
    if (excludeExperienceId && !experienceId) {
      q.experienceId = { $ne: excludeExperienceId };
    }

    if (ratingRaw) {
      const r = parseInt(ratingRaw, 10);
      if (r >= 1 && r <= 5) q.rating = r;
    }

    const sortObj = (sort === "recent") ? { date: -1, createdAt: -1 } : { rating: -1, date: -1, createdAt: -1 };

    const reviewsRaw = await Review.find(q).sort(sortObj).skip(skip).limit(limit).lean();

    const authorIds = [];
    for (const r of reviewsRaw) {
      if (r && r.authorId) authorIds.push(r.authorId);
    }

    let okSet = null;
    if (authorIds.length > 0) {
      const okUsers = await User.find({ _id: { $in: authorIds }, isDeleted: { $ne: true }, accountStatus: "active" }).select("_id").lean();
      okSet = new Set((okUsers || []).map(u => String(u._id)));
    }

    const reviews = [];
    for (const r of reviewsRaw) {
      if (!r) continue;
      if (okSet && r.authorId && okSet.has(String(r.authorId)) === false) continue;
      reviews.push(r);
    }

    return res.json({ ok: true, page: page, limit: limit, count: reviews.length, reviews: reviews });
  } catch (e) {
    try { __log("error", "reviews_fetch_failed", { rid: __tstsRidNow(), error: String((e && e.message) ? e.message : String(e)) }); } catch (_) {}
    return res.status(500).json({ ok: false, error: "REVIEWS_FETCH_FAILED" });
  }
});

app.post("/api/reviews", authMiddleware, reviewLimiter, async (req, res) => {
  // L7-7: review only after completion
  if (bookingId) {
    const BookingModel = mongoose.model("Booking");
    const b = await BookingModel.findById(bookingId).select("status").lean();
    if (!b || String(b.status).toLowerCase() != "completed") {
      return res.status(400).json({ message: "Review allowed only after completion." });
    }
  }

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
  const reviews = await Review.find({ experienceId: expId, type: "guest_to_host" }).sort({ date: -1 }).lean();

  const authorIds = Array.from(new Set((reviews || []).map((r) => String((r && r.authorId) || "")).filter(Boolean)));
  let allowed = new Set();
  if (authorIds.length > 0) {
    const okUsers = await User.find({ _id: { $in: authorIds }, isDeleted: { $ne: true }, accountStatus: "active" }).select("_id").lean();
    allowed = new Set((okUsers || []).map((u) => String(u._id)));
  }

  const out = (reviews || []).map((r) => {
    const a = String((r && r.authorId) || "");
    if (!a || !allowed.has(a)) {
      const rr = (r && typeof r === "object") ? { ...r } : r;
      if (rr && typeof rr === "object") {
        rr.authorId = "";
        rr.authorName = "Deleted user";
      }
      return rr;
    }
    return r;
  });

  return res.json(out);
});

// --- Likes --- (toggle + count)
app.post("/api/experiences/:id/like", authMiddleware, likeLimiter, async (req, res) => {
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

app.post("/api/experiences/:id/comments", authMiddleware, commentLimiter, async (req, res) => {
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

// Moderation: user reports (triage workflow)
app.post("/api/moderation/report", authMiddleware, reportLimiter, async (req, res) => {
  try {
    const body = (req && req.body && typeof req.body === "object") ? req.body : {};
    const targetType = String(body.targetType || "").trim().toLowerCase();
    const targetId = String(body.targetId || "").trim();
    const category = String(body.category || "").trim().toLowerCase();
    const message = String(body.message || "").trim();

    const allowedTargets = { user: true, experience: true, booking: true, review: true, comment: true };
    const allowedCats = { spam: true, harassment: true, fraud: true, safety: true, other: true };

    if (!allowedTargets[targetType]) return res.status(400).json({ message: "Invalid targetType" });
    if (!targetId) return res.status(400).json({ message: "targetId required" });
    if (!allowedCats[category]) return res.status(400).json({ message: "Invalid category" });

    const msg = message.slice(0, 1200);
    const u = (req && req.user) ? req.user : null;
    const reporterId = u && (u._id || u.id) ? String(u._id || u.id) : "";
    const reporterEmail = u && u.email ? String(u.email) : "";
    const reporterMasked = (typeof __maskEmail === "function") ? __maskEmail(reporterEmail) : "";
    const reporterHash = (typeof __hashEmail === "function") ? __hashEmail(reporterEmail) : "";

    const r = await Report.create({
      reporterId,
      reporterMasked,
      reporterHash,
      targetType,
      targetId,
      category,
      message: msg,
      status: "open"
    });

    return res.status(201).json({ ok: true, id: String(r._id) });
  } catch (e) {
    __log("error", "moderation_report_error", { rid: __ridFromReq(req) });
    return res.status(500).json({ message: "Report failed" });
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
      .populate("authorId", "name profilePic bio handle publicProfile isDeleted accountStatus");

    const out = comments.map((c) => {
      const u = c.authorId;
      return {
        _id: c._id,
        experienceId: expId,
        text: c.text,
        createdAt: c.createdAt,
        author: u
          ? ((u.isDeleted === true || String(u.accountStatus || "") !== "active")
              ? null
              : {
                  _id: u._id,
                  name: String(u.name || ""),
                  profilePic: u.publicProfile ? String(u.profilePic || "") : "",
                  bio: u.publicProfile ? String(u.bio || "") : "",
                  handle: String(u.handle || ""),
                  publicProfile: !!u.publicProfile,
                })
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

  // Validate experienceId format using existing pattern
  const cleanId = __cleanId(experienceId, 64);
  if (!cleanId) return res.status(400).json({ ok: false, code: "INVALID_EXPERIENCE_ID", message: "Invalid experienceId", rid: __ridFromReq(req) });

  // Validate experience existence
  const experience = await Experience.findById(cleanId);
  if (!experience) return res.status(404).json({ ok: false, code: "EXPERIENCE_NOT_FOUND", message: "Experience not found", rid: __ridFromReq(req) });

  // Check if experience is disabled or unpublished
  const isUnavailable = (experience.isDeleted === true) || (experience.isPaused === true);
  if (isUnavailable) {
    // Allow if user is admin or host
    const isAdmin = Boolean(req.user && (req.user.isAdmin === true || String(req.user.role || "").toLowerCase() === "admin"));
    const isHost = String(experience.hostId) === String(userId);
    
    if (!isAdmin && !isHost) {
      return res.status(403).json({ ok: false, code: "EXPERIENCE_NOT_AVAILABLE", message: "Experience not available", rid: __ridFromReq(req) });
    }
  }

  const existing = await Bookmark.findOne({ userId, experienceId: cleanId });
  if (existing) {
    await Bookmark.findByIdAndDelete(existing._id);
    return res.json({ ok: true, message: "Removed" });
  }

  await Bookmark.create({ userId, experienceId: cleanId });
  return res.json({ ok: true, message: "Added" });
});

app.get("/api/my/bookmarks/details", authMiddleware, async (req, res) => {
  const bms = await Bookmark.find({ userId: req.user._id });
  const exps = await Experience.find({ _id: { $in: bms.map((b) => b.experienceId) }, isDeleted: false, isPaused: false });
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
app.post("/api/social/connect", authMiddleware, socialGuard, connectLimiter, async (req, res) => {
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
    if (targetUserId) target = await User.findById(targetUserId)
      .select("_id name profilePic bio handle publicProfile createdAt discoverable blockedUserIds allowHandleSearch");
    if (!target && handle) target = await User.findOne({ handle, allowHandleSearch: true })
      .select("_id name profilePic bio handle publicProfile createdAt discoverable blockedUserIds allowHandleSearch");

    if (target && __canDiscoverUser(target) !== true) {
      return res.status(404).json({ message: "User not found" });
    }

    if (target) {
      const meId = req.user && (req.user._id || req.user.id);
      const __me = meId ? String(meId) : "";
      const __tid = String((target && (target._id || target.id)) || "" );
      if (__me.length > 0 && __tid.length > 0) {
        try {
          const __meDoc = await User.findById(__me).select("blockedUserIds").lean();
          if (__isBlockedPair(__meDoc, target, __me, __tid) === true) {
            return res.status(404).json({ message: "User not found" });
          }
        } catch (_e) {
          return res.status(404).json({ message: "User not found" });
        }
      }
    }

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
app.get("/api/social/requests", authMiddleware, socialGuard, async (req, res) => {
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
app.post("/api/social/requests/:id/accept", authMiddleware, socialGuard, async (req, res) => {
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

app.post("/api/social/requests/:id/reject", authMiddleware, socialGuard, async (req, res) => {
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

// SOCIAL_USER_BLOCK_TSTS (Batch6 G1)
app.post("/api/social/block-user", authMiddleware, socialGuard, connectLimiter, async (req, res) => {
  try {
    const targetId = String((req.body && req.body.userId) || "").trim();
    if (!targetId) return res.status(400).json({ message: "userId required" });
    const me = req.user;
    const meId = String(me._id || "");
    if (!meId) return res.status(401).json({ message: "Unauthorized" });
    if (targetId == meId) return res.status(400).json({ message: "Cannot block yourself" });
    const cur = Array.isArray(me.blockedUserIds) ? me.blockedUserIds.map((x) => String(x)) : [];
    if (!cur.includes(targetId)) cur.push(targetId);
    me.blockedUserIds = cur.slice(0, 500);
    await me.save();
    return res.json({ ok: true, blockedUserIds: me.blockedUserIds });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Social: accept / reject / block
app.post("/api/social/requests/:id/block", authMiddleware, socialGuard, async (req, res) => {
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
app.get("/api/social/connections", authMiddleware, socialGuard, async (req, res) => {
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

// Social: remove connection
app.post("/api/social/connections/:userId/remove", authMiddleware, socialGuard, async (req, res) => {
  try {
    const targetUserId = __cleanId(req.params.userId, 64);
    if (!targetUserId) return res.status(400).json({ message: "Invalid userId" });

    const meId = String(req.user._id);
    if (targetUserId === meId) return res.status(400).json({ message: "Cannot remove connection with yourself" });

    // Find an accepted connection between the users
    const connection = await Connection.findOne({
      status: "accepted",
      $or: [
        { requesterId: meId, addresseeId: targetUserId },
        { requesterId: targetUserId, addresseeId: meId }
      ]
    });

    if (!connection) return res.status(404).json({ message: "Connection not found" });

    // Use existing social safety check
    const targetUser = await User.findById(targetUserId).select("_id blockedUserIds").lean();
    if (__isBlockedPair(req.user, targetUser, meId, targetUserId) === true) {
      return res.status(403).json({ message: "Cannot remove connection" });
    }

    // Delete the connection
    await Connection.findByIdAndDelete(connection._id);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// Social: friends feed (opt-in)
app.get("/api/social/feed", authMiddleware, socialGuard, async (req, res) => {
  try {
    const me = req.user._id;

    const conns = await Connection.find({
      status: "accepted",
      $or: [{ requesterId: me }, { addresseeId: me }],
    });

    const friendIds = conns.map((c) => (String(c.requesterId) === String(me) ? c.addresseeId : c.requesterId));
    if (friendIds.length === 0) return res.json([]);

    const allowedUsers = await User.find({ _id: { $in: friendIds }, showExperiencesToFriends: true, isDeleted: { $ne: true }, accountStatus: "active" }).select("_id");
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
app.get("/api/social/user/:userId/visible-bookings", authMiddleware, socialGuard, async (req, res) => {
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


// Admin: moderation triage (reports)
app.get("/api/admin/reports", adminMiddleware, requireAdminReason, async (req, res) => {
  try {
    const q = (req && req.query && typeof req.query === "object") ? req.query : {};
    const status = String(q.status || "").trim().toLowerCase();
    const limitRaw = Number.parseInt(String(q.limit || "50"), 10);
    const skipRaw = Number.parseInt(String(q.skip || "0"), 10);
    const limit = (Number.isFinite(limitRaw) && limitRaw > 0 && limitRaw <= 200) ? limitRaw : 50;
    const skip = (Number.isFinite(skipRaw) && skipRaw >= 0 && skipRaw <= 200000) ? skipRaw : 0;

    const filter = {};
    if (status) filter.status = status;

    const items = await Report.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();
    const total = await Report.countDocuments(filter);

    await __auditAdmin(req, "admin_reports_list", { targetType: "report", targetId: "", reason: __adminReason(req), meta: { status, limit, skip } }, { ok: true });
    return res.json({ ok: true, total, items });
  } catch (e) {
    await __auditAdmin(req, "admin_reports_list", { targetType: "report", targetId: "", reason: __adminReason(req) }, { ok: false, error: "admin_reports_list_failed" });
    return res.status(500).json({ message: "Failed" });
  }
});

app.patch("/api/admin/reports/:id", adminMiddleware, requireAdminReason, async (req, res) => {
  try {
    const id = String((req && req.params && req.params.id) ? req.params.id : "").trim();
    if (!id) return res.status(400).json({ message: "id required" });

    const body = (req && req.body && typeof req.body === "object") ? req.body : {};
    const status = String(body.status || "").trim().toLowerCase();
    const action = String(body.action || "none").trim().toLowerCase();
    const reason = String(body.reason || __adminReason(req) || "").trim().slice(0, 240);

    const allowedStatus = { open: true, triaged: true, actioned: true, closed: true };
    const allowedAction = { none: true, mute_user: true, delete_user: true, pause_experience: true };

    if (status && !allowedStatus[status]) return res.status(400).json({ message: "Invalid status" });
    if (!allowedAction[action]) return res.status(400).json({ message: "Invalid action" });
    if (action !== "none" && !reason) return res.status(400).json({ message: "reason required for action" });

    const r = await Report.findById(id);
    if (!r) return res.status(404).json({ message: "Not found" });

    const actorId = (req && req.user && (req.user._id || req.user.id)) ? String(req.user._id || req.user.id) : "";

    // Apply action
    if (action === "mute_user") {
      const minsRaw = Number.parseInt(String(body.muteMinutes || "15"), 10);
      const mins = (Number.isFinite(minsRaw) && minsRaw > 0 && minsRaw <= 43200) ? minsRaw : 15;
      if (String(r.targetType || "") !== "user") return res.status(400).json({ message: "mute_user requires targetType=user" });

      const UserModel = mongoose.model("User");
      const u = await UserModel.findById(String(r.targetId));
      if (!u) return res.status(404).json({ message: "Target user not found" });
      u.mutedUntil = new Date(Date.now() + mins * 60 * 1000);
      await u.save();
      r.adminMeta = { ...(r.adminMeta || {}), muteMinutes: mins };
    }

    if (action === "delete_user") {
      if (String(r.targetType || "") !== "user") return res.status(400).json({ message: "delete_user requires targetType=user" });

      const UserModel = mongoose.model("User");
      const u = await UserModel.findById(String(r.targetId));
      if (!u) return res.status(404).json({ message: "Target user not found" });
      u.isDeleted = true;
      u.accountStatus = "deleted";
      u.deletedAt = new Date();
      await u.save();
    }

    if (action === "pause_experience") {
      if (String(r.targetType || "") !== "experience") return res.status(400).json({ message: "pause_experience requires targetType=experience" });

      const ExperienceModel = mongoose.model("Experience");
      const exp = await ExperienceModel.findById(String(r.targetId));
      if (!exp) return res.status(404).json({ message: "Target experience not found" });
      exp.isPaused = true;
      await exp.save();
    }

    if (status) r.status = status;
    r.adminAction = action;
    if (reason) r.adminReason = reason;
    r.adminActorId = actorId;

    if (r.status === "closed" || r.status === "actioned") {
      r.resolvedAt = new Date();
    }

    await r.save();

    await __auditAdmin(
      req,
      "admin_report_update",
      { targetType: "report", targetId: String(r._id), reason, meta: { status: r.status, action: r.adminAction, reportTargetType: r.targetType, reportTargetId: r.targetId } },
      { ok: true }
    );

    return res.json({ ok: true, id: String(r._id), status: r.status, action: r.adminAction });
  } catch (e) {
    await __auditAdmin(req, "admin_report_update", { targetType: "report", targetId: "", reason: __adminReason(req) }, { ok: false, error: "admin_report_update_failed" });
    return res.status(500).json({ message: "Failed" });
  }
});
app.get("/api/admin/stats", adminMiddleware, requireAdminReason, async (req, res) => {
  try { await __auditAdmin(req, "admin_stats", {}, { ok: true }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  const [userCount, expCount, bookingCount, hostIds, revenueAgg] = await Promise.all([
    User.countDocuments(),
    Experience.countDocuments(),
    Booking.countDocuments(),
    Experience.distinct("hostId", { isDeleted: false }),
    Booking.aggregate([
      { $match: { $or: [{ status: "confirmed" }, { paymentStatus: "paid" }] } },
      {
        $project: {
          cents: {
            $ifNull: [
              "$pricing.totalCents",
              { $ifNull: ["$pricingSnapshot.totalCents", { $ifNull: ["$feeBreakdown.totalCents", 0] }] }
            ]
          }
        }
      },
      { $group: { _id: null, totalCents: { $sum: "$cents" } } }
    ])
  ]);
  const totalCents = (revenueAgg && revenueAgg[0] && Number(revenueAgg[0].totalCents)) || 0;
  const totalRevenue = Number((totalCents / 100).toFixed(2));
  const hostCount = Array.isArray(hostIds) ? hostIds.filter((h) => String(h || "").trim()).length : 0;
  res.json({
    userCount,
    hostCount,
    expCount,
    bookingCount,
    totalRevenue,
  });
});

// Admin bookings
app.get("/api/admin/bookings", adminMiddleware, requireAdminReason, async (req, res) => {
  try { await __auditAdmin(req, "admin_bookings_list", {}, { ok: true }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  try {
    const bookings = await Booking.find()
      .populate("experience")
      .populate({ path: "guestId", select: "-password -email" })
      .sort({ createdAt: -1 })
      .limit(50);

    const out = (bookings || []).map((b) => {
      const o = (b && typeof b.toObject === "function")
        ? b.toObject({ virtuals: true })
        : (b || {});
      if (o && typeof o === "object") delete o.guestEmail;
      if (o && o.guestId && typeof o.guestId === "object") o.guestId = adminSafeUser(o.guestId);
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
  const exps = await Experience.find({ isPaused: false, isDeleted: false }).sort({ averageRating: -1 }).limit(4);
  if (exps.length > 0) return res.json(exps);
  const fallback = await Experience.find({ isPaused: false, isDeleted: false }).limit(4);
  res.json(fallback);
});

// Curations (truthful navigation collections)
app.get("/api/curations", authMiddleware, async (req, res) => {
  try {
    const userId = String((req.auth && req.auth.userId) || (req.user && req.user._id) || "");
    if (!userId) return res.status(401).json({ message: "Invalid user" });

    const collections = [];

    function mostCommon(arr) {
      const m = new Map();
      (arr || []).forEach((x) => {
        const k = String(x || "").trim();
        if (!k) return;
        m.set(k, (m.get(k) || 0) + 1);
      });
      let best = "";
      let bestN = 0;
      for (const [k, n] of m.entries()) {
        if (n > bestN) { best = k; bestN = n; }
      }
      return best;
    }

    async function countAvailable(filters) {
      const q = { isPaused: false, isDeleted: false };

      if (filters && filters.city) {
        try { q.city = new RegExp(String(filters.city), "i"); } catch (_) {}
      }
      if (filters && filters.category) {
        q.tags = { $in: [String(filters.category)] };
      } else if (filters && filters.q) {
        const qTok = String(filters.q).trim();
        if (qTok) {
          const r = new RegExp(qTok, "i");
          q.$or = [
            { title: r },
            { description: r },
            { tags: r },
            { city: r }
          ];
        }
      }
      if (filters && filters.minPrice != null) q.price = Object.assign({}, q.price || {}, { $gte: Number(filters.minPrice) });
      if (filters && filters.maxPrice != null) q.price = Object.assign({}, q.price || {}, { $lte: Number(filters.maxPrice) });

      if (filters && filters.date) {
        const d = new Date(String(filters.date) + "T00:00:00");
        if (!Number.isNaN(d.getTime())) {
          q.startDate = { $lte: d };
          q.endDate = { $gte: d };
        }
      }

      try {
        return await Experience.countDocuments(q).maxTimeMS(5000);
      } catch (_) {
        return 0;
      }
    }

    // 1) USER: Similar to recent bookings (strongest)
    const recentBookings = await Booking.find({ guestId: userId })
      .sort({ createdAt: -1 })
      .limit(20);

    const bookedExpIds = (recentBookings || []).map((b) => String(b.experienceId || "")).filter(Boolean);
    const bookedExps = bookedExpIds.length ? await Experience.find({ _id: { $in: bookedExpIds }, isPaused: false, isDeleted: false }).limit(50) : [];

    if (bookedExps.length) {
      const cities = bookedExps.map((e) => e.city);
      const tags = [];
      bookedExps.forEach((e) => (e.tags || []).forEach((t) => tags.push(t)));

      const city = mostCommon(cities);
      const pillar = mostCommon(tags.filter((t) => (CATEGORY_PILLARS || []).includes(String(t))));
      const tag = pillar || mostCommon(tags);

      const filters = {};
      if (city) filters.city = city;
      if (pillar) filters.category = pillar;
      else if (tag) filters.q = tag;

      const count = await countAvailable(filters);
      if (count > 0) {
        collections.push({
          id: "similar_to_you",
          title: (filters.category && filters.city) ? `${filters.category} experiences in ${filters.city}` :
                 (filters.q && filters.city) ? `${filters.q} experiences in ${filters.city}` :
                 (filters.category) ? `${filters.category} experiences` :
                 (filters.q) ? `${filters.q} experiences` : "Explore",
          subtitle: "Available now",
          filters,
          count
        });
      }
    }

    // 2) USER: New since last booking (availability-first)
    const lastBooking = recentBookings && recentBookings[0] ? recentBookings[0] : null;
    if (lastBooking && lastBooking.createdAt instanceof Date) {
      const since = lastBooking.createdAt;
      const newCount = await Experience.countDocuments({ isPaused: false, isDeleted: false, createdAt: { $gt: since } }).maxTimeMS(5000).catch(() => 0);
      if (newCount > 0) {
        const filters2 = {};
        const count = await countAvailable(filters2);
        if (count > 0) {
          collections.push({
            id: "new_since_last",
            title: "New experiences",
            subtitle: "Since your last booking",
            filters: filters2,
            count
          });
        }
      }
    }

    // 3) USER: From bookmarks
    const bm = await Bookmark.find({ userId: userId }).limit(50);
    const bmIds = (bm || []).map((x) => String(x.experienceId || "")).filter(Boolean);
    const bmExps = bmIds.length ? await Experience.find({ _id: { $in: bmIds }, isPaused: false, isDeleted: false }).limit(50) : [];

    if (bmExps.length) {
      const cities = bmExps.map((e) => e.city);
      const tags = [];
      bmExps.forEach((e) => (e.tags || []).forEach((t) => tags.push(t)));

      const city = mostCommon(cities);
      const pillar = mostCommon(tags.filter((t) => (CATEGORY_PILLARS || []).includes(String(t))));
      const tag = pillar || mostCommon(tags);

      const filters = {};
      if (city) filters.city = city;
      if (pillar) filters.category = pillar;
      else if (tag) filters.q = tag;

      const count = await countAvailable(filters);
      if (count > 0) {
        collections.push({
          id: "from_bookmarks",
          title: (filters.category && filters.city) ? `${filters.category} experiences in ${filters.city}` :
                 (filters.q && filters.city) ? `${filters.q} experiences in ${filters.city}` :
                 (filters.category) ? `${filters.category} experiences` :
                 (filters.q) ? `${filters.q} experiences` : "Explore",
          subtitle: "From your bookmarks",
          filters,
          count
        });
      }
    }

    // 4) SOCIAL: Active in your circle (opt-in, can be 1 connection)
    const conns = await Connection.find({
      status: "accepted",
      $or: [{ requesterId: userId }, { addresseeId: userId }]
    }).limit(200);

    const friendIds = (conns || []).map((c) => {
      const r = String(c.requesterId || "");
      const a = String(c.addresseeId || "");
      return r === userId ? a : r;
    }).filter(Boolean);

    if (friendIds.length) {
      const shareUsers = await User.find({ _id: { $in: friendIds }, showExperiencesToFriends: true }).select("_id").limit(200);
      const shareIds = (shareUsers || []).map((u) => String(u._id || "")).filter(Boolean);

      if (shareIds.length) {
        const socialBookings = await Booking.find({
          guestId: { $in: shareIds },
          visibilityToFriends: true
        }).sort({ createdAt: -1 }).limit(50);

        const socialExpIds = (socialBookings || []).map((b) => String(b.experienceId || "")).filter(Boolean);
        const socialExps = socialExpIds.length ? await Experience.find({ _id: { $in: socialExpIds }, isPaused: false, isDeleted: false }).limit(50) : [];

        if (socialExps.length) {
          const cities = socialExps.map((e) => e.city);
          const tags = [];
          socialExps.forEach((e) => (e.tags || []).forEach((t) => tags.push(t)));

          const city = mostCommon(cities);
          const pillar = mostCommon(tags.filter((t) => (CATEGORY_PILLARS || []).includes(String(t))));
          const tag = pillar || mostCommon(tags);

          const filters = {};
          if (city) filters.city = city;
          if (pillar) filters.category = pillar;
          else if (tag) filters.q = tag;

          const count = await countAvailable(filters);
          if (count > 0) {
            collections.push({
              id: "active_in_circle",
              title: (filters.category && filters.city) ? `${filters.category} experiences in ${filters.city}` :
                     (filters.q && filters.city) ? `${filters.q} experiences in ${filters.city}` :
                     (filters.category) ? `${filters.category} experiences` :
                     (filters.q) ? `${filters.q} experiences` : "Explore",
              subtitle: "Recently active in your connections (opt-in)",
              filters,
              count
            });
          }
        }
      }
    }

    const out = collections.slice(0, 3);
    return res.json({ collections: out });
  } catch (err) {
    try { __log("warn", "curations_error", { rid: __ridFromReq(req), error: String((err && err.message) ? err.message : err) }); } catch (_) {}
    return res.status(500).json({ collections: [] });
  }
});

// Admin users
app.get("/api/admin/users", adminMiddleware, requireAdminReason, async (req, res) => {
  try { await __auditAdmin(req, "admin_users_list", {}, { ok: true }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  try {
    const users = await User.find({ isDeleted: { $ne: true } }).sort({ createdAt: -1 });
    const out = (users || []).map((u) => {
      const safe = adminSafeUser(u);
      if (u && u.email) safe.email = String(u.email || "");
      return safe;
    });
    return res.json(out);
  } catch (err) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/admin/users/:id", adminMiddleware, requireAdminReason, async (req, res) => {
  try { await __auditAdmin(req, "admin_user_delete", { targetType: "user", targetId: String(req.params.id || "" ) }, { ok: true }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  try {
    const userIdParam = __cleanId(req.params.id, 64);
    if (!userIdParam) return res.status(400).json({ message: "Invalid userId" });
    const user = await User.findById(userIdParam);
    if (!user) return res.status(404).json({ message: "User not found." });
    user.isDeleted = true;
    user.deletedAt = new Date();
    user.deletedBy = String((req.user && (req.user._id || req.user.id)) || "");
    try {
      const cur = Number.isFinite(Number(user.tokenVersion)) ? Number(user.tokenVersion) : 0;
      user.tokenVersion = cur + 1;
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    try {
      user.accountStatusChangedAt = new Date();
      user.accountStatusReason = String(__adminReason(req) || "admin_soft_delete").slice(0, 240);
    } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    await user.save();
    res.json({ message: "User banned/deleted." });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/admin/experiences", adminMiddleware, requireAdminReason, async (req, res) => {
  try { await __auditAdmin(req, "admin_experiences_list", {}, { ok: true }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  try {
    const exps = await Experience.find({ isDeleted: false }).sort({ createdAt: -1 });
    res.json(exps);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/api/admin/experiences/:id/toggle", adminMiddleware, requireAdminReason, async (req, res) => {
  try { await __auditAdmin(req, "admin_experience_toggle", { targetType: "experience", targetId: String(req.params.id || "" ) }, { ok: true }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

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

app.get("/api/users/:userId/profile", optionalAuthMiddleware, async (req, res) => {
  const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
  try { if (rid) res.set("X-Request-Id", rid); } catch (_) {}

  try {
    const userIdParam = __cleanId(req.params.userId, 64);
    if (!userIdParam) {
      return res.status(400).json({ ok: false, code: "INVALID_USER_ID", message: "Invalid userId", rid: rid });
    }

    const meId = req.user && (req.user._id || req.user.id);
    const isAdmin = !!(req.user && req.user.isAdmin);
    const isSelf = !!(meId && String(meId) === String(userIdParam));

    const user = await User.findById(userIdParam)
      .select("name profilePic bio handle publicProfile createdAt discoverable")
      .lean();

    if (!user) {
      return res.status(404).json({ ok: false, code: "NOT_FOUND", message: "User not found", rid: rid });
    }

    if (!isSelf && !isAdmin) {
      if (__canDiscoverUser(user) !== true) {
        return res.status(404).json({ ok: false, code: "NOT_FOUND", message: "User not found", rid: rid });
      }

      if (meId) {
        try {
          const meDoc = await User.findById(meId).select("blockedUserIds").lean();
          const targetDoc = await User.findById(userIdParam).select("blockedUserIds").lean();
          if (__isBlockedPair(meDoc, targetDoc, meId, userIdParam) === true) {
            return res.status(404).json({ ok: false, code: "NOT_FOUND", message: "User not found", rid: rid });
          }
        } catch (_e) {
          return res.status(404).json({ ok: false, code: "NOT_FOUND", message: "User not found", rid: rid });
        }
      }
    }

    const out = {
      name: user.name,
      profilePic: user.profilePic,
      bio: (isSelf || (req.user && (req.user.isAdmin === true || String(req.user.role || "").toLowerCase() === "admin")) || user.publicProfile) ? user.bio : "",
      handle: user.handle,
      publicProfile: user.publicProfile,
      createdAt: user.createdAt
    };

    return res.json(out);
  } catch (err) {
    try {
      __log("error", "profile_fetch_failed", {
        rid: rid,
        path: "/api/users/:userId/profile",
        error: (err && err.message) ? String(err.message) : String(err)
      });
    } catch (_) {}
    return res.status(500).json({ ok: false, code: "PROFILE_FETCH_FAILED", message: "Error fetching profile", rid: rid });
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
let __payment_recon_inflight_v1 = false;
  try { __log("info", "job_runner_started", { job: "payment_reconciliation_v1" }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
  setTimeout(() => { runPaymentReconciliationOnce_V1().catch(() => {}); }, 30 * 1000);
  setInterval(() => {
  if (__payment_recon_inflight_v1) return;
  __payment_recon_inflight_v1 = true;
  Promise.resolve(runPaymentReconciliationOnce_V1())
    .catch(() => {})
    .finally(() => { __payment_recon_inflight_v1 = false; });
}, 10 * 60 * 1000);
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
            try {
              const claimUpd = {};
              claimUpd[SET] = { capacityReleasedAt: now };
              let claimed = false;
              try {
                const r2 = await Booking.updateOne({ _id: b._id, capacityReleasedAt: null }, claimUpd);
                claimed = Boolean(r2 && (Number(r2.modifiedCount) > 0 || Number(r2.nModified) > 0));
              } catch (e) {
                try { __log("warn", "unpaid_expiry_step_failed", { step: "claim_capacityReleasedAt", bookingId: String(b._id || ""), err: String((e && e.message) ? e.message : e) }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
              }
              if (claimed) {
                let releasedOk = false;
                try { await releaseCapacitySlot(expId, dateStr, slot, g); releasedOk = true; } catch (e) {
                  releasedOk = false;
                  try { __log("warn", "unpaid_expiry_step_failed", { step: "release_capacity", bookingId: String(b._id || ""), experienceId: String(expId || ""), bookingDate: String(dateStr || ""), timeSlot: String(slot || ""), guests: Number(g || 0), err: String((e && e.message) ? e.message : e) }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
                }
                if (!releasedOk) {
                  const UNSET = String.fromCharCode(36) + "unset";
                  const revertUpd = {};
                  revertUpd[UNSET] = { capacityReleasedAt: 1 };
                  try { await Booking.updateOne({ _id: b._id, capacityReleasedAt: now }, revertUpd); } catch (e) {
                    try { __log("warn", "unpaid_expiry_step_failed", { step: "revert_capacityReleasedAt", bookingId: String(b._id || ""), err: String((e && e.message) ? e.message : e) }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
                  }
                }
              }
              try {
                const bookingDoc = await Booking.findById(String(b._id || ""));
                if (bookingDoc) {
                  try { await maybeSendBookingExpiredComms(bookingDoc); } catch (e) {
                    try { __log("warn", "unpaid_expiry_step_failed", { step: "send_expired_comms", bookingId: String(b._id || ""), err: String((e && e.message) ? e.message : e) }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
                  }
                }
              } catch (e) {
                try { __log("warn", "unpaid_expiry_step_failed", { step: "load_booking_for_comms", bookingId: String(b._id || ""), err: String((e && e.message) ? e.message : e) }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
              }
            } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

          }
        } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      }
    }
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
}

function startUnpaidBookingExpiryCleanupLoop_V1() {
  if (!__shouldRunJobs()) { __log("info", "jobs_skipped_disabled", { job: "unpaid_booking_expiry_cleanup_v1", reason: "RUN_JOBS disabled" }); return; }

  if (global.__tsts_unpaid_cleanup_started_v1 === true) return;
  global.__tsts_unpaid_cleanup_started_v1 = true;

  try {
    startJobs((level, msg, meta) => {
      try { __log(level, msg, meta || {}); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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
app.post("/api/comms/email-event", async (req, res) => {
  const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
  try { if (rid) res.set("X-Request-Id", rid); } catch (_) {}

  try {
    const secret = String(process.env.EMAIL_EVENT_SECRET || "").trim();
    const got = String((req && req.headers && (req.headers["x-email-event-secret"] || req.headers["X-Email-Event-Secret"])) || "").trim();
    if (!secret || got !== secret) {
      return res.status(401).json({ ok: false, code: "UNAUTHORIZED", message: "Unauthorized", rid: rid });
    }

    const email = String((req && req.body && req.body.email) ? req.body.email : "").trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ ok: false, code: "INVALID_INPUT", message: "email required", rid: rid });
    }

    const eventRaw = String((req && req.body && req.body.event) ? req.body.event : "").trim().toLowerCase();
    if (!eventRaw) {
      return res.status(400).json({ ok: false, code: "INVALID_INPUT", message: "event required", rid: rid });
    }

    const bookingId = String((req && req.body && req.body.bookingId) ? req.body.bookingId : "").trim();
    const template = String((req && req.body && req.body.template) ? req.body.template : "EVENT_EMAIL").trim();
    const providerMessageId = String((req && req.body && req.body.providerMessageId) ? req.body.providerMessageId : "").trim();
    const reason = String((req && req.body && req.body.reason) ? req.body.reason : "").trim();

    const allowed = ["delivered", "bounce", "bounced", "complaint", "suppressed", "unsubscribe", "unsubscribed", "failed"];
    if (allowed.indexOf(eventRaw) < 0) {
      return res.status(400).json({ ok: false, code: "INVALID_EVENT", message: "unknown event", rid: rid });
    }

    const toState = (ev) => {
      if (ev === "delivered") return "delivered";
      if (ev === "failed") return "failed";
      if (ev === "bounce" || ev === "bounced") return "bounced";
      if (ev === "complaint") return "complaint";
      if (ev === "suppressed") return "suppressed";
      if (ev === "unsubscribe" || ev === "unsubscribed") return "unsubscribed";
      return "received";
    };

    const state = toState(eventRaw);

    if (state !== "delivered" && state !== "received") {
      const supReason = reason ? reason : state;
      try {
        await EmailSuppression.updateOne({ email: email }, { $set: { reason: supReason } }, { upsert: true });
      } catch (e) {
        try {
          __log("warn", "email_event_webhook_db_fail", {
            rid: rid,
            op: "EmailSuppression.updateOne",
            email: email,
            state: state,
            error: (e && e.message) ? String(e.message) : String(e)
          });
        } catch (_) {}
      }
    }

    if (bookingId) {
      const upd = {
        state: state,
        providerMessageId: providerMessageId,
        error: reason
      };
      try {
        await EmailDelivery.updateOne({ bookingId: bookingId, template: template }, { $set: upd });
      } catch (e) {
        try {
          __log("warn", "email_event_webhook_db_fail", {
            rid: rid,
            op: "EmailDelivery.updateOne",
            bookingId: bookingId,
            template: template,
            state: state,
            error: (e && e.message) ? String(e.message) : String(e)
          });
        } catch (_) {}
      }
    }

    try {
      __log("info", "email_event_processed", {
        rid: rid,
        email: email,
        event: eventRaw,
        state: state,
        bookingId: bookingId ? bookingId : undefined,
        template: template ? template : undefined
      });
    } catch (_) {}

    return res.status(200).json({ ok: true, rid: rid });
  } catch (e) {
    try { __log("error", "email_event_failed", { rid: rid, error: (e && e.message) ? String(e.message) : String(e) }); } catch (_) {}
    return res.status(500).json({ ok: false, code: "EMAIL_EVENT_FAILED", message: "Server error", rid: rid });
  }
});





// INTERNAL_JOBS_ENDPOINT_TSTS (Batch6 D1)

// ==========================
// L5_JOB_INFRA_V1 (LOCKED)
// ==========================
async function withJobRun(db, jobName, fn, opts) {
  const runId = "job_" + Date.now() + "_" + Math.random().toString(36).slice(2);
  const now = new Date();

  const o = opts || {};
  const envTtl = Number(process.env.JOB_LOCK_TTL_MS);
  const ttlMs = Number.isFinite(o.lockTtlMs) ? o.lockTtlMs : (
    Number.isFinite(envTtl) && envTtl > 0 ? envTtl : (60 * 60 * 1000)
  );
  const expiresAt = new Date(now.getTime() + ttlMs);

  const locks = db.collection("job_locks");
  const runs  = db.collection("job_runs");
  const dlq   = db.collection("job_dlq");

  const lock = await locks.findOneAndUpdate(
    {
      _id: jobName,
      $or: [
        { locked: { $ne: true } },
        { expiresAt: { $lte: now } }
      ]
    },
    {
      $set: {
        locked: true,
        at: now,
        runId: runId,
        expiresAt: expiresAt
      }
    },
    { upsert: true, returnDocument: "after" }
  );

  if (!lock.value || lock.value.runId !== runId) {
    throw new Error("JOB_LOCKED");
  }

  await runs.insertOne({
    runId: runId,
    jobName: jobName,
    startedAt: now,
    status: "running"
  });

  try {
    await fn(runId);
    await runs.updateOne(
      { runId: runId },
      { $set: { status: "completed", finishedAt: new Date() } }
    );
  } catch (err) {
    const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";
    const errStr = (isProd ? ((err && err.message) ? String(err.message) : String(err)) : ((err && err.stack) ? String(err.stack) : String(err)));
    await runs.updateOne(
      { runId: runId },
      { $set: { status: "failed", finishedAt: new Date(), error: errStr } }
    );
    await dlq.insertOne({
      runId: runId,
      jobName: jobName,
      error: errStr,
      at: new Date()
    });
    try { __log("error", "job_failed", { jobName, runId }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    throw err;
  } finally {
    await locks.updateOne(
      { _id: jobName, runId: runId },
      {
        $set: { locked: false, releasedAt: new Date() },
        $unset: { runId: "", expiresAt: "" }
      }
    );
  }
}
// ==========================
// END L5_JOB_INFRA_V1
// ==========================

// Trigger idempotent job runs via scheduler (Render Cron / trusted caller).
// Security: requires env INTERNAL_JOBS_TOKEN and header X-Internal-Token to match.
// Note: This endpoint runs functions that are already safe/idempotent by design.
function internalJobsGuardMiddleware(req, res, next) {
  const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
  try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  if (typeof __dbReady !== "undefined" && __dbReady !== true) {
    try { __log("error", "internal_jobs_db_not_ready", { rid: rid, path: "/api/internal/jobs/run" }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(503).json({ ok: false, code: "DB_NOT_READY", message: "Database not ready", rid: rid });
  }

  const expected = String(process.env.INTERNAL_JOBS_TOKEN || "").trim();
  if (expected.length === 0) {
    try { __log("error", "internal_jobs_token_missing", { rid: rid, path: "/api/internal/jobs/run" }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(500).json({ ok: false, code: "MISCONFIGURED", message: "Internal jobs token missing", rid: rid });
  }

  const got = String((req && req.headers && (req.headers["x-internal-token"] || req.headers["X-Internal-Token"])) || "").trim();
  if (got.length === 0 || got !== expected) {
    try { __log("error", "internal_jobs_unauthorized", { rid: rid, path: "/api/internal/jobs/run" }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    return res.status(401).json({ ok: false, code: "UNAUTHORIZED", message: "Unauthorized", rid: rid });
  }

  try {
    if (global && global.__tsts_internal_jobs_running === true) {
      try { __log("error", "internal_jobs_busy", { rid: rid, path: "/api/internal/jobs/run" }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
      return res.status(409).json({ ok: false, code: "BUSY", message: "Busy", rid: rid });
    }
    if (global) global.__tsts_internal_jobs_running = true;
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  return next();
}

app.post("/api/internal/jobs/run", internalJobsGuardMiddleware, async (req, res) => {
  const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
  try { if (rid) res.set("X-Request-Id", rid); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  const queued = ["unpaid_booking_expiry_cleanup_v1", "payment_reconciliation_v1"];
  try { res.status(202).json({ ok: true, accepted: true, queued: queued, rid: rid }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  setTimeout(async () => {
    const ran = [];
    const errors = [];

    try {
      try { await runUnpaidBookingExpiryCleanupOnce_V1(); ran.push("unpaid_booking_expiry_cleanup_v1"); }
      catch (e) { errors.push({ job: "unpaid_booking_expiry_cleanup_v1", error: String(e) }); }

      try { await runPaymentReconciliationOnce_V1(); ran.push("payment_reconciliation_v1"); }
      catch (e) { errors.push({ job: "payment_reconciliation_v1", error: String(e) }); }

      const ok = (errors.length === 0);
      try {
        __log(ok ? "info" : "error",
          ok ? "internal_jobs_async_ok" : "internal_jobs_async_fail",
          { rid: rid, path: "/api/internal/jobs/run", ran: ran, errors: errors }
        );
      } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    } finally {
      try { if (global) global.__tsts_internal_jobs_running = false; } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    }
  }, 0);
});



// STARTUP: do not accept traffic until DB is ready (avoid mongoose buffering dead-hangs)
async function __startServerAfterDb() {
  try {
    // Wait for mongoose connection to be readyState=1
    const t0 = Date.now();
    while (!(global && global.__tsts_db_connected === true)) {
      if (Date.now() - t0 > 30000) {
        try { __log("error", "startup_db_timeout", { rid: __tstsRidNow() }); } catch (_) {}
        process.exit(1);
      }
      await new Promise((r) => setTimeout(r, 100));
    }

    // Start job loops only after DB is ready
    // jobs start after db_connected
    try { startUnpaidBookingExpiryCleanupLoop_V1(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
    try { startPaymentReconciliationLoop_V1(); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  } catch (e) {
    try { __log("error", "startup_fatal", { message: (e && e.message) ? String(e.message) : String(e), rid: __tstsRidNow() }); } catch (_) {}
    process.exit(1);
  }
}






// ================= AUDIT_MARKERS_STATE_V1 =================
// L8_ADMIN_REASON_GUARD_V1
// L9_JOB_SINGLE_FLIGHT_GUARD_V1
// L10_JOB_LOCK_TTL_60M_ENV_OVERRIDE_V1
// L11_EMAIL_IDEMPOTENCY_WRAPPER_V1
// L12_GUEST_COUNT_CANONICALIZATION_V1
// NOTE: Markers are audit-only. They do not change runtime behavior.
// ============================================================

// Mandatory admin reason middleware (used by admin mutation routes).
// Requirement: caller must send header: X-Admin-Reason (min 5 chars).
function requireAdminReason(req, res, next) {
  const reason = String((req && req.headers && (req.headers["x-admin-reason"] || req.headers["X-Admin-Reason"])) || "").trim();
  if (!reason || reason.length < 5) {
    return res.status(400).json({ message: "Admin reason required (X-Admin-Reason)" });
  }
  req.adminReason = reason.slice(0, 240);
  return next();
}
// ================================================================

let __httpServerStarted = false;
function __startHttpServerOnce() {
app.get(
  "/api/admin/runbook/refund-failure",
  adminMiddleware,
  requireAdminReason,
  async (req, res) => {
    return res.json({
      ok: true,
      title: "Refund failure runbook",
      steps: [
        "Capture rid from response headers (X-Request-Id) or response body rid.",
        "Search logs by rid to isolate the failing path.",
        "If failure is in Stripe refund creation, confirm payment intent exists and amountCents is <= totalCents.",
        "If webhook did not update booking status, inspect FinancialLedger for matching (eventId,eventType).",
        "Use admin refund endpoints only with X-Admin-Reason and record the reason in the ticket."
      ],
      notes: [
        "All admin mutations must include X-Admin-Reason.",
        "All error responses include code and rid."
      ]
    });
  }
);

app.get(
  "/api/admin/runbook/backup-restore",
  adminMiddleware,
  requireAdminReason,
  async (req, res) => {
    return res.json({
      ok: true,
      title: "Backup and restore runbook",
      steps: [
        "Use managed database backups (provider feature).",
        "Verify automated backups are enabled and retention is configured.",
        "Perform a restore test to staging and confirm server boots and core endpoints respond.",
        "Record restore evidence: timestamp, snapshot id, and smoke test output."
      ],
      evidenceRequired: [
        "Provider restore audit trail",
        "Smoke test output"
      ]
    });
  }
);

app.get(
  "/api/admin/orphans/report",
  adminMiddleware,
  requireAdminReason,
  async (req, res) => {
    try {
      const limRaw = (req.query && req.query.limit) ? req.query.limit : "2000";
      const limit = Math.max(1, Math.min(5000, Number.isFinite(Number(limRaw)) ? Math.floor(Number(limRaw)) : 2000));

      const BookingModel = mongoose.model("Booking");
      const rows = await BookingModel.find({}, { _id: 1, guestId: 1, experienceId: 1, paymentStatus: 1, stripePaymentIntentId: 1 })
        .limit(limit).lean();

      let missingGuestId = 0;
      let missingExperienceId = 0;
      let paidMissingStripePaymentIntentId = 0;
      const sample = [];

      for (const r of (rows || [])) {
        const gid = (r && r.guestId != null) ? String(r.guestId) : "";
        const eid = (r && r.experienceId != null) ? String(r.experienceId) : "";
        const ps = (r && r.paymentStatus != null) ? String(r.paymentStatus) : "";
        const pi = (r && r.stripePaymentIntentId != null) ? String(r.stripePaymentIntentId) : "";
        const badG = (gid.trim().length == 0);
        const badE = (eid.trim().length == 0);
        const badPi = (ps == "paid") && (pi.trim().length == 0);

        if (badG) missingGuestId += 1;
        if (badE) missingExperienceId += 1;
        if (badPi) paidMissingStripePaymentIntentId += 1;

        if ((badG || badE || badPi) && (sample.length < 20)) {
          sample.push({
            _id: r._id,
            guestId: r.guestId,
            experienceId: r.experienceId,
            paymentStatus: r.paymentStatus,
            stripePaymentIntentId: r.stripePaymentIntentId
          });
        }
      }

      return res.json({
        ok: true,
        scanned: (rows || []).length,
        counts: {
          missingGuestId: missingGuestId,
          missingExperienceId: missingExperienceId,
          paidMissingStripePaymentIntentId: paidMissingStripePaymentIntentId
        },
        sample: sample
      });
    } catch (_) {
      return res.status(500).json({ message: "Server error" });
    }
  }
);

app.get(
  "/api/admin/export/bookings",
  adminMiddleware,
  requireAdminReason,
  async (req, res) => {
    const rid = String((req && (req.requestId || req.rid)) ? (req.requestId || req.rid) : __tstsRidNow());
    try { if (rid) res.set("X-Request-Id", rid); } catch (_) {}

    try {
      const format = String((req.query && req.query.format) ? req.query.format : "json").toLowerCase();
      const limRaw = (req.query && req.query.limit) ? req.query.limit : "1000";
      const limit = Math.max(1, Math.min(5000, Number.isFinite(Number(limRaw)) ? Math.floor(Number(limRaw)) : 1000));

      const BookingModel = mongoose.model("Booking");
      const rows = await BookingModel.find({}, {
        _id: 1,
        experienceId: 1,
        guestId: 1,
        hostId: 1,
        guestName: 1,
        guestEmail: 1,
        numGuests: 1,
        bookingDate: 1,
        timeSlot: 1,
        status: 1,
        paymentStatus: 1,
        stripeSessionId: 1,
        stripePaymentIntentId: 1,
        createdAt: 1,
        updatedAt: 1
      }).limit(limit).lean();

      if (format == "csv") {
        const header = [
          "id","experienceId","guestId","hostId","guestName","guestEmail","numGuests","bookingDate","timeSlot","status","paymentStatus","stripeSessionId","stripePaymentIntentId","createdAt","updatedAt"
        ];

        const protectCsv = (txt) => {
          if (!txt) return txt;
          const first = txt[0];
          if (first === "=" || first === "+" || first === "-" || first === "@") {
            return String.fromCharCode(39) + txt;
          }
          return txt;
        };

        const esc = (v) => {
          const raw = (v == null) ? "" : String(v);
          const x = protectCsv(raw);
          const needs = (x.indexOf(",") >= 0) || (x.indexOf("\"") >= 0) || (x.indexOf("\n") >= 0);
          const y = x.replace(/"/g, "\"\"");
          return needs ? ("\"" + y + "\"") : y;
        };

        const out = [];
        out.push(header.join(","));
        for (const r of (rows || [])) {
          out.push([
            esc(r._id),
            esc(r.experienceId),
            esc(r.guestId),
            esc(r.hostId),
            esc(r.guestName),
            esc(r.guestEmail),
            esc(r.numGuests),
            esc(r.bookingDate),
            esc(r.timeSlot),
            esc(r.status),
            esc(r.paymentStatus),
            esc(r.stripeSessionId),
            esc(r.stripePaymentIntentId),
            esc(r.createdAt),
            esc(r.updatedAt)
          ].join(","));
        }

        try { res.set("Content-Type", "text/csv; charset=utf-8"); } catch (_) {}
        try { res.set("Content-Disposition", "attachment; filename=bookings_export.csv"); } catch (_) {}
        return res.status(200).send(out.join("\n"));

      }

      return res.json({ ok: true, rid: rid, count: (rows || []).length, rows: rows || [] });
    } catch (e) {
      try {
        __log("error", "admin_export_bookings_failed", {
          rid: rid,
          path: "/api/admin/export/bookings",
          error: (e && e.message) ? String(e.message) : String(e)
        });
      } catch (_) {}
      return res.status(500).json({ ok: false, code: "EXPORT_FAILED", message: "Export failed", rid: rid });
    }
  }
);


  if (__httpServerStarted) return;
  __httpServerStarted = true;
      app.listen(PORT, () => {
        try { __log("info", "server_listen", { rid: undefined, path: undefined }); } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }
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

    // L2_BOOKING_STATE_MACHINE_V1
  // Enforce allowed transitions and terminal states. Fail loud on invalid transitions.
  const curStatus = String(booking.status || "");
  const next = String(nextStatus || "");
  const TERMINAL = new Set(["refunded", "cancelled", "cancelled_by_host", "expired", "completed"]);
  const ALLOWED = {
    pending: ["confirmed", "cancelled", "cancelled_by_host", "expired"],
    confirmed: ["cancelled", "cancelled_by_host", "refunded", "completed"],
    cancelled: [],
    cancelled_by_host: ["refunded"],
    refunded: [],
    expired: [],
    completed: []
  };

  if (TERMINAL.has(curStatus)) {
    if (curStatus === next) {
      return booking;
    }
    throw new Error("BOOKING_INVALID_TRANSITION_TERMINAL:" + curStatus + "->" + next);
  }

  const allowedNext = Array.isArray(ALLOWED[curStatus]) ? ALLOWED[curStatus] : [];
  if (allowedNext.indexOf(next) === -1) {
    throw new Error("BOOKING_INVALID_TRANSITION:" + curStatus + "->" + next);
  }

// L2_EXPIRED_SAFE_NOOP_V1
  // Expiry is a cleanup sink. Never throw, never corrupt terminal/paid-path bookings if called accidentally.
  if (nextStatus === "expired") {
    const cur = String(booking.status || "");
    const protectedStates = new Set(["confirmed", "refunded", "cancelled", "cancelled_by_host", "completed"]);
    if (protectedStates.has(cur)) {
      return booking;
    }
  }

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
    // L2_GUEST_CANCEL_COMMS_IDEMPOTENCY_V1
  // Cancel comms exactly once using guestCancelledAt as idempotency key.
  const L2_IS_GUEST_CANCEL_TRANSITION = (nextStatus === "cancelled");
  const L2_SHOULD_SEND_GUEST_CANCEL_COMMS = (L2_IS_GUEST_CANCEL_TRANSITION && !booking.guestCancelledAt);

// L2_STATE_MACHINE_V1
  // Refunded is terminal in practice. Make the transition idempotent and explicitly detectable.
  const L2_IS_REFUND_TRANSITION = (nextStatus === "refunded");
  const L2_SHOULD_SEND_REFUND_COMMS = (L2_IS_REFUND_TRANSITION && !booking.refundedAt);

  if (L2_IS_REFUND_TRANSITION) {
    // Unique-by-refundedAt: once set, keep the original timestamp forever.
    updates.refundedAt = booking.refundedAt || now;
  }

  // Keep in-memory doc consistent with persisted transition
  try {
    Object.assign(booking, updates);
  } catch (_) {
    try { __log("warn", "empty_catch", { rid: __tstsRidNow() }); } catch (_) {}
  }

  await booking.updateOne({ $set: updates });

  // fire-and-forget comms (must not block state)
  // meta.suppressComms=true allows internal transitions without email noise
  if (!(meta && meta.suppressComms === true)) {
    try {
      if (nextStatus === "confirmed") {
        await maybeSendBookingConfirmedComms(booking);
      }
      if (L2_SHOULD_SEND_GUEST_CANCEL_COMMS) {
        await maybeSendBookingCancelledComms(booking);
      }
      if (nextStatus === "expired") {
        await maybeSendBookingExpiredComms(booking);
      }
      if (nextStatus === "cancelled_by_host") {
        await maybeSendBookingCancelledByHostComms(booking);
      }
      if (L2_SHOULD_SEND_REFUND_COMMS) {
        await maybeSendRefundProcessedComms(booking);
      }
    } catch (e) {
      try { __log("error", "booking_comms_fail", { bookingId: String(booking && booking._id), nextStatus: String(nextStatus), message: (e && e.message) ? String(e.message) : String(e), rid: __tstsRidNow() }); } catch (_) {}
    }
  }

  return booking;
}


