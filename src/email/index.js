const { renderTemplate, requiredVarsForTemplateId } = require("./templates");
const { sendMail } = require("./mailer");
const { getTemplateForEvent } = require("./events");
const { senderForCategory } = require("./senders");

async function sendEventEmail(i) {
  const template = getTemplateForEvent(i.eventName);

  const __mode = String(process.env.EMAIL_STRICT_CONTRACT || "warn");
  const __isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";
  const __varsIn = (i && i.vars && typeof i.vars === "object") ? i.vars : {};
  const __vars = Object.assign({}, __varsIn);

  const __req = requiredVarsForTemplateId(template) || [];

  function __has(k) { return Object.prototype.hasOwnProperty.call(__vars, k); }
  function __val(k) {
    if (!__has(k)) return "";
    const v = __vars[k];
    return String(v == null ? "" : v).trim();
  }
  function __setIfMissing(k, v) {
    const cur = __val(k);
    const nv = String(v == null ? "" : v).trim();
    if (cur.length === 0 && nv.length > 0) __vars[k] = nv;
  }

  function __needs(k) { return Array.isArray(__req) && __req.indexOf(k) >= 0; }

  if (__needs("DASHBOARD_URL")) {
    const fbEnv = String(process.env.FRONTEND_BASE_URL || "").trim();
      if (fbEnv.length === 0 && __isProd) {
        throw new Error("FRONTEND_BASE_URL_REQUIRED");
      }
      const fb = String((fbEnv.length > 0 ? fbEnv : "http://localhost:3000")).replace(/\/$/, "");
    __setIfMissing("DASHBOARD_URL", fb + "/dashboard");
  }

    if (__needs("REVIEW_URL")) {
      const fbEnv2 = String(process.env.FRONTEND_BASE_URL || "").trim();
      if (fbEnv2.length === 0 && __isProd) {
        throw new Error("FRONTEND_BASE_URL_REQUIRED");
      }
      const fb2 = String((fbEnv2.length > 0 ? fbEnv2 : "http://localhost:3000")).replace(/\/$/, "");
      const __bid = String(__val("BOOKING_ID") || __val("bookingId") || "").trim();
      const __eid = String(__val("EXPERIENCE_ID") || "").trim();
      let __review = "";
      if (__bid.length > 0) __review = fb2 + "/review?bookingId=" + encodeURIComponent(__bid);
      else if (__eid.length > 0) __review = fb2 + "/review?experienceId=" + encodeURIComponent(__eid);
      else __review = String(__val("DASHBOARD_URL") || fb2 + "/dashboard");
      __setIfMissing("REVIEW_URL", __review);
    }


  if (__needs("HOST_NAME")) {
    __setIfMissing("HOST_NAME", __val("Name"));
    __setIfMissing("HOST_NAME", __val("GUEST_NAME"));
  }
  if (__needs("GUEST_NAME")) {
    __setIfMissing("GUEST_NAME", __val("Name"));
    __setIfMissing("GUEST_NAME", __val("HOST_NAME"));
  }

  if (__needs("DATE")) __setIfMissing("DATE", __val("BOOKING_DATE"));
  if (__needs("BOOKING_DATE")) __setIfMissing("BOOKING_DATE", __val("DATE"));

  if (__needs("TIME")) __setIfMissing("TIME", __val("TIME_SLOT"));
  if (__needs("TIME_SLOT")) __setIfMissing("TIME_SLOT", __val("TIME"));

  const __missing = [];
  for (const kk of __req) {
    const has = Object.prototype.hasOwnProperty.call(__vars, kk);
    const val = has ? String(__vars[kk] == null ? "" : __vars[kk]).trim() : "";
    if (!has || val.length === 0) __missing.push(kk);
  }

  if (__missing.length > 0) {
    try {
      console.error("email_contract_missing_vars", JSON.stringify({
        eventName: String(i && i.eventName || ""),
        templateId: String(template || ""),
        missing: __missing
      }));
    } catch (_) {}
    const __wantsThrow = (__mode === "true" || __mode === "throw");
    if (!__isProd && __wantsThrow) {
      const e = new Error("EMAIL_CONTRACT_MISSING_VARS");
      e.missing = __missing;
      throw e;
    }
  }

  const rendered = renderTemplate(template, __vars);
  return sendMail({
    from: senderForCategory(i.category),
    to: i.to,
    subject: rendered.subject,
    text: rendered.body
  });
}

module.exports = { sendEventEmail };
