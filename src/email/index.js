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
    const fb = String(process.env.FRONTEND_BASE_URL || "http://localhost:3000").replace(/\/$/, "");
    __setIfMissing("DASHBOARD_URL", fb + "/dashboard");
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
