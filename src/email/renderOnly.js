const { renderTemplate, requiredVarsForTemplateId } = require("./templates");
const { getTemplateForEvent } = require("./events");

function renderEventEmail(i) {
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
    if (fbEnv.length === 0 && __isProd) throw new Error("FRONTEND_BASE_URL_REQUIRED");
    const fb = String((fbEnv.length > 0 ? fbEnv : "http://localhost:3000")).replace(/\/$/, "");
    __setIfMissing("DASHBOARD_URL", fb + "/dashboard");
  }

  if (__needs("REVIEW_URL")) {
    const fbEnv2 = String(process.env.FRONTEND_BASE_URL || "").trim();
    if (fbEnv2.length === 0 && __isProd) throw new Error("FRONTEND_BASE_URL_REQUIRED");
    const fb2 = String((fbEnv2.length > 0 ? fbEnv2 : "http://localhost:3000")).replace(/\/$/, "");
    const bid = __val("BOOKING_ID");
    const eid = __val("EXPERIENCE_ID");
    let review = "";
    if (bid) review = fb2 + "/review?bookingId=" + encodeURIComponent(bid);
    else if (eid) review = fb2 + "/review?experienceId=" + encodeURIComponent(eid);
    else review = fb2 + "/dashboard";
    __setIfMissing("REVIEW_URL", review);
  }

  if (__needs("HOST_NAME")) __setIfMissing("HOST_NAME", __val("GUEST_NAME"));
  if (__needs("GUEST_NAME")) __setIfMissing("GUEST_NAME", __val("HOST_NAME"));
  if (__needs("DATE")) __setIfMissing("DATE", __val("BOOKING_DATE"));
  if (__needs("TIME")) __setIfMissing("TIME", __val("TIME_SLOT"));

  const missing = [];
  for (const k of __req) {
    const v = __val(k);
    if (!v) missing.push(k);
  }

  if (missing.length && (__mode === "true" || __mode === "throw") && !__isProd) {
    const e = new Error("EMAIL_CONTRACT_MISSING_VARS");
    e.missing = missing;
    throw e;
  }

  const rendered = renderTemplate(template, __vars);
  return { subject: rendered.subject, text: rendered.body, templateId: template };
}

module.exports = { renderEventEmail };
