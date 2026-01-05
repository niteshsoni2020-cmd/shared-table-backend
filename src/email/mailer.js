const https = require("https");

function __norm(x) {
  return String(x == null ? "" : x).trim();
}

function __hasResend() {
  return __norm(process.env.RESEND_API_KEY).length > 0;
}

function __jsonSafeParse(s) {
  try { return JSON.parse(String(s || "")); } catch (_) { return null; }
}

function sendViaResend(p) {
  return new Promise((resolve, reject) => {
    const key = __norm(process.env.RESEND_API_KEY);
    if (!key) return reject(new Error("EMAIL_PROVIDER_NOT_CONFIGURED"));

    const from = __norm((p && p.from) || process.env.FROM_EMAIL);
    if (!from) return reject(new Error("MAIL_FROM_REQUIRED"));

    const to = __norm(p && p.to);
    const subject = __norm(p && p.subject);
    const text = __norm(p && p.text);
    const html = __norm(p && p.html);

    if (!to) return reject(new Error("MAIL_TO_REQUIRED"));
    if (!subject) return reject(new Error("MAIL_SUBJECT_REQUIRED"));
    if (!text && !html) return reject(new Error("MAIL_TEXT_OR_HTML_REQUIRED"));

    const obj = { from, to, subject };
    if (text) obj.text = text;
    if (html) obj.html = html;
    const payload = JSON.stringify(obj);

    const req = https.request(
      "https://api.resend.com/emails",
      {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + key,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload)
        }
      },
      (res) => {
        let data = "";
        res.on("data", (c) => { data += c; });
        res.on("end", () => {
          const statusCode = Number(res.statusCode || 0);
          const ok = statusCode >= 200 && statusCode < 300;

          if (!ok) {
            const body = String(data || "").slice(0, 800);
            const e = new Error("RESEND_SEND_FAIL statusCode=" + String(statusCode) + " body=" + body);
            e.statusCode = statusCode;
            e.response = body;
            e.provider = "resend";
            return reject(e);
          }

          const j = __jsonSafeParse(data) || {};
          const id = __norm(j.id || j.messageId || j.messageID);
          return resolve({
            provider: "resend",
            statusCode: statusCode,
            providerMessageId: id
          });
        });
      }
    );

    req.on("error", (e) => {
      const msg = (e && e.message) ? e.message : String(e || "");
      const err = new Error("RESEND_SEND_FAIL " + msg);
      err.provider = "resend";
      return reject(err);
    });

    req.write(payload);
    req.end();
  });
}

async function sendMail(p) {
  if (!p || typeof p !== "object") throw new Error("MAIL_PAYLOAD_REQUIRED");
  if (!__hasResend()) throw new Error("EMAIL_PROVIDER_NOT_CONFIGURED");
  return await sendViaResend(p);
}

module.exports = { sendMail };
