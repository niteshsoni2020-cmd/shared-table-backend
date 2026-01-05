const nodemailer = require("nodemailer");


// RETURN_PROMISE_ENFORCED
function __ensurePromise(p) {
  if (p && typeof p.then === "function") return p;
  return Promise.resolve(p);
}
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
    auth: { user, pass }
  });
  return __mailer;
}

async function sendMail(p) {
  const mailer = getMailer();
  if (!mailer) return false;

  if (!p || !p.to) throw new Error("MAIL_TO_REQUIRED");
  if (!p.subject) throw new Error("MAIL_SUBJECT_REQUIRED");
  if (!p.text) throw new Error("MAIL_TEXT_REQUIRED");

  const from = String(process.env.FROM_EMAIL || p.from || process.env.SMTP_USER || "");
  if (!from) throw new Error("MAIL_FROM_REQUIRED");

  try {
    await mailer.sendMail({
      from,
      to: p.to,
      subject: p.subject,
      text: p.text
    });
    return true;
  } catch (_) {
    return false;
  }
}

module.exports = { sendMail };
