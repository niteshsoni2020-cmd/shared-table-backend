async function sendMail(p) {
  if (!p.to) throw new Error("MAIL_TO_REQUIRED");
  if (!p.from) throw new Error("MAIL_FROM_REQUIRED");
  if (!p.subject) throw new Error("MAIL_SUBJECT_REQUIRED");
  if (!p.text) throw new Error("MAIL_TEXT_REQUIRED");
  throw new Error("MAILER_NOT_CONFIGURED");
}

module.exports = { sendMail };
