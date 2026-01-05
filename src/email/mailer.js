const https = require("https");

function hasResend() {
  return String(process.env.RESEND_API_KEY || "").trim().length > 0;
}

function sendViaResend(p) {
  return new Promise((resolve) => {
    const key = String(process.env.RESEND_API_KEY || "").trim();
    if (!key) return resolve(false);

    const from = String(process.env.FROM_EMAIL || (p && p.from) || "").trim();
    if (!from) throw new Error("MAIL_FROM_REQUIRED");

    const payload = JSON.stringify({
      from: from,
      to: String((p && p.to) || ""),
      subject: String((p && p.subject) || ""),
      text: String((p && p.text) || "")
    });

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
          const ok = res.statusCode >= 200 && res.statusCode < 300;
          if (!ok) {
            const body = String(data || "").slice(0, 500);
            console.error("RESEND_SEND_FAIL", JSON.stringify({ status: res.statusCode, body: body }));
            return resolve(false);
          }
          return resolve(true);
        });
      }
    );

    req.on("error", (e) => {
      console.error("RESEND_SEND_FAIL", JSON.stringify({ err: String(e || "").slice(0, 200) }));
      resolve(false);
    });

    req.write(payload);
    req.end();
  });
}

async function sendMail(p) {
  if (!p || !p.to) throw new Error("MAIL_TO_REQUIRED");
  if (!p.subject) throw new Error("MAIL_SUBJECT_REQUIRED");
  if (!p.text) throw new Error("MAIL_TEXT_REQUIRED");

  if (!hasResend()) return false;
  const ok = await sendViaResend(p);
  return ok === true;
}

module.exports = { sendMail };
