const { renderTemplate } = require("./templates");
const { sendMail } = require("./mailer");
const { getTemplateForEvent } = require("./events");
const { senderForCategory } = require("./senders");

async function sendEventEmail(i) {
  const template = getTemplateForEvent(i.eventName);
  const rendered = renderTemplate(template, i.vars || {});
  return sendMail({
    from: senderForCategory(i.category),
    to: i.to,
    subject: rendered.subject,
    text: rendered.body
  });
}

module.exports = { sendEventEmail };
