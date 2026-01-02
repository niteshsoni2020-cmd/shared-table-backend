const SENDERS = {
  AUTH: "auth@thesharedtablestory.com",
  NOTIFICATIONS: "notifications@thesharedtablestory.com",
  PAYMENTS: "payments@thesharedtablestory.com"
};

function senderForCategory(c) {
  if (!(c in SENDERS)) throw new Error("SENDER_CATEGORY_UNKNOWN_" + c);
  return SENDERS[c];
}

module.exports = { senderForCategory };
