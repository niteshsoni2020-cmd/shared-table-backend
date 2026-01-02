const EVENTS = {
  PASSWORD_RESET_REQUEST: "03_password_reset_request.txt",
  PASSWORD_CHANGED_CONFIRMATION: "04_password_changed_confirmation.txt"
};

function getTemplateForEvent(e) {
  if (!(e in EVENTS)) throw new Error("EMAIL_EVENT_UNKNOWN_" + e);
  return EVENTS[e];
}

module.exports = { getTemplateForEvent };
