const EVENTS = {
  EMAIL_VERIFICATION: "01_email_verification.txt",
  WELCOME_POST_VERIFICATION: "02_welcome_post_verification.txt",
  PASSWORD_RESET_REQUEST: "03_password_reset_request.txt",
  PASSWORD_CHANGED_CONFIRMATION: "04_password_changed_confirmation.txt",
  BOOKING_REQUEST_SUBMITTED: "05_booking_request_submitted.txt",
  BOOKING_CONFIRMED_GUEST: "06_booking_confirmed_guest.txt",
  BOOKING_CONFIRMED_HOST: "07_booking_confirmed_host.txt",
  BOOKING_CANCELLED_BY_GUEST_GUEST: "08_booking_cancelled_by_guest_guest.txt",
  BOOKING_CANCELLED_BY_GUEST_HOST: "09_booking_cancelled_by_guest_host.txt",
  BOOKING_CANCELLED_BY_HOST_GUEST: "10_booking_cancelled_by_host_guest.txt",
  BOOKING_CANCELLED_BY_HOST_HOST: "11_booking_cancelled_by_host_host.txt",
  UPCOMING_EXPERIENCE_GUEST: "12_upcoming_experience_guest.txt",
  UPCOMING_EXPERIENCE_HOST: "13_upcoming_experience_host.txt",
  INVOICE_RECEIPT_GUEST: "14_invoice_receipt_guest.txt",
  REVIEW_REQUEST_GUEST: "15_review_request_guest.txt",
  REVIEW_RECEIVED_HOST: "16_review_received_host.txt",
  HOST_APPLICATION_RECEIVED: "17_host_application_received.txt",
  HOST_APPLICATION_APPROVED: "18_host_application_approved.txt",
  HOST_APPLICATION_DECLINED: "19_host_application_declined.txt",
  PAYMENT_FAILED: "20_payment_failed.txt",
  BOOKING_EXPIRED: "21_booking_expired.txt",
  BOOKING_EXPIRED_HOST: "21_booking_expired_host.txt",
  EXPERIENCE_UPDATED_GUEST: "22_experience_updated_guest.txt",
  EXPERIENCE_UPDATED_HOST: "23_experience_updated_host.txt",
  ACCOUNT_SUSPENDED: "24_account_suspended.txt",
  ACCOUNT_REACTIVATED: "25_account_reactivated.txt",
  ACCOUNT_DELETED: "26_account_deleted.txt",
  EXPERIENCE_RECOMMENDATION: "27_experience_recommendation.txt",
  HOST_PAYOUT_PROCESSED: "28_host_payout_processed.txt",
  REFUND_PROCESSED: "29_refund_processed.txt",
  SYSTEM_MESSAGE: "30_system_message.txt"
};

const ALIASES = {
  BOOKING_EXPIRED_GUEST: "BOOKING_EXPIRED"
};

function normalizeEventName(ev) {
  const s = String(ev || "").trim().toUpperCase();
  if (!s) return "";
  return ALIASES[s] || s;
}

function getTemplateForEvent(eventName) {
  const ev = normalizeEventName(eventName);
  if (!ev) throw new Error("EMAIL_EVENT_NAME_REQUIRED");
  const id = EVENTS[ev];
  if (!id) throw new Error("EMAIL_EVENT_UNKNOWN_" + ev);
  return id;
}

module.exports = { getTemplateForEvent };
