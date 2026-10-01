import mongoose from "mongoose";
import crypto from "crypto";

// ===========================================================
// 🍪 COOKIE / TRACKER CONSENT — Domain 8 (ss. 2, 4, 5, 6; Rules 3, 6, 8)
// ===========================================================
// Per-subject, per-category consent for cookies/trackers. The DPDP Act never
// names "cookies", so every tracker is treated as personal-data processing and
// rests on consent (s. 6) or a s. 7 legitimate use. Append-only: a later
// accept/reject/custom/withdrawal is a NEW event, never an overwrite.
//
// The IP is stored as a salted HASH (and an optional truncated form) under the
// dedicated `consent_audit` purpose — never raw, never bundled into marketing
// (s. 4 purpose limitation, s. 6(1) minimisation). It is retained under the
// Rule 8(3) ≥1-year floor via the `security`/log retention policy.
const cookieConsentSchema = new mongoose.Schema(
  {
    // Pseudonymous subject token — works for anonymous visitors too.
    subject_token: { type: String, required: true, index: true },
    // Present when a signed-in user acted (so we can join to the account).
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
      index: true,
    },

    notice_version: { type: String, required: true },
    legal_version: { type: String, required: true },
    language: { type: String, default: "en" },
    channel: {
      type: String,
      enum: ["web", "app", "cli", "consent_manager", "admin"],
      default: "web",
    },

    action: {
      type: String,
      enum: ["accept_all", "reject_all", "custom", "withdrawn"],
      required: true,
    },
    // Per-category grants. Non-essential categories default false; the
    // functional/security ones default true.
    categories: {
      strictly_functional: { type: Boolean, default: true },
      // Google reCAPTCHA (anti-bot). Security measure; default on, but the
      // user may refuse (the auth pages then re-ask with a full explanation).
      captcha: { type: Boolean, default: true },
      analytics: { type: Boolean, default: false },
      advertising: { type: Boolean, default: false },
      personalisation: { type: Boolean, default: false },
      social_media: { type: Boolean, default: false },
      consent_audit: { type: Boolean, default: true },
    },

    // s. 6(10) evidence — hashed, never raw (Rule 6(a)).
    ip_hash: { type: String, default: null },
    ip_truncated: { type: String, default: null },
    user_agent: { type: String, default: null },
    user_agent_hash: { type: String, default: null },

    captured_at: { type: Date, default: Date.now },
    consent_manager_ref: { type: String, default: null },
    // When this event withdraws/changes an earlier decision, reference it.
    withdrawal_of: { type: String, default: null },
    // Fourth Schedule (Part B): "confirming that the DP is not a child" is a
    // permitted children's purpose. When the visitor affirmatively asserts they
    // are 18+, we record it so an adult may consent to non-essential trackers
    // and the decision survives later GET re-resolves. Never true for a child.
    age_assured: { type: Boolean, default: false },
    evidence_hash: { type: String, required: true },
  },
  { timestamps: true }
);

cookieConsentSchema.index({ subject_token: 1, captured_at: -1 });
cookieConsentSchema.index({ captured_at: 1 }); // Rule 8(3) retention sweep

// Append-only guard (s. 6(10)).
for (const op of ["findOneAndUpdate", "updateOne", "updateMany"]) {
  cookieConsentSchema.pre(op, function () {
    throw new Error("Cookie consent artefacts are append-only (DPDP s. 6(10)).");
  });
}

/** Evidence hash over the material fields of a cookie-consent event. */
export const computeCookieEvidenceHash = (doc) =>
  crypto
    .createHash("sha256")
    .update(
      [
        doc.subject_token,
        doc.notice_version,
        doc.language,
        doc.action,
        JSON.stringify(doc.categories || {}),
        new Date(doc.captured_at || Date.now()).toISOString(),
      ].join("|")
    )
    .digest("hex");

const CookieConsent =
  mongoose.models.CookieConsent ||
  mongoose.model("CookieConsent", cookieConsentSchema);
export default CookieConsent;
