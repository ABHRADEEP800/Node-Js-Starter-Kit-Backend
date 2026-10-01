import mongoose from "mongoose";
import crypto from "crypto";

// ===========================================================
// ✅ CONSENT ARTEFACT — s. 6(10): the burden of proof is on us
// ===========================================================
// Store an IMMUTABLE, provable record of exactly what notice the Data
// Principal saw, in which language, what they did, and when. Append-only:
// withdrawal creates a NEW event rather than overwriting history.
//
// No raw PII is stored here beyond the pseudonymous user reference. Contextual
// evidence (IP / user-agent) is hashed, not stored in the clear (Rule 6(a)).
const consentSchema = new mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    // Opaque pseudonymous reference so the artefact survives even if the user
    // document is erased (proof of consent does not require the PII).
    data_principal_ref: { type: String, required: true },

    notice_version: { type: String, required: true },
    legal_version: { type: String, required: true },
    language: { type: String, default: "en" },

    // Purpose-scoped: never a blanket "I agree" (s. 6, "specific").
    purposes: { type: [String], required: true },
    lawful_basis: { type: String, required: true, default: "consent:6(1)" },

    action: {
      type: String,
      enum: ["granted", "withdrawn", "denied"],
      required: true,
    },
    // Describes the affirmative act (proves opt-in, not pre-ticked).
    affirmative_action: { type: String, default: "explicit_checkbox_unticked_default" },

    captured_at: { type: Date, default: Date.now },
    channel: {
      type: String,
      enum: ["web", "app", "cli", "consent_manager", "admin"],
      default: "web",
    },

    // Hashed context — never the raw value (Rule 6(a)).
    ip_hash: { type: String, default: null },
    user_agent_hash: { type: String, default: null },

    // s. 6(7)–(9): if consent was routed through a Consent Manager, its ref.
    consent_manager_ref: { type: String, default: null },

    // Tamper-evidence for this single artefact.
    evidence_hash: { type: String, required: true },
  },
  { timestamps: true }
);

consentSchema.index({ user_id: 1, captured_at: -1 });
consentSchema.index({ purposes: 1, action: 1 });

// Append-only guard: once written, a consent artefact must never be updated.
// Corrections happen by appending a superseding event.
consentSchema.pre("findOneAndUpdate", function () {
  throw new Error("Consent artefacts are append-only (DPDP s. 6(10)).");
});
consentSchema.pre("updateOne", function () {
  throw new Error("Consent artefacts are append-only (DPDP s. 6(10)).");
});
consentSchema.pre("updateMany", function () {
  throw new Error("Consent artefacts are append-only (DPDP s. 6(10)).");
});

/** Compute the evidence hash over the artefact's material fields. */
export const computeConsentEvidenceHash = (doc) =>
  crypto
    .createHash("sha256")
    .update(
      [
        String(doc.user_id ?? doc.data_principal_ref),
        doc.notice_version,
        doc.language,
        [...(doc.purposes || [])].sort().join(","),
        doc.lawful_basis,
        doc.action,
        new Date(doc.captured_at || Date.now()).toISOString(),
      ].join("|")
    )
    .digest("hex");

const Consent = mongoose.models.Consent || mongoose.model("Consent", consentSchema);
export default Consent;
