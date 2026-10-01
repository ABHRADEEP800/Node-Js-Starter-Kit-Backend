import mongoose from "mongoose";

// ===========================================================
// 👨‍👩‍👧 VERIFIABLE PARENTAL / GUARDIAN CONSENT — s. 9, Rules 10 & 11
// ===========================================================
// A child is anyone under 18 (s. 2(f)). Before processing a child's data we
// must obtain consent from an IDENTIFIABLE ADULT parent/lawful guardian,
// verified via one of the Rule 10 mechanisms. For a person with disability the
// equivalent comes from a lawful guardian (Rule 11).
//
// Guardian identity fields are stored ENCRYPTED at rest (Rule 6(a)); only the
// verification outcome and evidence hash are needed for proof.
const guardianConsentSchema = new mongoose.Schema(
  {
    child_user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    relationship: {
      type: String,
      enum: ["parent", "guardian", "lawful_guardian"],
      required: true,
    },
    // Encrypted at rest (cryptoVault envelope). Never logged in the clear.
    guardian_name_enc: { type: String, required: true },
    guardian_email_enc: { type: String, default: null },
    guardian_phone_enc: { type: String, default: null },

    verification_method: {
      type: String,
      enum: [
        "existing_reliable_identity", // (a) details already held & verified
        "voluntarily_provided_identity", // (b) provided + due diligence
        "virtual_token", // (c) authorised entity token
        "digital_locker", // (c) Digital Locker / Board-recognised mechanism
      ],
      required: true,
    },
    verifier: { type: String, required: true }, // who/which service verified
    verification_reference: { type: String, default: null },
    evidence_hash: { type: String, required: true },

    verified_at: { type: Date, default: Date.now },
    expires_at: { type: Date, default: null },
    status: {
      type: String,
      enum: ["active", "revoked", "expired"],
      default: "active",
    },
    revoked_at: { type: Date, default: null },
    // Rule 12 exemption actually applied (must be logged if any).
    rule12_exemption: { type: String, default: null },
  },
  { timestamps: true }
);

guardianConsentSchema.index({ child_user_id: 1, status: 1 });

const GuardianConsent =
  mongoose.models.GuardianConsent ||
  mongoose.model("GuardianConsent", guardianConsentSchema);
export default GuardianConsent;
