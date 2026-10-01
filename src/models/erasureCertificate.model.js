import mongoose from "mongoose";
import crypto from "crypto";

// ===========================================================
// 🧾 ERASURE CERTIFICATE — s. 8(7), Rule 8
// ===========================================================
// Proof that erasure happened, WITHOUT retaining the erased personal data.
// The subject is referenced only by a pseudonymous token; there is no PII here.
const erasureCertificateSchema = new mongoose.Schema(
  {
    certificate_id: {
      type: String,
      required: true,
      unique: true,
      default: () => `ERC-${crypto.randomBytes(8).toString("hex").toUpperCase()}`,
    },
    subject_ref: { type: String, required: true }, // pseudonymous token
    trigger: {
      type: String,
      enum: ["consent_withdrawn", "deletion_request", "inactivity", "purpose_fulfilled", "ttl_expired"],
      required: true,
    },
    categories: { type: [String], default: [] },
    systems: { type: [String], default: [] }, // primary, sessions, passkeys, backups…
    processor_notifications: { type: [String], default: [] },
    actor: { type: String, default: "retention-job" },
    erased_at: { type: Date, default: Date.now },
    evidence_hash: { type: String, required: true },
    notes: { type: String, default: null },
  },
  { timestamps: true }
);

erasureCertificateSchema.index({ subject_ref: 1, erased_at: -1 });

const ErasureCertificate =
  mongoose.models.ErasureCertificate ||
  mongoose.model("ErasureCertificate", erasureCertificateSchema);
export default ErasureCertificate;
