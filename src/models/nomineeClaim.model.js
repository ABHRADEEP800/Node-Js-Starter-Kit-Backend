import mongoose from "mongoose";
import crypto from "crypto";

// ===========================================================
// 👥 NOMINEE CLAIM — s. 14 (nomination on death/incapacity)
// ===========================================================
// A nominee (designated by the Data Principal, s. 14) exercises the DP's rights
// on her death or incapacity. This record captures the claim lifecycle:
//   pending → approved (nominee may then exercise rights) | rejected
//
// Identity/evidence is ENCRYPTED at rest (Rule 6(a)); the record stores only the
// case id, status, and an evidence hash so the decision is provable (s. 6/8).
const nomineeClaimSchema = new mongoose.Schema(
  {
    claim_id: {
      type: String,
      required: true,
      unique: true,
      default: () => `NMC-${crypto.randomBytes(8).toString("hex").toUpperCase()}`,
    },
    // The Data Principal whose data is being claimed.
    data_principal_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    // Which nominee on the DP's list is claiming (index into user.nominees).
    nominee_index: { type: Number, required: true },
    // Claimant identity — encrypted at rest.
    claimant_name_enc: { type: String, required: true },
    claimant_contact_enc: { type: String, default: null },
    claimant_relationship: { type: String, default: null },

    // Why the nominee may act: death or incapacity.
    basis: {
      type: String,
      enum: ["death", "incapacity"],
      required: true,
    },
    // Evidence the claimant submits (encrypted reference; no raw doc here).
    evidence_reference_enc: { type: String, default: null },
    evidence_hash: { type: String, required: true },
    // Human-readable note from the claimant (free text, capped).
    note: { type: String, default: null },

    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
      index: true,
    },
    requested_at: { type: Date, default: Date.now },
    decided_at: { type: Date, default: null },
    decided_by: { type: String, default: null }, // admin id
    decision_note: { type: String, default: null },

    // What the nominee did after approval (access/export/erasure on the DP's
    // behalf). Append-only log, no PII.
    actions: {
      type: [
        {
          at: { type: Date, default: Date.now },
          action: String,
          actor: String,
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

nomineeClaimSchema.index({ data_principal_id: 1, status: 1 });
nomineeClaimSchema.index({ requested_at: -1 });

const NomineeClaim =
  mongoose.models.NomineeClaim ||
  mongoose.model("NomineeClaim", nomineeClaimSchema);
export default NomineeClaim;
