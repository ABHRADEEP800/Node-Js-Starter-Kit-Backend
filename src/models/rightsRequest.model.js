import mongoose from "mongoose";
import crypto from "crypto";

// ===========================================================
// 🗂️ DATA PRINCIPAL RIGHTS REQUEST — ss. 11–14, Rule 14
// ===========================================================
// Every rights request gets a case id, an SLA clock and an audit trail. The
// DP must exhaust our grievance mechanism before approaching the Board
// (s. 13). Rule 14's printed period is ambiguous ("not exceeding 90 days");
// our policy targets 30 days and never exceeds 90 (see dpdp.config.js).
const rightsRequestSchema = new mongoose.Schema(
  {
    case_id: {
      type: String,
      required: true,
      unique: true,
      default: () => `DPR-${crypto.randomBytes(8).toString("hex").toUpperCase()}`,
    },
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: ["access", "correction", "erasure", "withdraw", "grievance", "nomination"],
      required: true,
    },
    status: {
      type: String,
      enum: ["received", "in_progress", "completed", "rejected", "escalated"],
      default: "received",
      index: true,
    },
    // For withdraw/correction; may be "all".
    purpose_id: { type: String, default: null },
    // Masked request payload — never raw PII.
    payload: { type: mongoose.Schema.Types.Mixed, default: {} },
    language: { type: String, default: "en" },

    // Minimal, risk-based identity verification (do not over-collect).
    identity_verification: {
      method: { type: String, default: "session_authenticated" },
      verified_at: { type: Date, default: null },
    },

    requested_at: { type: Date, default: Date.now },
    acknowledged_at: { type: Date, default: null },
    sla_due_at: { type: Date, required: true },
    rule_ref: { type: String, default: "Rule 14" },
    resolved_at: { type: Date, default: null },
    resolution_notes: { type: String, default: null },

    // Escalation path after exhausting the grievance mechanism (s. 13).
    escalation: {
      to_board: { type: Boolean, default: false },
      at: { type: Date, default: null },
      board_reference: { type: String, default: null },
    },
  },
  { timestamps: true }
);

rightsRequestSchema.index({ user_id: 1, requested_at: -1 });
rightsRequestSchema.index({ status: 1, sla_due_at: 1 });

const RightsRequest =
  mongoose.models.RightsRequest ||
  mongoose.model("RightsRequest", rightsRequestSchema);
export default RightsRequest;
