import mongoose from "mongoose";
import crypto from "crypto";

// ===========================================================
// 🚨 PERSONAL DATA BREACH INCIDENT — s. 8(6), s. 2(u), Rule 7
// ===========================================================
// An incident record with an immutable timeline, Rule 7 fields, evidence
// hashes and the 72-hour countdown. Nothing here may be deleted during an
// incident (evidence preservation). No raw PII — affected users are counted
// and referenced by pseudonymous token.
const breachSchema = new mongoose.Schema(
  {
    incident_id: {
      type: String,
      required: true,
      unique: true,
      default: () => `INC-${crypto.randomBytes(8).toString("hex").toUpperCase()}`,
    },
    title: { type: String, required: true },
    description: { type: String, required: true },

    // s. 2(u) compromise classification.
    impact: {
      confidentiality: { type: Boolean, default: false },
      integrity: { type: Boolean, default: false },
      availability: { type: Boolean, default: false },
    },
    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium",
    },

    nature: { type: String, default: null },
    extent: { type: String, default: null },
    location: { type: String, default: null },
    likely_impact: { type: String, default: null },
    data_categories: { type: [String], default: [] },
    affected_count: { type: Number, default: 0 },
    affected_user_refs: { type: [String], default: [] },
    involves_children: { type: Boolean, default: false }, // s. 9 urgency
    cause: { type: String, default: null },
    perpetrator_findings: { type: String, default: null },

    occurred_at: { type: Date, default: null },
    detected_at: { type: Date, default: Date.now },
    // Rule 7(2): first report "without delay" (target <24h) + detailed ≤72h.
    board_first_report_due_at: { type: Date, default: null },
    board_detailed_report_due_at: { type: Date, default: null },
    board_first_reported_at: { type: Date, default: null },
    board_detailed_reported_at: { type: Date, default: null },
    board_extension_granted: { type: Boolean, default: false },
    board_extension_notes: { type: String, default: null },
    data_principals_notified_at: { type: Date, default: null },

    mitigation_steps: { type: [String], default: [] },
    remedial_measures: { type: [String], default: [] },
    status: {
      type: String,
      enum: ["open", "contained", "notified", "closed"],
      default: "open",
    },
    incident_commander: { type: String, default: null },
    dpo_notified_at: { type: Date, default: null },

    evidence_hashes: { type: [String], default: [] },
    // Append-only timeline of events (no PII).
    timeline: {
      type: [
        {
          at: { type: Date, default: Date.now },
          actor: String,
          event: String,
          note: String,
        },
      ],
      default: [],
    },
    post_mortem: { type: String, default: null },
    closed_at: { type: Date, default: null },
  },
  { timestamps: true }
);

breachSchema.index({ status: 1, detected_at: -1 });

const Breach = mongoose.models.Breach || mongoose.model("Breach", breachSchema);
export default Breach;
