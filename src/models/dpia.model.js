import mongoose from "mongoose";

// ===========================================================
// 📊 DPIA / AUDIT REGISTER — s. 10, Rule 13
// ===========================================================
// Mandatory at least once every 12 months for a Significant Data Fiduciary
// (SDF), and best practice ("privacy by design", s. 8(4)) for any high-risk
// processing. Includes the SDF obligations so a notified entity can record
// them: India-based DPO, independent auditor, algorithm due diligence and
// localisation.
const dpiaSchema = new mongoose.Schema(
  {
    activity_name: { type: String, required: true },
    purpose_ids: { type: [String], default: [] },
    lawful_basis: { type: String, default: null },
    data_categories: { type: [String], default: [] },
    data_principals: {
      adults: { type: Boolean, default: true },
      children: { type: Boolean, default: false },
      persons_with_disability: { type: Boolean, default: false },
    },
    volume: { type: String, default: null },
    retention: { type: String, default: null },
    processors: { type: [String], default: [] },
    cross_border: { type: Boolean, default: false },
    automated_decisions: { type: Boolean, default: false },
    ai_models: { type: [String], default: [] },

    necessity_notes: { type: String, default: null },
    risks: {
      type: [
        {
          risk: String,
          likelihood: String,
          severity: String,
          affected_rights: [String],
          mitigation: String,
          residual: String,
        },
      ],
      default: [],
    },

    controls_verified: {
      encryption: { type: Boolean, default: false },
      masking: { type: Boolean, default: false },
      access_control: { type: Boolean, default: false },
      logging: { type: Boolean, default: false },
      backup_dr: { type: Boolean, default: false },
      retention_1yr: { type: Boolean, default: false },
      processor_contracts: { type: Boolean, default: false },
      automated_erasure: { type: Boolean, default: false },
      breach_runbook_tested: { type: Boolean, default: false },
      rights_workflows: { type: Boolean, default: false },
    },

    residual_rating: {
      type: String,
      enum: ["low", "medium", "high", "unacceptable"],
      default: "medium",
    },
    decision: {
      type: String,
      enum: ["proceed", "proceed_with_conditions", "do_not_proceed"],
      default: "proceed_with_conditions",
    },
    conditions: { type: [String], default: [] },

    // SDF obligations (s. 10, Rule 13) — only relevant if notified.
    is_sdf: { type: Boolean, default: false },
    dpo_name: { type: String, default: null },
    dpo_india_based: { type: Boolean, default: false },
    auditor_name: { type: String, default: null },
    auditor_significant_observations: { type: String, default: null },
    localisation_notes: { type: String, default: null },

    dpo_signed_at: { type: Date, default: null },
    auditor_signed_at: { type: Date, default: null },
    reviewed_at: { type: Date, default: Date.now },
    next_review_due_at: { type: Date, default: null }, // ≤12 months (Rule 13)
  },
  { timestamps: true }
);

dpiaSchema.index({ next_review_due_at: 1 });

const Dpia = mongoose.models.Dpia || mongoose.model("Dpia", dpiaSchema);
export default Dpia;
