import mongoose from "mongoose";

// ===========================================================
// 🌍 CROSS-BORDER TRANSFER REGISTER — s. 16, Rule 15
// ===========================================================
// Transfers are permitted by default unless the Government restricts a
// country/territory by notification (s. 16). Rule 15 adds conditions where
// data may be made available to a foreign State or its entities. Every
// transfer is registered here and gated against `RESTRICTED_COUNTRIES`.
const transferRegisterSchema = new mongoose.Schema(
  {
    country: { type: String, required: true }, // ISO-3166 alpha-2
    recipient: { type: String, required: true },
    recipient_type: {
      type: String,
      enum: ["processor", "sub_processor", "group_company", "foreign_state_entity"],
      default: "processor",
    },
    purpose_id: { type: String, required: true },
    lawful_basis: { type: String, required: true },
    data_categories: { type: [String], default: [] },
    safeguards: { type: [String], default: [] }, // contract, encryption, SCCs…
    mechanism: { type: String, default: "contractual" },
    is_foreign_state_entity: { type: Boolean, default: false }, // Rule 15
    restricted: { type: Boolean, default: false }, // gated by notification
    restricted_reference: { type: String, default: null },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

transferRegisterSchema.index({ country: 1, active: 1 });

const TransferRegister =
  mongoose.models.TransferRegister ||
  mongoose.model("TransferRegister", transferRegisterSchema);
export default TransferRegister;
