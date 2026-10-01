import mongoose from "mongoose";

// ===========================================================
// 🧾 APPEND-ONLY, TAMPER-EVIDENT AUDIT LOG — Rule 6(c), s. 8(5)
// ===========================================================
// Every access, modification, export, consent event, rights request and breach
// action is recorded here. Records are hash-chained (`prevHash` → `hash`) so
// silent tampering is detectable via `verifyAuditChain()`. The entry stores NO
// raw PII: users are referenced by `userId` (ObjectId) and `actorToken`
// (HMAC pseudonym), and `details` must already be masked by the caller.
//
// Rule 8(3) + Seventh Schedule: retain for at least 1 year, then erase unless
// a longer period is legally required.
const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: false, // Optional for failed logins where user doesn't exist
      index: true,
    },
    action: {
      type: String,
      required: true,
      index: true,
    },
    // Coarse grouping so compliance queries (consent/rights/breach/security)
    // can be filtered without scanning free-text actions.
    category: {
      type: String,
      enum: ["general", "auth", "consent", "rights", "security", "breach", "erasure", "admin"],
      default: "general",
      index: true,
    },
    // s. 4/s. 5(ii): the purpose + lawful basis under which this processing ran.
    purposeId: { type: String, default: null },
    lawfulBasis: { type: String, default: null },
    targetType: { type: String, default: null },
    targetId: { type: String, default: null },
    details: {
      type: String,
      required: false,
    },
    ip: {
      type: String,
      required: false,
    },
    userAgent: {
      type: String,
      required: false,
    },
    status: {
      type: String,
      enum: ["SUCCESS", "FAILED"],
      required: true,
    },

    // ---- Hash-chain (tamper-evidence) ----
    prevHash: { type: String, default: null },
    hash: { type: String, default: null, index: true },
    actorToken: { type: String, default: null },
  },
  { timestamps: true }
);

auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ category: 1, createdAt: -1 });

export default mongoose.model("AuditLog", auditLogSchema);
