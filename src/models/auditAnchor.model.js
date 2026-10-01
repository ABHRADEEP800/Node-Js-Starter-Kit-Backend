import mongoose from "mongoose";

// ===========================================================
// ⚓ AUDIT CHAIN ANCHOR — preserves tamper-evidence across purges
// ===========================================================
// The audit log is a hash chain. When Rule 8(3) requires purging logs older
// than the retention floor, the oldest surviving entry's `prevHash` points to a
// DELETED entry — so a naive verifier would report the whole chain as broken.
//
// An anchor records the hash of the last purged link. `verifyAuditChain()`
// resumes from this hash, so the chain stays verifiable while still allowing
// lawful erasure. One anchor per purge; the most recent one wins.
const auditAnchorSchema = new mongoose.Schema(
  {
    // Hash of the newest entry that was purged (the "cut" point).
    lastPurgedHash: { type: String, required: true },
    purgedThrough: { type: Date, required: true },
    purgedCount: { type: Number, default: 0 },
    actor: { type: String, default: "retention-job" },
  },
  { timestamps: true }
);

auditAnchorSchema.index({ createdAt: -1 });

const AuditAnchor =
  mongoose.models.AuditAnchor ||
  mongoose.model("AuditAnchor", auditAnchorSchema);
export default AuditAnchor;
