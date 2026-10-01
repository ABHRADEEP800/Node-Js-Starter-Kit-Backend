import { EventEmitter } from "events";
import { appendAudit } from "../utility/auditChain.js";
import { systemLog } from "./systemLog.events.js";

class AuditEmitter extends EventEmitter {}
const auditEmitter = new AuditEmitter();

// Single listener owns every AuditLog write. Controllers just `audit(...)`.
// Writes now go through the hash-chained append so the log is tamper-evident
// (Rule 6(c), s. 8(5)). Fire-and-forget: failures are logged to the system log
// but never break the request that triggered the audit event.
auditEmitter.on("log", async (entry) => {
  try {
    await appendAudit(entry);
  } catch (err) {
    console.error("Failed to write audit log:", err);
    systemLog({
      level: "ERROR",
      event: "AUDIT_LOG_WRITE_FAILED",
      message: err.message,
      meta: { action: entry?.action },
    });
  }
});

/** Emit an audit entry (fire-and-forget). Shape matches the AuditLog model. */
export const audit = (entry) => auditEmitter.emit("log", entry);

export default auditEmitter;
