import { EventEmitter } from "events";
import AuditLog from "../models/auditLog.model.js";
import { systemLog } from "./systemLog.events.js";

class AuditEmitter extends EventEmitter {}
const auditEmitter = new AuditEmitter();

// Single listener owns every AuditLog write. Controllers just `audit(...)`.
// Fire-and-forget: failures are logged (to the system log) but never break
// the request that triggered the audit event.
auditEmitter.on("log", async (entry) => {
  try {
    await AuditLog.create(entry);
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
