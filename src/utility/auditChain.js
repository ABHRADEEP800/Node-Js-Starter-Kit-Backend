// ===========================================================
// 🔗 APPEND-ONLY, TAMPER-EVIDENT AUDIT CHAIN — Rule 6(c), s. 8(5)
// ===========================================================
// Every audit event is written as a link in a hash chain:
//   hash = SHA256(canonical(entry) + "|" + prevHash)
// The chain makes silent deletion/alteration detectable via `verifyAuditChain()`.
// The log itself stores NO raw PII (Rule 6(a)): users are referenced by
// pseudonymous token, and details must already be masked by the caller.
//
// A single in-process writer serialises appends so concurrent requests cannot
// fork the chain. For multi-instance deployments, move this behind a DB
// transaction or a Redis lock so the chain stays linear per tenant.

import crypto from "crypto";
import AuditLog from "../models/auditLog.model.js";
import AuditAnchor from "../models/auditAnchor.model.js";
import { systemLog } from "../events/systemLog.events.js";
import { hashIdentifier, maskPII } from "./piiMask.js";

/**
 * Central PII choke point (Rule 6(a), s. 8(5)): every audit entry passes here
 * before storage, so a raw IP can never reach the log regardless of what the
 * caller passed. Non-IP values (already-masked, hashed, or absent) pass
 * through unchanged.
 */
const looksLikeIp = (value) =>
  typeof value === "string" &&
  (/^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(":"));

const sanitizeAuditEntry = (entry) => ({
  ...entry,
  ip: looksLikeIp(entry.ip) ? maskPII(entry.ip, "ip") : entry.ip ?? null,
  // User-agents are identifying; never store the raw string.
  userAgent: entry.userAgent ? "[MASKED]" : null,
});

let writeQueue = Promise.resolve();

const canonical = (entry) =>
  JSON.stringify({
    userId: entry.userId ? String(entry.userId) : null,
    actorToken: entry.actorToken || null,
    action: entry.action,
    category: entry.category || "general",
    purposeId: entry.purposeId || null,
    lawfulBasis: entry.lawfulBasis || null,
    targetType: entry.targetType || null,
    targetId: entry.targetId || null,
    details: entry.details || null,
    ip: entry.ip || null,
    userAgent: entry.userAgent || null,
    status: entry.status,
    createdAt: entry.createdAt
      ? new Date(entry.createdAt).toISOString()
      : new Date().toISOString(),
  });

/** Compute the chain hash for an entry given the previous link's hash. */
export const computeHash = (entry, prevHash) =>
  crypto
    .createHash("sha256")
    .update(canonical(entry) + "|" + (prevHash || "GENESIS"))
    .digest("hex");

/**
 * Append an audit entry to the chain (serialised). Masks nothing itself —
 * callers must pass already-safe details; `actorToken` is derived here.
 */
export const appendAudit = async (entry) => {
  const run = async () => {
    // Mask before anything is hashed/written — the log must never contain raw PII.
    entry = sanitizeAuditEntry(entry);
    const createdAt = entry.createdAt ? new Date(entry.createdAt) : new Date();
    const prev = await AuditLog.findOne({}, { hash: 1 }).sort({ createdAt: -1, _id: -1 }).lean();
    const prevHash = prev?.hash || null;

    const actorToken =
      entry.actorToken ||
      (entry.userId ? hashIdentifier(String(entry.userId), "actor") : null);

    const toWrite = { ...entry, createdAt, prevHash, actorToken };
    const hash = computeHash(toWrite, prevHash);

    await AuditLog.create({ ...toWrite, hash });
    return hash;
  };

  // Chain the promise so appends are strictly sequential in-process.
  writeQueue = writeQueue.then(run, run);
  return writeQueue;
};

/**
 * Verify the chain from oldest to newest. Returns { valid, brokenAt, count }.
 * Because hash chaining alone can't detect a truncation of the tail, we also
 * report the number of records so a caller can compare against an external
 * anchor/count if one is maintained.
 */
export const verifyAuditChain = async () => {
  const entries = await AuditLog.find({}).sort({ createdAt: 1, _id: 1 }).lean();

  // Resume from the last purge anchor, if any: after a lawful erasure the
  // oldest surviving entry chains to a deleted link, so the expected "previous
  // hash" is the anchor's lastPurgedHash (or GENESIS when there is none).
  const anchor = await AuditAnchor.findOne({}).sort({ createdAt: -1, _id: -1 }).lean();
  let prevHash = anchor?.lastPurgedHash || null;
  const anchored = Boolean(anchor);

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const expected = computeHash(e, prevHash);
    if (e.prevHash !== prevHash || e.hash !== expected) {
      return {
        valid: false,
        brokenAt: e._id,
        index: i,
        count: entries.length,
        anchored,
      };
    }
    prevHash = e.hash;
  }
  return { valid: true, brokenAt: null, index: -1, count: entries.length, anchored };
};

/** Fire-and-forget append used by the audit emitter. */
export const secureAudit = (entry) => {
  appendAudit(entry).catch((err) => {
    systemLog({
      level: "ERROR",
      event: "AUDIT_CHAIN_WRITE_FAILED",
      message: err.message,
      meta: { action: entry?.action },
    });
  });
};

export default { appendAudit, verifyAuditChain, computeHash, secureAudit };
