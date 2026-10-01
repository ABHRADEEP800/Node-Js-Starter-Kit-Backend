// ===========================================================
// ⏳ RETENTION & ERASURE SERVICE — s. 8(7)/(8), Rule 8
// ===========================================================
// Implements the automated cleanup + cascade erasure contract:
//   1. records whose purpose is fulfilled / TTL expired
//   2. consent-withdrawn data (s. 8(7))
//   3. deletion requests
//   4. inactive Data Principals past the Third Schedule period — after a
//      48-hour pre-erasure warning (Rule 8(2))
//   …always excluding records under a valid `legal_hold` (citation logged).
//
// Every erasure emits a pseudonymous ERASURE CERTIFICATE (no erased PII) and
// an append-only audit entry (Rule 6(c)).

import crypto from "crypto";
import User from "../models/user.model.js";
import Session from "../models/session.model.js";
import Consent from "../models/consent.model.js";
import GuardianConsent from "../models/guardianConsent.model.js";
import Passkey from "../models/passkey.model.js";
import RightsRequest from "../models/rightsRequest.model.js";
import AuditLog from "../models/auditLog.model.js";
import AuditAnchor from "../models/auditAnchor.model.js";
import NomineeClaim from "../models/nomineeClaim.model.js";
import Breach from "../models/breach.model.js";
import ErasureCertificate from "../models/erasureCertificate.model.js";
import { appendAudit } from "../utility/auditChain.js";
import { tokenize } from "../utility/cryptoVault.js";
import { audit } from "../events/auditLog.events.js";
import { systemLog } from "../events/systemLog.events.js";
import { sendEmail } from "../utility/email.js";
import CookieConsent from "../models/cookieConsent.model.js";
import {
  INACTIVITY_ERASURE_DAYS,
  LOG_RETENTION_DAYS,
  ERASURE_WARNING_HOURS,
  optionalPurposes,
} from "../config/dpdp.config.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

const buildEvidenceHash = (parts) =>
  crypto.createHash("sha256").update(parts.join("|")).digest("hex");

/**
 * Hard-erase a user and cascade to every store that holds their data
 * (s. 8(7)). Backups are expired on the documented schedule; here we delete
 * from the live stores and record the cascade in the certificate.
 */
export const eraseUserData = async ({ userId, trigger, actor = "retention-job" }) => {
  const subjectRef = tokenize(String(userId), "dp");

  const [sessions, consents, guardians, passkeys, rights, cookieConsents, nomineeClaims] =
    await Promise.all([
      Session.deleteMany({ user_id: userId }),
      Consent.deleteMany({ user_id: userId }),
      GuardianConsent.deleteMany({ child_user_id: userId }),
      Passkey.deleteMany({ user_id: userId }),
      RightsRequest.updateMany(
        { user_id: userId },
        { $set: { user_id: null, payload: {} } }
      ),
      // Domain 8: cookie-consent artefacts reference the user; the consent
      // EVIDENCE is itself a processing record whose purpose has ended with the
      // account, so it is cascaded too (Rule 8(3) floor applies to logs).
      CookieConsent.deleteMany({ user_id: userId }),
      // s. 14: nominee claims hold the claimant's encrypted name/contact; once
      // the Data Principal is erased the claim has no lawful basis to persist.
      NomineeClaim.deleteMany({ data_principal_id: userId }),
    ]);

  const deletedUser = await User.findByIdAndDelete(userId);

  // Only emit a certificate if something actually existed (avoids noise for
  // repeated cleanup passes).
  if (!deletedUser) return null;

  const systems = [
    "primary:user",
    `sessions:${sessions.deletedCount}`,
    `consents:${consents.deletedCount}`,
    `guardian_consents:${guardians.deletedCount}`,
    `passkeys:${passkeys.deletedCount}`,
    `rights_requests_scrubbed:${rights.modifiedCount}`,
    `cookie_consents:${cookieConsents.deletedCount}`,
    `nominee_claims:${nomineeClaims.deletedCount}`,
    "backups:expire-per-schedule",
  ];

  const erasedAt = new Date();
  const evidence_hash = buildEvidenceHash([
    subjectRef,
    trigger,
    systems.join(","),
    erasedAt.toISOString(),
  ]);

  const cert = await ErasureCertificate.create({
    subject_ref: subjectRef,
    trigger,
    categories: ["account", "profile", "sessions", "passkeys", "consents", "guardian_consents"],
    systems,
    processor_notifications: [],
    actor,
    erased_at: erasedAt,
    evidence_hash,
  });

  // The audit entry references only the pseudonymous token (no PII).
  await appendAudit({
    userId: null,
    actorToken: subjectRef,
    action: "ERASURE_COMPLETED",
    category: "erasure",
    purposeId: null,
    lawfulBasis: "s.8(7)",
    targetType: "ErasureCertificate",
    targetId: cert.certificate_id,
    status: "SUCCESS",
    details: `trigger=${trigger} systems=${systems.length}`,
  });

  return cert;
};

/**
 * Third Schedule carve-out: on the INACTIVITY clock we must NOT delete the
 * record that (a) enables the DP to access her user account or (b) enables
 * access to a virtual token. We therefore erase every NON-carve-out artefact
 * (sessions, optional consents, passkeys, 2FA, cookie preferences) and keep the
 * minimal account-access record, flagged so it is not re-processed.
 */
export const trimInactiveUser = async ({ userId, actor = "retention-job" }) => {
  const subjectRef = tokenize(String(userId), "dp");
  const user = await User.findById(userId);
  if (!user) return null;

  const [sessions, passkeys, cookieConsents] = await Promise.all([
    Session.deleteMany({ user_id: userId }),
    Passkey.deleteMany({ user_id: userId }),
    CookieConsent.deleteMany({ user_id: userId }),
  ]);

  // Withdraw all OPTIONAL consents; keep `account` (the carve-out) intact.
  const optionalIds = optionalPurposes().map((p) => p.id);
  await Consent.deleteMany({ user_id: userId, purposes: { $in: optionalIds } });

  // Strip optional/enriched profile data AND all third-party / secret fields
  // that are not required for account access. Only the carve-out minimum
  // remains: identity needed to sign in + the account purpose.
  user.telemetryDisabled = true;
  user.twofa = false;
  user.twofaCode = null;
  user.backupCodes = [];
  // Third-party PII (nominees) and unused reset/verification tokens are NOT
  // part of the account-access carve-out — erase them.
  user.nominees = [];
  user.passwordResetToken = null;
  user.passwordResetExpires = null;
  user.emailVerificationToken = null;
  user.emailVerificationExpires = null;
  user.accountStatus = "active"; // account access retained per carve-out
  // Never clear a legal hold here: the query already excludes held accounts,
  // but a hold set concurrently must survive an automated trim.
  user.erasureWarnedAt = null;
  user.erasureDueAt = null;
  // Mark the trim so the SAME record is not re-trimmed (and re-certificated)
  // on every subsequent retention pass. If the DP logs in again, `lastActiveAt`
  // advances past this marker and future inactivity can be evaluated afresh.
  user.retentionTrimmedAt = new Date();
  await user.save({ validateBeforeSave: false });

  const erasedAt = new Date();
  const evidence_hash = crypto
    .createHash("sha256")
    .update([subjectRef, "third_schedule_carveout", erasedAt.toISOString()].join("|"))
    .digest("hex");

  const cert = await ErasureCertificate.create({
    subject_ref: subjectRef,
    trigger: "inactivity",
    categories: ["sessions", "passkeys", "optional_consents", "cookie_consents", "telemetry"],
    systems: [
      `sessions:${sessions.deletedCount}`,
      `passkeys:${passkeys.deletedCount}`,
      `cookie_consents:${cookieConsents.deletedCount}`,
      "account_access_record:retained (Third Schedule carve-out)",
    ],
    actor,
    erased_at: erasedAt,
    notes:
      "Third Schedule carve-out: the account-access record is retained; only non-carve-out data was erased.",
    evidence_hash,
  });

  await appendAudit({
    userId: null,
    actorToken: subjectRef,
    action: "INACTIVITY_TRIM_COMPLETED",
    category: "erasure",
    lawfulBasis: "Rule 8(1) + Third Schedule carve-out",
    targetType: "ErasureCertificate",
    targetId: cert.certificate_id,
    status: "SUCCESS",
    details: "account-access record retained",
  });

  return cert;
};

/** Send the Rule 8(2) ≥48-hour pre-erasure warning. */
export const sendErasureWarning = async (user, dueAt) => {
  const subject = `${process.env.PROJECT_NAME || "Starter Kit"} — your account is scheduled for deletion`;
  const text =
    `Hi ${user.firstName},\n\n` +
    `Your account has been inactive, and under our retention schedule ` +
    `(DPDP Act 2023 s. 8(8), Rule 8) it is scheduled for erasure on ` +
    `${dueAt.toISOString()}.\n\n` +
    `If you wish to keep your account, simply sign in before that date.\n\n` +
    `If you believe this is an error, contact our Data Protection Officer.`;
  try {
    await sendEmail(user.email, subject, text, `<p>${text.replace(/\n/g, "<br/>")}</p>`);
  } catch (err) {
    systemLog({
      level: "WARN",
      event: "ERASURE_WARNING_EMAIL_FAILED",
      message: err.message,
    });
  }
};

/**
 * Evaluate all retention rules and perform due erasures. Returns a summary.
 * @param {object} opts { dryRun?: boolean }
 */
export const runRetentionPass = async ({ dryRun = false } = {}) => {
  const now = new Date();
  const summary = {
    warned: 0,
    erasedInactive: 0,
    erasedRequests: 0,
    logsPurged: 0,
    cookieConsentsPurged: 0,
    skippedLegalHold: 0,
    incidentHold: false,
    dryRun,
  };

  // Evidence preservation (Rule 7): while a breach incident is open or merely
  // contained, suppress ALL erasure — not just log purges — so records that may
  // be evidence are not destroyed mid-investigation.
  const hasOpenIncident = await Breach.exists({
    status: { $in: ["open", "contained"] },
  });
  summary.incidentHold = Boolean(hasOpenIncident);

  // --- 1. Inactivity (s. 8(8), Rule 8(1)/(2)) ---
  const inactiveCutoff = new Date(now.getTime() - INACTIVITY_ERASURE_DAYS * DAY);
  const inactive = await User.find({
    accountStatus: { $ne: "erased" },
    legalHold: false,
    lastActiveAt: { $lt: inactiveCutoff },
    // Skip accounts already trimmed for inactivity (no re-trim loop): only
    // evaluate if they were trimmed before their last activity.
    $or: [
      { retentionTrimmedAt: null },
      { $expr: { $lt: ["$retentionTrimmedAt", "$lastActiveAt"] } },
    ],
  });

  for (const user of inactive) {
    if (user.legalHold) {
      summary.skippedLegalHold += 1;
      continue;
    }
    const dueAt = new Date(
      (user.lastActiveAt || user.createdAt).getTime() + INACTIVITY_ERASURE_DAYS * DAY
    );

    if (!user.erasureWarnedAt) {
      // First pass: warn, do not erase yet (Rule 8(2)).
      summary.warned += 1;
      if (!dryRun) {
        // Warn only if we have not already warned (48h clock starts now).
        const in48h = new Date(now.getTime() + ERASURE_WARNING_HOURS * HOUR);
        user.erasureWarnedAt = now;
        user.erasureDueAt = in48h > dueAt ? in48h : dueAt;
        await user.save({ validateBeforeSave: false });
        await sendErasureWarning(user, user.erasureDueAt);
      }
      continue;
    }

    const warnedLongEnough =
      now.getTime() - new Date(user.erasureWarnedAt).getTime() >= ERASURE_WARNING_HOURS * HOUR;
    if (warnedLongEnough && (!user.erasureDueAt || now >= user.erasureDueAt)) {
      summary.erasedInactive += 1;
      // Third Schedule carve-out: erase everything EXCEPT the account-access
      // record (which must survive so the DP can still reach her account).
      if (!dryRun && !hasOpenIncident) await trimInactiveUser({ userId: user._id });
    }
  }

  // --- 2. Deletion requests / consent withdrawal (s. 8(7)) ---
  const requested = await User.find({
    accountStatus: "erasure_pending",
    legalHold: false,
  });
  for (const user of requested) {
    if (user.legalHold) {
      summary.skippedLegalHold += 1;
      continue;
    }
    summary.erasedRequests += 1;
    if (!dryRun && !hasOpenIncident)
      await eraseUserData({ userId: user._id, trigger: "consent_withdrawn" });
  }

  // NOTE — Third Schedule carve-out: the erasure obligation does NOT apply to
  // data that (a) enables the DP to access her user account, or (b) enables
  // access to a virtual token usable for money/goods/services. Those purposes
  // (`account`, `virtual-token-access`) are therefore NEVER scheduled for
  // erasure on the inactivity clock; the account-access record is preserved
  // even though other purposes are erased. Erasure here is driven by consent
  // withdrawal / a deletion request, not by the inactivity clock.

  // --- 3. Audit/log retention floor (Rule 8(3) + Seventh Schedule) ---
  // Erase logs older than the retention floor, BUT preserve everything while
  // an incident is open (hasOpenIncident computed above).
  if (!hasOpenIncident) {
    const logCutoff = new Date(now.getTime() - LOG_RETENTION_DAYS * DAY);
    if (dryRun) {
      summary.logsPurged = await AuditLog.countDocuments({ createdAt: { $lt: logCutoff } });
    } else {
      // Anchor the chain BEFORE deleting, so verifyAuditChain() can resume from
      // the last purged link (otherwise a lawful purge would look like tampering).
      const lastToPurge = await AuditLog.findOne({ createdAt: { $lt: logCutoff } })
        .sort({ createdAt: -1, _id: -1 })
        .select("hash createdAt")
        .lean();
      if (lastToPurge?.hash) {
        await AuditAnchor.create({
          lastPurgedHash: lastToPurge.hash,
          purgedThrough: lastToPurge.createdAt || logCutoff,
          purgedCount: await AuditLog.countDocuments({ createdAt: { $lt: logCutoff } }),
        });
      }
      const res = await AuditLog.deleteMany({ createdAt: { $lt: logCutoff } });
      summary.logsPurged = res.deletedCount || 0;
    }
    // Domain 8: cookie-consent artefacts (which include the hashed consent
    // IP under the `consent_audit` purpose) are erased past the ≥1-year floor,
    // unless an incident is open. This is the evidential-retention boundary.
    if (dryRun) {
      summary.cookieConsentsPurged = await CookieConsent.countDocuments({
        captured_at: { $lt: logCutoff },
      });
    } else {
      const cc = await CookieConsent.deleteMany({ captured_at: { $lt: logCutoff } });
      summary.cookieConsentsPurged = cc.deletedCount || 0;
    }
  }

  audit({
    action: "RETENTION_PASS",
    category: "erasure",
    lawfulBasis: "Rule 8",
    status: "SUCCESS",
    details: `warned=${summary.warned} erasedInactive=${summary.erasedInactive} erasedRequests=${summary.erasedRequests} logsPurged=${summary.logsPurged} dryRun=${dryRun}`,
  });

  return summary;
};
