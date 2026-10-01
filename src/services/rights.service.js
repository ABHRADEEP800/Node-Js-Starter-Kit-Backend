// ===========================================================
// 🗂️ DATA PRINCIPAL RIGHTS SERVICE — ss. 11–14, Rule 14
// ===========================================================
// Access, correction, erasure, withdrawal, grievance and nomination. Every
// request gets a case id, an SLA clock (target 30 days, ceiling 90) and an
// append-only audit trail. Identity is verified with minimal, risk-based proof.

import RightsRequest from "../models/rightsRequest.model.js";
import User from "../models/user.model.js";
import Session from "../models/session.model.js";
import Consent from "../models/consent.model.js";
import Passkey from "../models/passkey.model.js";
import { audit } from "../events/auditLog.events.js";
import { maskObject, maskPII } from "../utility/piiMask.js";
import { computeSlaDueAt, RIGHTS_RULE_REF, getDpoContact, getBoardComplaintInfo } from "../config/dpdp.config.js";
import { getConsentState } from "./consent.service.js";
import { eraseUserData } from "./retention.service.js";
// Deferred (function-body) usage breaks the import cycle at module-eval time.
import { setNominees } from "./nominee.service.js";

/**
 * Rule 9 / s. 8(9): every rights response must carry the DPO/authorised-person
 * contact details and the Board-complaint route. Merge into each response.
 */
const withContact = (payload) => ({
  ...payload,
  data_fiduciary_contact: getDpoContact(),
  board_complaint: getBoardComplaintInfo(),
});

/** Open a rights case with an SLA clock. */
export const createRightsRequest = async ({
  userId,
  type,
  purposeId = null,
  payload = {},
  language = "en",
  req,
}) => {
  const caseDoc = await RightsRequest.create({
    user_id: userId,
    type,
    purpose_id: purposeId,
    // Store only masked payload — never raw PII in the request record.
    payload: maskObject(payload),
    language,
    sla_due_at: computeSlaDueAt(),
    rule_ref: RIGHTS_RULE_REF,
    identity_verification: { method: "session_authenticated", verified_at: new Date() },
  });

  audit({
    userId,
    action: `RIGHT_${type.toUpperCase()}_REQUESTED`,
    category: "rights",
    targetType: "RightsRequest",
    targetId: caseDoc.case_id,
    status: "SUCCESS",
    details: `case=${caseDoc.case_id} sla=${caseDoc.sla_due_at.toISOString()}`,
    ip: req?.ip,
    userAgent: req?.headers?.["user-agent"],
  });

  return caseDoc;
};

const complete = async (caseDoc, notes) => {
  caseDoc.status = "completed";
  caseDoc.resolved_at = new Date();
  caseDoc.resolution_notes = notes;
  await caseDoc.save();
  audit({
    userId: caseDoc.user_id,
    action: `RIGHT_${caseDoc.type.toUpperCase()}_COMPLETED`,
    category: "rights",
    targetType: "RightsRequest",
    targetId: caseDoc.case_id,
    status: "SUCCESS",
    details: notes,
  });
  return caseDoc;
};

/**
 * s. 11 — Access: a summary of personal data being processed, the processing
 * activities, and the identities of Data Fiduciaries/Processors it was shared
 * with (with the law-enforcement carve-out).
 */
export const handleAccess = async ({ userId, req, language }) => {
  const caseDoc = await createRightsRequest({ userId, type: "access", req, language });

  const user = await User.findById(userId).lean();
  const [consentState, consents, sessions, passkeys] = await Promise.all([
    getConsentState(userId),
    Consent.find({ user_id: userId }).sort({ captured_at: -1 }).lean(),
    Session.find({ user_id: userId }).select("ip browser os last_seen remember revoked").lean(),
    Passkey.find({ user_id: userId }).select("name last_used_at createdAt").lean(),
  ]);

  const summary = {
    case_id: caseDoc.case_id,
    generated_at: new Date().toISOString(),
    data_fiduciary: getDpoContact(),
    personal_data: {
      firstName: user.firstName,
      lastName: user.lastName,
      username: user.username,
      email: maskPII(user.email, "email"),
      isChild: user.isChild,
      guardianVerified: user.guardianVerified,
      // dateOfBirth intentionally summarised, not exported in full.
      dateOfBirth: user.dateOfBirth ? maskPII(user.dateOfBirth.toISOString(), "dob") : null,
      createdAt: user.createdAt,
      lastActiveAt: user.lastActiveAt,
    },
    processing_activities: Object.entries(consentState).map(([purposeId, granted]) => ({
      purpose_id: purposeId,
      consented: granted,
    })),
    consent_history: consents.map((c) => ({
      action: c.action,
      purposes: c.purposes,
      notice_version: c.notice_version,
      language: c.language,
      captured_at: c.captured_at,
    })),
    sessions: sessions.map(maskObject),
    passkeys: passkeys.map(maskObject),
    // s. 11: identities of DFs/Processors we have shared data with. Law
    // enforcement / cyber-incident sharing may be withheld as the Act allows.
    shared_with: [
      {
        name: process.env.SMTP_HOST ? "Email delivery processor (SMTP)" : "Local email test (Ethereal)",
        type: "processor",
        purpose: "service-email",
      },
      {
        name: "Cloud database hosting",
        type: "processor",
        purpose: "account",
      },
    ],
    withheld: {
      law_enforcement: "Sharing details withheld where disclosure would impede law enforcement/cyber-incident response (s. 11 proviso).",
    },
    rights_and_escalation: {
      grievance: "POST /api/v1/privacy/grievance",
      board: getBoardComplaintInfo(),
    },
  };

  await complete(caseDoc, "Access summary generated");
  // Rule 9 / s. 8(9): DPO + Board contact in every rights response.
  return { caseDoc, summary: withContact(summary) };
};

/** s. 12 — Correction/completion of inaccurate data. */
export const handleCorrection = async ({ userId, updates, req, language }) => {
  const caseDoc = await createRightsRequest({
    userId,
    type: "correction",
    payload: updates,
    req,
    language,
  });

  const allowed = {};
  if (typeof updates.firstName === "string") allowed.firstName = updates.firstName.trim();
  if (typeof updates.lastName === "string") allowed.lastName = updates.lastName.trim();

  // Changing the email is a security-sensitive change: the new address must be
  // re-verified and any sessions for the old identity revoked. Otherwise a
  // party could move the account to an unverified address and keep access.
  let emailChanged = false;
  if (typeof updates.email === "string") {
    const email = updates.email.trim().toLowerCase();
    if (email) {
      const clash = await User.findOne({ email, _id: { $ne: userId } });
      if (clash) {
        caseDoc.status = "rejected";
        caseDoc.resolution_notes = "Email already in use";
        await caseDoc.save();
        return { caseDoc, user: null };
      }
      const current = await User.findById(userId).select("email").lean();
      emailChanged = current?.email?.toLowerCase() !== email;
      if (emailChanged) {
        allowed.email = email;
        // Force re-verification of the new address (s. 8(3) accuracy).
        allowed.isEmailVerified = false;
        allowed.emailVerificationToken = null;
        allowed.emailVerificationExpires = null;
      }
    }
  }

  const user = await User.findByIdAndUpdate(userId, allowed, { new: true });

  if (emailChanged) {
    // Revoke every session: the login identity changed.
    await Session.updateMany(
      { user_id: userId, revoked: false },
      { revoked: true }
    );
    audit({
      userId,
      action: "EMAIL_CHANGED_REVERIFY_REQUIRED",
      category: "security",
      status: "SUCCESS",
      details: "Email changed via s.12 correction — re-verification required, sessions revoked",
    });
  }

  await complete(caseDoc, `Corrected fields: ${Object.keys(allowed).join(", ") || "none"}`);
  return { caseDoc, user, emailChanged };
};

/** s. 12 — Erasure (hard delete, cascade) unless a legal hold applies. */
export const handleErasure = async ({ userId, req, language }) => {
  const caseDoc = await createRightsRequest({ userId, type: "erasure", req, language });

  const user = await User.findById(userId).lean();
  if (user?.legalHold) {
    caseDoc.status = "rejected";
    caseDoc.resolution_notes = `Retention required by law: ${user.legalHoldCitation || "unspecified"}`;
    await caseDoc.save();
    return { caseDoc, erased: false, reason: "legal_hold" };
  }

  // Run the cascade FIRST; only mark the case completed once it succeeds, so a
  // failed erasure is never reported as done.
  const cert = await eraseUserData({ userId, trigger: "deletion_request", actor: "rights-workflow" });
  if (!cert) {
    // Nothing was erased (e.g. the user record was already gone). Report the
    // truth rather than a false success.
    caseDoc.status = "rejected";
    caseDoc.resolution_notes = "No matching account found to erase";
    await caseDoc.save();
    return { caseDoc, erased: false, reason: "not_found" };
  }
  await complete(caseDoc, "Erasure executed (cascade)");
  return { caseDoc, erased: true, certificate_id: cert.certificate_id || null };
};

/** s. 14 — Nomination: designate one or more persons for death/incapacity. */
export const handleNomination = async ({ userId, nominees, req, language }) => {
  const caseDoc = await createRightsRequest({
    userId,
    type: "nomination",
    payload: { count: (nominees || []).length },
    req,
    language,
  });

  // Delegate storage to the nominee service: it encrypts name/contact at rest
  // (Rule 6(a)), enforces the max list size, and returns only masked values.
  const maskedNominees = await setNominees({ userId, nominees, req });

  await complete(caseDoc, `Nominees recorded: ${maskedNominees.length}`);
  return { caseDoc, nominees: maskedNominees };
};

/** s. 13 — Grievance: readily available mechanism; exhaust before Board. */
export const handleGrievance = async ({ userId, subject, message, req, language }) => {
  const caseDoc = await createRightsRequest({
    userId,
    type: "grievance",
    // Store the subject and the FULL message (this is the substance an admin
    // needs to resolve the grievance — s. 13). It is user-authored content, not
    // derived PII, but we cap its length and keep it free-text so staff can act.
    payload: {
      subject: String(subject || "").slice(0, 200),
      message: String(message || "").slice(0, 5000),
    },
    req,
    language,
  });

  caseDoc.payload = {
    ...caseDoc.payload,
    message_length: String(message || "").length,
  };
  await caseDoc.save();

  audit({
    userId,
    action: "GRIEVANCE_RAISED",
    category: "rights",
    targetType: "RightsRequest",
    targetId: caseDoc.case_id,
    status: "SUCCESS",
    details: `case=${caseDoc.case_id}`,
  });

  // Acknowledge immediately; resolution tracked against the SLA clock.
  caseDoc.acknowledged_at = new Date();
  caseDoc.status = "in_progress";
  await caseDoc.save();
  return caseDoc;
};

/** Escalate a grievance to the Board after exhausting our mechanism (s. 13). */
export const escalateToBoard = async ({ caseDoc, boardReference }) => {
  caseDoc.status = "escalated";
  caseDoc.escalation = { to_board: true, at: new Date(), board_reference: boardReference || null };
  await caseDoc.save();
  audit({
    userId: caseDoc.user_id,
    action: "GRIEVANCE_ESCALATED_TO_BOARD",
    category: "rights",
    targetType: "RightsRequest",
    targetId: caseDoc.case_id,
    status: "SUCCESS",
  });
  return caseDoc;
};

/** Cases approaching or breaching the SLA (Rule 14). */
export const slaStatus = async () => {
  const now = new Date();
  const open = await RightsRequest.find({ status: { $in: ["received", "in_progress"] } }).lean();
  return open.map((c) => {
    const due = new Date(c.sla_due_at);
    return {
      case_id: c.case_id,
      type: c.type,
      status: c.status,
      sla_due_at: due,
      overdue: due < now,
      days_left: Math.ceil((due.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)),
    };
  });
};
