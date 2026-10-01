// ===========================================================
// 🇮🇳 PRIVACY / DPDP CONTROLLER — ss. 5–14, Rules 3/8/9/10/14
// ===========================================================
// Surfaces for notice, consent, and every Data Principal right. All handlers
// are wrapped by `requestHandler` and return `ApiResponse` like the rest of
// the codebase.

import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import ApiResponse from "../utility/ApiResponse.js";
import User from "../models/user.model.js";
import RightsRequest from "../models/rightsRequest.model.js";
import buildNotice, { buildLegacyMigrationNotice } from "../utility/notice.js";
import {
  PURPOSES,
  getDpoContact,
  getBoardComplaintInfo,
  NOTICE_VERSION,
  DPDP_LEGAL_VERSION,
} from "../config/dpdp.config.js";
import {
  recordConsent,
  getConsentState,
  withdrawConsent,
} from "../services/consent.service.js";
import {
  handleAccess,
  handleCorrection,
  handleErasure,
  handleGrievance,
  handleNomination,
  escalateToBoard,
  createRightsRequest,
} from "../services/rights.service.js";
import { ageFromDob, recordGuardianConsent } from "../services/age.service.js";
import { rotateCsrfToken } from "../middlewares/csrf.middleware.js";
import {
  getNominees,
  setNominees,
  updateNominee,
  removeNominee,
  submitClaim,
} from "../services/nominee.service.js";

// ==========================================
// 📜 NOTICE (public) — s. 5, Rule 3
// ==========================================
const getNotice = requestHandler(async (req, res) => {
  const language = req.query.language || "en";
  const notice = buildNotice(language);
  return res.status(200).json(new ApiResponse(200, "Notice", notice));
});

// s. 5(2) — migration notice for consent obtained before commencement.
const getLegacyNotice = requestHandler(async (req, res) => {
  const language = req.query.language || "en";
  return res
    .status(200)
    .json(new ApiResponse(200, "Legacy migration notice", buildLegacyMigrationNotice(language)));
});

// Public purpose registry so the signup UI can render itemised consents.
const getPurposes = requestHandler(async (_req, res) => {
  return res.status(200).json(
    new ApiResponse(200, "Purposes", {
      notice_version: NOTICE_VERSION,
      legal_version: DPDP_LEGAL_VERSION,
      purposes: PURPOSES,
      dpo: getDpoContact(),
      board: getBoardComplaintInfo(),
    })
  );
});

// ==========================================
// ✅ CONSENT STATE — s. 6
// ==========================================
const getMyConsent = requestHandler(async (req, res) => {
  const state = await getConsentState(req.user._id);
  return res.status(200).json(
    new ApiResponse(200, "Consent state", {
      purposes: state,
      registry: PURPOSES.map((p) => ({ id: p.id, required: p.required, label: p.label })),
      notice_version: NOTICE_VERSION,
    })
  );
});

// Grant consent for one or more purposes (opt-in; no pre-ticked).
const grantConsent = requestHandler(async (req, res) => {
  const { purposes, language } = req.body;
  if (!Array.isArray(purposes) || purposes.length === 0)
    throw new ApiError(400, "At least one purpose is required");

  const artefact = await recordConsent({
    userId: req.user._id,
    purposes,
    action: "granted",
    req,
    language: language || "en",
  });

  // Keep telemetry level in sync with analytics consent for adults.
  const user = await User.findById(req.user._id);
  if (user && !user.isChild && purposes.includes("analytics")) {
    user.telemetryDisabled = false;
    await user.save({ validateBeforeSave: false });
  }

  return res.status(200).json(
    new ApiResponse(200, "Consent recorded", {
      consent_id: artefact._id,
      evidence_hash: artefact.evidence_hash,
      notice_version: artefact.notice_version,
    })
  );
});

// Withdraw consent for a purpose (or all) — equal ease (s. 6(4)).
const withdrawMyConsent = requestHandler(async (req, res) => {
  const { purposeId, language } = req.body;
  const artefact = await withdrawConsent({
    userId: req.user._id,
    purposeId: purposeId || "all",
    req,
    language: language || "en",
  });
  return res.status(200).json(
    new ApiResponse(200, "Consent withdrawn. Processing for that purpose has stopped.", {
      consent_id: artefact._id,
      purposes: artefact.purposes,
    })
  );
});

// ==========================================
// 🗂️ DATA PRINCIPAL RIGHTS — ss. 11–14
// ==========================================
// s. 11 — Access
const getMyData = requestHandler(async (req, res) => {
  const { summary } = await handleAccess({
    userId: req.user._id,
    req,
    language: req.query.language || "en",
  });
  return res.status(200).json(new ApiResponse(200, "Your data", summary));
});

// s. 12 — Correction
const correctMyData = requestHandler(async (req, res) => {
  const { caseDoc, user, emailChanged } = await handleCorrection({
    userId: req.user._id,
    updates: req.body,
    req,
    language: req.body.language || "en",
  });
  if (!user)
    throw new ApiError(409, caseDoc.resolution_notes || "Correction could not be applied");
  return res.status(200).json(
    new ApiResponse(
      200,
      emailChanged
        ? "Data corrected. Your email changed — please verify the new address; you have been signed out to re-authenticate."
        : "Data corrected",
      { case_id: caseDoc.case_id, emailChanged: Boolean(emailChanged) }
    )
  );
});

// s. 12 — Erasure (hard delete, cascade)
const eraseMyData = requestHandler(async (req, res) => {
  const { caseDoc, erased, reason, certificate_id } = await handleErasure({
    userId: req.user._id,
    req,
    language: req.body.language || "en",
  });
  if (!erased) {
    const msg =
      reason === "not_found"
        ? "No matching account found to erase."
        : `Retention required: ${reason}`;
    throw new ApiError(409, msg, { case_id: caseDoc.case_id, reason });
  }
  // Clear every auth cookie — the account no longer exists. The CSRF token was
  // bound to the now-deleted session, so clear it too and hand back a fresh
  // token bound to the post-deletion (anonymous) context.
  res.clearCookie("session_id");
  res.clearCookie("device_id");
  res.clearCookie("_csrf_token");
  // The session no longer exists, so rebind the CSRF token to the anonymous
  // (device) context used by the public endpoints.
  delete req.cookies.session_id;
  const csrfToken = rotateCsrfToken(req, res);
  return res.status(200).json(
    new ApiResponse(200, "Your data has been erased", {
      case_id: caseDoc.case_id,
      certificate_id,
      erased: true,
      csrfToken,
    })
  );
});

// s. 13 — Grievance
const raiseGrievance = requestHandler(async (req, res) => {
  const caseDoc = await handleGrievance({
    userId: req.user._id,
    subject: req.body.subject,
    message: req.body.message,
    req,
    language: req.body.language || "en",
  });
  return res.status(201).json(
    new ApiResponse(201, "Grievance received. We target resolution within 30 days (Rule 14).", {
      case_id: caseDoc.case_id,
      sla_due_at: caseDoc.sla_due_at,
      board: getBoardComplaintInfo(),
    })
  );
});

// s. 13 — escalate to Board after exhausting internal mechanism
const escalateGrievance = requestHandler(async (req, res) => {
  const caseDoc = await RightsRequest.findOne({
    case_id: req.body.case_id,
    user_id: req.user._id,
  });
  if (!caseDoc) throw new ApiError(404, "Case not found");
  if (caseDoc.status === "completed")
    throw new ApiError(400, "This case is already resolved");

  await escalateToBoard({ caseDoc, boardReference: req.body.board_reference });
  return res.status(200).json(
    new ApiResponse(200, "Escalated to the Data Protection Board", {
      case_id: caseDoc.case_id,
      board: getBoardComplaintInfo(),
    })
  );
});

// s. 14 — Nomination
const nominate = requestHandler(async (req, res) => {
  const { nominees } = req.body;
  if (!Array.isArray(nominees) || nominees.length === 0)
    throw new ApiError(400, "At least one nominee is required");
  const result = await handleNomination({
    userId: req.user._id,
    nominees,
    req,
    language: req.body.language || "en",
  });
  return res.status(200).json(
    new ApiResponse(200, "Nominee(s) recorded", {
      case_id: result.caseDoc.case_id,
      nominees: result.nominees,
    })
  );
});

// s. 14 — list my nominees (masked)
const listMyNominees = requestHandler(async (req, res) => {
  const nominees = await getNominees(req.user._id);
  return res.status(200).json(new ApiResponse(200, "Your nominees", { nominees }));
});

// s. 14 — replace my nominee list
const setMyNominees = requestHandler(async (req, res) => {
  const { nominees } = req.body;
  if (!Array.isArray(nominees))
    throw new ApiError(400, "nominees must be an array");
  const saved = await setNominees({ userId: req.user._id, nominees, req });
  return res
    .status(200)
    .json(new ApiResponse(200, "Nominees saved", { nominees: saved }));
});

// s. 14 — edit a single nominee by index
const editMyNominee = requestHandler(async (req, res) => {
  const index = parseInt(req.params.index, 10);
  if (Number.isNaN(index)) throw new ApiError(400, "Invalid nominee index");
  const updated = await updateNominee({
    userId: req.user._id,
    index,
    updates: req.body,
    req,
  });
  return res
    .status(200)
    .json(new ApiResponse(200, "Nominee updated", { nominee: updated }));
});

// s. 14 — remove (soft) a nominee by index
const removeMyNominee = requestHandler(async (req, res) => {
  const index = parseInt(req.params.index, 10);
  if (Number.isNaN(index)) throw new ApiError(400, "Invalid nominee index");
  const updated = await removeNominee({ userId: req.user._id, index, req });
  return res
    .status(200)
    .json(new ApiResponse(200, "Nominee removed", { nominee: updated }));
});

// s. 14 — PUBLIC: a nominee submits a claim on death/incapacity.
const submitNomineeClaim = requestHandler(async (req, res) => {
  const {
    dataPrincipalId,
    nomineeIndex,
    claimantName,
    claimantContact,
    claimantRelationship,
    basis,
    evidenceReference,
    note,
  } = req.body;
  if (!dataPrincipalId || !claimantName || !basis)
    throw new ApiError(400, "dataPrincipalId, claimantName and basis are required");
  const result = await submitClaim({
    dataPrincipalId,
    nomineeIndex: Number(nomineeIndex) || 0,
    claimantName,
    claimantContact,
    claimantRelationship,
    basis,
    evidenceReference,
    note,
    req,
  });
  // Track the claim as a rights case for the SLA clock + audit trail.
  await createRightsRequest({
    userId: dataPrincipalId,
    type: "nomination",
    purposeId: null,
    payload: { claim_id: result.claim_id, basis },
    req,
    language: req.body.language || "en",
  });
  return res.status(201).json(
    new ApiResponse(
      201,
      "Claim received. Our Data Protection Officer will verify the documents and contact you.",
      result
    )
  );
});

// List the caller's own rights cases (case id + SLA + status).
const listMyCases = requestHandler(async (req, res) => {
  const cases = await RightsRequest.find({ user_id: req.user._id })
    .sort({ requested_at: -1 })
    .lean();
  return res.status(200).json(new ApiResponse(200, "Your requests", { cases }));
});

// ==========================================
// 👶 CHILDREN / GUARDIAN — s. 9, Rule 10/11
// ==========================================
// Report the caller's age status so the UI can gate features.
const ageStatus = requestHandler(async (req, res) => {
  return res.status(200).json(
    new ApiResponse(200, "Age status", {
      isChild: req.user.isChild,
      guardianVerified: req.user.guardianVerified,
      age: req.user.dateOfBirth ? ageFromDob(req.user.dateOfBirth) : null,
      childLimit: 18,
      telemetryDisabled: req.user.telemetryDisabled,
    })
  );
});

// Record verifiable guardian consent (Rule 10/11). In a real integration the
// `verificationMethod` would be satisfied by an authorised entity / Digital
// Locker / Board-recognised mechanism.
const submitGuardianConsent = requestHandler(async (req, res) => {
  const {
    relationship,
    guardianName,
    guardianEmail,
    guardianPhone,
    verificationMethod,
  } = req.body;

  if (!req.user.isChild) throw new ApiError(400, "Not required for adult accounts");
  if (!guardianName || !verificationMethod)
    throw new ApiError(400, "Guardian name and verification method are required");

  const consent = await recordGuardianConsent({
    childUserId: req.user._id,
    relationship: relationship || "parent",
    guardianName,
    guardianEmail,
    guardianPhone,
    verificationMethod,
    verifier: "self-attested-with-due-diligence",
  });

  return res.status(201).json(
    new ApiResponse(201, "Guardian consent recorded", {
      guardian_consent_id: consent._id,
      evidence_hash: consent.evidence_hash,
    })
  );
});

// ==========================================
// 🔐 SECURITY — audit-chain verification (read-only proof of integrity)
// ==========================================
// Self-service: an authenticated Data Principal can verify that their audit
// trail has not been silently tampered with. Returns pass/fail + counts only,
// never any PII or another principal's records.
const verifyAuditIntegrity = requestHandler(async (_req, res) => {
  const { verifyAuditChain } = await import("../utility/auditChain.js");
  const result = await verifyAuditChain();
  return res.status(200).json(new ApiResponse(200, "Audit chain verification", result));
});

export {
  getNotice,
  getLegacyNotice,
  getPurposes,
  getMyConsent,
  grantConsent,
  withdrawMyConsent,
  getMyData,
  correctMyData,
  eraseMyData,
  raiseGrievance,
  escalateGrievance,
  nominate,
  listMyNominees,
  setMyNominees,
  editMyNominee,
  removeMyNominee,
  submitNomineeClaim,
  listMyCases,
  ageStatus,
  submitGuardianConsent,
  verifyAuditIntegrity,
};
