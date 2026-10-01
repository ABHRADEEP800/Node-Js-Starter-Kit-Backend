// ===========================================================
// 🛡️ ADMIN DPDP CONTROLLER — s. 8(6)/s. 10/s. 16, Rules 7/13/15
// ===========================================================
// Admin-only surfaces for the compliance control plane: breach workflow,
// retention runs, rights SLA dashboard, cross-border transfer register,
// DPIA/SDF register, and audit-chain verification.

import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import ApiResponse from "../utility/ApiResponse.js";
import Breach from "../models/breach.model.js";
import TransferRegister from "../models/transferRegister.model.js";
import Dpia from "../models/dpia.model.js";
import AuditLog from "../models/auditLog.model.js";
import RightsRequest from "../models/rightsRequest.model.js";
import User from "../models/user.model.js";
import { maskObject, maskPII } from "../utility/piiMask.js";
import { decryptField } from "../utility/cryptoVault.js";
import { verifyAuditChain } from "../utility/auditChain.js";
import { audit } from "../events/auditLog.events.js";
import {
  openIncident,
  buildIncidentReport,
  buildBoardFirstReportDraft,
  buildBoardDetailedReportDraft,
  buildDataPrincipalNoticeDraft,
  breachCountdown,
} from "../services/breach.service.js";
import { runRetentionPass } from "../services/retention.service.js";
import { slaStatus } from "../services/rights.service.js";
import {
  listClaims,
  decideClaim,
} from "../services/nominee.service.js";

// ---------- Rights SLA dashboard (Rule 14) ----------
const rightsDashboard = requestHandler(async (_req, res) => {
  const cases = await slaStatus();
  return res.status(200).json(new ApiResponse(200, "Rights SLA status", { cases }));
});

// ---------- Rights & grievance inbox (ss. 11–14) ----------
// Full case list an admin needs to actually act on grievances/rights requests.
// Optionally filter by type (e.g. ?type=grievance) or status.
const listRightsCases = requestHandler(async (req, res) => {
  // Validate filter values against the enum — never interpolate arbitrary query
  // input into the Mongo filter.
  const TYPES = ["access", "correction", "erasure", "withdraw", "grievance", "nomination"];
  const STATUSES = ["received", "in_progress", "completed", "rejected", "escalated"];
  const filter = {};
  if (req.query.type) {
    if (!TYPES.includes(req.query.type)) throw new ApiError(400, "Invalid type filter");
    filter.type = req.query.type;
  }
  if (req.query.status) {
    if (!STATUSES.includes(req.query.status)) throw new ApiError(400, "Invalid status filter");
    filter.status = req.query.status;
  }
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);

  const cases = await RightsRequest.find(filter)
    .sort({ requested_at: -1 })
    .limit(limit)
    .populate("user_id", "firstName lastName username email")
    .lean();

  // Mask the linked user's email; never expose raw contact in an admin list.
  const safe = cases.map((c) => {
    const out = maskObject(c);
    if (out.user_id && typeof out.user_id === "object") {
      out.user_id.email = c.user_id?.email
        ? maskPII(c.user_id.email, "email")
        : null;
    }
    return out;
  });

  return res
    .status(200)
    .json(new ApiResponse(200, "Rights cases", { cases: safe, count: safe.length }));
});

// Resolve / update a rights case (acknowledge, resolve, reject, escalate).
const updateRightsCase = requestHandler(async (req, res) => {
  const { case_id } = req.params;
  const { status, resolution_notes, board_reference } = req.body;
  const caseDoc = await RightsRequest.findOne({ case_id });
  if (!caseDoc) throw new ApiError(404, "Case not found");

  if (status) {
    const allowed = ["received", "in_progress", "completed", "rejected", "escalated"];
    if (!allowed.includes(status)) throw new ApiError(400, "Invalid status");
    caseDoc.status = status;
    if (status === "completed" || status === "rejected") {
      caseDoc.resolved_at = new Date();
    }
  }
  if (typeof resolution_notes === "string") {
    caseDoc.resolution_notes = resolution_notes.slice(0, 2000);
  }
  if (status === "escalated") {
    caseDoc.escalation = {
      to_board: true,
      at: new Date(),
      board_reference: board_reference || null,
    };
  }
  if (!caseDoc.acknowledged_at) caseDoc.acknowledged_at = new Date();
  await caseDoc.save();

  audit({
    action: "RIGHTS_CASE_UPDATED",
    category: "rights",
    targetType: "RightsRequest",
    targetId: caseDoc.case_id,
    status: "SUCCESS",
    details: `status=${caseDoc.status}`,
  });

  return res
    .status(200)
    .json(new ApiResponse(200, "Case updated", { case: maskObject(caseDoc.toObject()) }));
});

// ---------- Nominee claims (s. 14) ----------
const listNomineeClaims = requestHandler(async (req, res) => {
  const claims = await listClaims({ status: req.query.status });
  return res.status(200).json(new ApiResponse(200, "Nominee claims", { claims }));
});

const decideNomineeClaim = requestHandler(async (req, res) => {
  const { claimId } = req.params;
  const { decision, note } = req.body;
  if (!["approve", "reject"].includes(decision))
    throw new ApiError(400, "decision must be approve or reject");
  const result = await decideClaim({
    claimId,
    decision,
    note,
    adminId: req.user._id,
  });
  return res.status(200).json(new ApiResponse(200, "Claim decided", result));
});

// Admin view of a DP's nominee list (decrypted, for verification of a claim).
const adminGetNominees = requestHandler(async (req, res) => {
  const user = await User.findById(req.params.userId)
    .select("nominees nomineeClaim")
    .lean();
  if (!user) throw new ApiError(404, "User not found");
  const nominees = (user.nominees || []).map((n) => {
    const contact = decryptField(n.contact) || "";
    return {
      ...maskObject(n),
      name: decryptField(n.name),
      contact: maskPII(contact, contact.includes("@") ? "email" : "phone"),
    };
  });
  return res
    .status(200)
    .json(new ApiResponse(200, "Nominees", { nominees, claim: user.nomineeClaim }));
});

// ---------- Breach workflow (s. 8(6), Rule 7) ----------
const listIncidents = requestHandler(async (_req, res) => {
  const incidents = await Breach.find({}).sort({ detected_at: -1 }).lean();
  return res
    .status(200)
    .json(new ApiResponse(200, "Incidents", { incidents: incidents.map(maskObject) }));
});

const createIncident = requestHandler(async (req, res) => {
  const incident = await openIncident({ input: req.body, actor: String(req.user._id) });
  return res
    .status(201)
    .json(new ApiResponse(201, "Incident opened", { incident: maskObject(incident.toObject()) }));
});

const getIncidentReport = requestHandler(async (req, res) => {
  const report = await buildIncidentReport(req.params.incidentId);
  return res.status(200).json(new ApiResponse(200, "Incident report", report));
});

const getIncidentDrafts = requestHandler(async (req, res) => {
  const [first, detailed, dpNotice, countdown] = await Promise.all([
    buildBoardFirstReportDraft(req.params.incidentId),
    buildBoardDetailedReportDraft(req.params.incidentId),
    buildDataPrincipalNoticeDraft(req.params.incidentId),
    breachCountdown(req.params.incidentId),
  ]);
  return res.status(200).json(
    new ApiResponse(200, "Rule 7 notification drafts", {
      board_first_report: first,
      board_detailed_report: detailed,
      data_principal_notice: dpNotice,
      countdown,
    })
  );
});

// Mark the Board reports / DP notifications as actually sent (evidence).
const markIncidentNotified = requestHandler(async (req, res) => {
  const { stage, note } = req.body;
  const incident = await Breach.findOne({ incident_id: req.params.incidentId });
  if (!incident) throw new ApiError(404, "Incident not found");

  if (stage === "board_first") incident.board_first_reported_at = new Date();
  else if (stage === "board_detailed") incident.board_detailed_reported_at = new Date();
  else if (stage === "data_principals") incident.data_principals_notified_at = new Date();
  else if (stage === "contained") incident.status = "contained";
  else if (stage === "close") {
    incident.status = "closed";
    incident.closed_at = new Date();
    incident.post_mortem = note || incident.post_mortem;
  } else if (stage === "extension") {
    incident.board_extension_granted = true;
    incident.board_extension_notes = note || "Board granted written extension (Rule 7(2)(b))";
  } else {
    throw new ApiError(400, "Unknown stage");
  }
  if (note) {
    incident.timeline.push({ at: new Date(), actor: String(req.user._id), event: stage, note });
  }
  await incident.save();

  audit({
    action: "BREACH_TIMELINE_EVENT",
    category: "breach",
    targetType: "Breach",
    targetId: incident.incident_id,
    status: "SUCCESS",
    details: `stage=${stage}`,
  });

  return res.status(200).json(new ApiResponse(200, "Incident updated", { incident: maskObject(incident.toObject()) }));
});

// ---------- Retention / erasure run (s. 8(7)/(8), Rule 8) ----------
const runRetention = requestHandler(async (req, res) => {
  const dryRun = req.body?.dryRun !== false; // default to dry-run (safe)
  const summary = await runRetentionPass({ dryRun });
  return res.status(200).json(new ApiResponse(200, "Retention pass complete", summary));
});

// ---------- Cross-border transfer register (s. 16, Rule 15) ----------
const listTransfers = requestHandler(async (_req, res) => {
  const transfers = await TransferRegister.find({}).sort({ createdAt: -1 }).lean();
  return res.status(200).json(new ApiResponse(200, "Transfer register", { transfers }));
});

const upsertTransfer = requestHandler(async (req, res) => {
  const { id, ...body } = req.body;
  if (!body.country || !body.recipient || !body.purpose_id)
    throw new ApiError(400, "country, recipient and purpose_id are required");
  const doc = id
    ? await TransferRegister.findByIdAndUpdate(id, body, { new: true, upsert: true })
    : await TransferRegister.create(body);
  audit({
    action: "TRANSFER_REGISTER_UPSERT",
    category: "security",
    targetType: "TransferRegister",
    targetId: String(doc._id),
    status: "SUCCESS",
    details: `country=${doc.country}`,
  });
  return res.status(200).json(new ApiResponse(200, "Transfer registered", { transfer: doc }));
});

// ---------- DPIA / SDF register (s. 10, Rule 13) ----------
const listDpias = requestHandler(async (_req, res) => {
  const dpias = await Dpia.find({}).sort({ reviewed_at: -1 }).lean();
  return res.status(200).json(new ApiResponse(200, "DPIA register", { dpias }));
});

const upsertDpia = requestHandler(async (req, res) => {
  const { id, ...body } = req.body;
  if (!body.activity_name) throw new ApiError(400, "activity_name is required");

  // SDF: annual DPIA + audit (Rule 13) → next review ≤ 12 months.
  const reviewedAt = body.reviewed_at ? new Date(body.reviewed_at) : new Date();
  const nextReview = body.next_review_due_at
    ? new Date(body.next_review_due_at)
    : new Date(reviewedAt.getTime() + 365 * 24 * 60 * 60 * 1000);

  const doc = id
    ? await Dpia.findByIdAndUpdate(id, { ...body, reviewed_at: reviewedAt, next_review_due_at: nextReview }, { new: true })
    : await Dpia.create({ ...body, reviewed_at: reviewedAt, next_review_due_at: nextReview });

  audit({
    action: "DPIA_UPSERT",
    category: "admin",
    targetType: "Dpia",
    targetId: String(doc._id),
    status: "SUCCESS",
  });
  return res.status(200).json(new ApiResponse(200, "DPIA recorded", { dpia: doc }));
});

// ---------- Audit integrity (Rule 6(c)) ----------
const auditIntegrity = requestHandler(async (_req, res) => {
  const result = await verifyAuditChain();
  return res.status(200).json(new ApiResponse(200, "Audit chain verification", result));
});

const listAudit = requestHandler(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  const filter = {};
  if (req.query.category) filter.category = req.query.category;
  const entries = await AuditLog.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
  return res.status(200).json(new ApiResponse(200, "Audit log", { entries: entries.map(maskObject) }));
});

export {
  rightsDashboard,
  listRightsCases,
  updateRightsCase,
  listNomineeClaims,
  decideNomineeClaim,
  adminGetNominees,
  listIncidents,
  createIncident,
  getIncidentReport,
  getIncidentDrafts,
  markIncidentNotified,
  runRetention,
  listTransfers,
  upsertTransfer,
  listDpias,
  upsertDpia,
  auditIntegrity,
  listAudit,
};
