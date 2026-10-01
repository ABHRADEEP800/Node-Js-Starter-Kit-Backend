// ===========================================================
// 🚨 BREACH WORKFLOW SERVICE — s. 8(6), s. 2(u), Rule 7
// ===========================================================
// Creates an incident, drafts the Rule 7 notifications (Board first report,
// Board 72-hour report, per-Data-Principal notice), tracks the 72-hour
// countdown, and keeps an append-only incident timeline. It NEVER suppresses
// or delays: a missed deadline requires an explicit, logged rationale.

import ApiError from "../utility/ApiError.js";
import crypto from "crypto";
import Breach from "../models/breach.model.js";
import { audit } from "../events/auditLog.events.js";
import { maskObject } from "../utility/piiMask.js";
import {
  BREACH_FIRST_REPORT_HOURS,
  BREACH_DETAILED_REPORT_HOURS,
  getDpoContact,
  getBoardComplaintInfo,
} from "../config/dpdp.config.js";

const HOUR = 60 * 60 * 1000;

/** Heuristic severity from the s. 2(u) impact flags, scope and children. */
export const classifySeverity = ({ impact = {}, affectedCount = 0, involvesChildren = false }) => {
  if (involvesChildren) return "critical";
  const flags = ["confidentiality", "integrity", "availability"].filter(
    (k) => impact[k]
  ).length;
  if (flags >= 2 || affectedCount > 1000) return "critical";
  if (flags === 1 && affectedCount > 100) return "high";
  if (flags >= 1) return "medium";
  return "low";
};

/**
 * Open a breach incident. `occurredAt` / `detectedAt` default sensibly.
 * The reported data must already be non-identifying (counts, categories).
 */
export const openIncident = async ({ input, actor = "system" }) => {
  const detectedAt = input.detectedAt ? new Date(input.detectedAt) : new Date();
  const severity =
    input.severity ||
    classifySeverity({
      impact: input.impact || {},
      affectedCount: input.affectedCount || 0,
      involvesChildren: input.involvesChildren || false,
    });

  const incident = await Breach.create({
    title: input.title,
    description: input.description,
    impact: input.impact || {},
    severity,
    nature: input.nature || null,
    extent: input.extent || null,
    location: input.location || null,
    likely_impact: input.likely_impact || null,
    data_categories: input.dataCategories || [],
    affected_count: input.affectedCount || 0,
    affected_user_refs: input.affectedUserRefs || [],
    involves_children: input.involvesChildren || false,
    cause: input.cause || null,
    occurred_at: input.occurredAt ? new Date(input.occurredAt) : null,
    detected_at: detectedAt,
    incident_commander: input.incidentCommander || actor,
    dpo_notified_at: new Date(),
    board_first_report_due_at: new Date(detectedAt.getTime() + BREACH_FIRST_REPORT_HOURS * HOUR),
    board_detailed_report_due_at: new Date(
      detectedAt.getTime() + BREACH_DETAILED_REPORT_HOURS * HOUR
    ),
    timeline: [
      {
        at: new Date(),
        actor,
        event: "INCIDENT_OPENED",
        note: `severity=${severity}`,
      },
    ],
  });

  audit({
    action: "BREACH_OPENED",
    category: "breach",
    targetType: "Breach",
    targetId: incident.incident_id,
    status: "SUCCESS",
    details: `severity=${severity} affected=${incident.affected_count} children=${incident.involves_children}`,
  });

  return incident;
};

const humanReport = (incident) =>
  [
    `INCIDENT ${incident.incident_id} — ${incident.title}`,
    `Severity: ${incident.severity}`,
    `Detected: ${incident.detected_at?.toISOString?.() || incident.detected_at}`,
    `Occurred: ${incident.occurred_at?.toISOString?.() || incident.occurred_at || "unknown"}`,
    `Nature: ${incident.nature || "-"}`,
    `Extent: ${incident.extent || "-"} (affected: ${incident.affected_count})`,
    `Location: ${incident.location || "-"}`,
    `Impact: ${JSON.stringify(incident.impact)}`,
    `Likely impact: ${incident.likely_impact || "-"}`,
    `Involves children: ${incident.involves_children ? "YES (s. 9 — heightened urgency)" : "no"}`,
    `Mitigation: ${(incident.mitigation_steps || []).join("; ") || "-"}`,
    `Remedial: ${(incident.remedial_measures || []).join("; ") || "-"}`,
  ].join("\n");

/**
 * Build the structured incident report (JSON + human-readable) with Rule 7
 * fields and evidence hashes.
 */
export const buildIncidentReport = async (incidentId) => {
  const incident = await Breach.findOne({ incident_id: incidentId }).lean();
  if (!incident) throw new ApiError(404, "Incident not found");

  // Never include raw PII — affected subjects are only ever pseudonymous refs.
  const safe = maskObject({
    ...incident,
    affected_user_refs: undefined,
  });

  const evidence_hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(safe))
    .digest("hex");

  return {
    json: safe,
    human: humanReport(incident),
    evidence_hash,
    generated_at: new Date().toISOString(),
  };
};

/** Draft the Board "without delay" first report (Rule 7(2)(a)). */
export const buildBoardFirstReportDraft = async (incidentId) => {
  const incident = await Breach.findOne({ incident_id: incidentId }).lean();
  if (!incident) throw new ApiError(404, "Incident not found");
  const board = getBoardComplaintInfo();
  const dpo = getDpoContact();
  return {
    to: board.name,
    subject: `Personal data breach notification — ${incident.incident_id}`,
    reference: incident.incident_id,
    filed_by: dpo.name,
    body: [
      `Description: ${incident.description}`,
      `Nature: ${incident.nature || "-"}`,
      `Extent: ${incident.extent || "-"} (affected: ${incident.affected_count})`,
      `Timing: occurred ${incident.occurred_at?.toISOString?.() || "unknown"}; detected ${incident.detected_at?.toISOString?.()}`,
      `Location: ${incident.location || "-"}`,
      `Likely impact: ${incident.likely_impact || "-"}`,
    ].join("\n"),
    due_at: incident.board_first_report_due_at,
  };
};

/** Draft the Board detailed report (Rule 7(2)(b), within 72 hours). */
export const buildBoardDetailedReportDraft = async (incidentId) => {
  const incident = await Breach.findOne({ incident_id: incidentId }).lean();
  if (!incident) throw new ApiError(404, "Incident not found");
  const board = getBoardComplaintInfo();
  const dpo = getDpoContact();
  return {
    to: board.name,
    subject: `Detailed breach report (72h) — ${incident.incident_id}`,
    reference: incident.incident_id,
    filed_by: dpo.name,
    body: [
      `Updated facts & causes: ${incident.cause || "-"}`,
      `Mitigation steps: ${(incident.mitigation_steps || []).join("; ") || "-"}`,
      `Perpetrator findings: ${incident.perpetrator_findings || "-"}`,
      `Remedial measures: ${(incident.remedial_measures || []).join("; ") || "-"}`,
      `Data Principal intimations: ${
        incident.data_principals_notified_at
          ? `sent at ${incident.data_principals_notified_at.toISOString()}`
          : "pending"
      }`,
    ].join("\n"),
    due_at: incident.board_detailed_report_due_at,
  };
};

/**
 * Draft the per-Data-Principal notification (Rule 7(1)) — nature/extent/timing,
 * likely consequences, mitigation taken, safety measures the DP can take, and
 * a contact person. Plain language; localise before sending where needed.
 */
export const buildDataPrincipalNoticeDraft = async (incidentId) => {
  const incident = await Breach.findOne({ incident_id: incidentId }).lean();
  if (!incident) throw new ApiError(404, "Incident not found");
  const dpo = getDpoContact();
  const contact = `${dpo.name}${dpo.email ? ` <${dpo.email}>` : ""}`;
  return {
    subject: `Important security notice regarding your data (${incident.incident_id})`,
    body:
      `What happened: ${incident.nature || incident.description}\n` +
      `When: ${incident.occurred_at?.toISOString?.() || "recently"}\n` +
      `What data was involved: ${(incident.data_categories || []).join(", ") || "your account data"}\n` +
      `Likely consequences: ${incident.likely_impact || "Please review your account for unusual activity."}\n` +
      `What we have done: ${(incident.mitigation_steps || []).join("; ") || "We contained the incident promptly."}\n` +
      `What you can do: change your password, enable two-factor authentication, and be alert to phishing.\n` +
      `Contact for queries: ${contact}\n`,
    contact,
    rule: "Rule 7(1)",
  };
};

/** Record a timeline event on the incident (append-only). */
export const addTimelineEvent = async ({ incidentId, actor, event, note }) => {
  return Breach.findOneAndUpdate(
    { incident_id: incidentId },
    { $push: { timeline: { at: new Date(), actor, event, note } } },
    { new: true }
  );
};

/**
 * 72-hour countdown status for escalation dashboards. Returns hours remaining
 * (negative = overdue) for both the first and detailed reports.
 */
export const breachCountdown = async (incidentId) => {
  const incident = await Breach.findOne({ incident_id: incidentId }).lean();
  if (!incident) throw new ApiError(404, "Incident not found");
  const now = Date.now();
  const hoursLeft = (d) =>
    d ? Math.round(((new Date(d).getTime() - now) / HOUR) * 10) / 10 : null;
  return {
    incident_id: incident.incident_id,
    severity: incident.severity,
    status: incident.status,
    first_report_due_at: incident.board_first_report_due_at,
    first_report_hours_left: hoursLeft(incident.board_first_report_due_at),
    first_report_overdue: Boolean(
      incident.board_first_report_due_at &&
        !incident.board_first_reported_at &&
        new Date(incident.board_first_report_due_at).getTime() < now
    ),
    detailed_report_due_at: incident.board_detailed_report_due_at,
    detailed_report_hours_left: hoursLeft(incident.board_detailed_report_due_at),
    detailed_report_overdue: Boolean(
      incident.board_detailed_report_due_at &&
        !incident.board_detailed_reported_at &&
        new Date(incident.board_detailed_report_due_at).getTime() < now
    ),
    extension_granted: incident.board_extension_granted,
  };
};
