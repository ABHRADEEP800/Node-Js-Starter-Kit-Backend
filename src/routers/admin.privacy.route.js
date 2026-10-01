import express from "express";
import authMiddleware from "../middlewares/auth.middleware.js";
import validate from "../middlewares/validate.middleware.js";
import {
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
} from "../controllers/admin.privacy.controller.js";
import {
  breachCreateSchema,
  breachNotifySchema,
  transferUpsertSchema,
  dpiaUpsertSchema,
  retentionRunSchema,
  nomineeClaimDecisionSchema,
} from "../utility/schemas.js";

// Admin-only DPDP control plane. authMiddleware(["admin"]) gates the whole
// router, mirroring admin.route.js strict RBAC.
const adminPrivacyRouter = express.Router();
adminPrivacyRouter.use(authMiddleware(["admin"]));

// Rights SLA dashboard (Rule 14)
adminPrivacyRouter.route("/rights").get(rightsDashboard);
// Rights & grievance inbox (ss. 11–14) — list, read, and update cases.
adminPrivacyRouter.route("/rights/cases").get(listRightsCases);
adminPrivacyRouter
  .route("/rights/cases/:case_id")
  .patch(updateRightsCase);

// Nominee claims (s. 14) — review, approve/reject, inspect a DP's nominees.
adminPrivacyRouter.route("/nominee-claims").get(listNomineeClaims);
adminPrivacyRouter
  .route("/nominee-claims/:claimId/decide")
  .post(validate(nomineeClaimDecisionSchema), decideNomineeClaim);
adminPrivacyRouter.route("/nominees/:userId").get(adminGetNominees);

// Breach workflow (s. 8(6), Rule 7)
adminPrivacyRouter.route("/breaches").get(listIncidents);
adminPrivacyRouter
  .route("/breaches")
  .post(validate(breachCreateSchema), createIncident);
adminPrivacyRouter.route("/breaches/:incidentId/report").get(getIncidentReport);
adminPrivacyRouter.route("/breaches/:incidentId/drafts").get(getIncidentDrafts);
adminPrivacyRouter
  .route("/breaches/:incidentId/notify")
  .post(validate(breachNotifySchema), markIncidentNotified);

// Retention / erasure (s. 8(7)/(8), Rule 8) — dry-run by default.
adminPrivacyRouter
  .route("/retention/run")
  .post(validate(retentionRunSchema), runRetention);

// Cross-border transfer register (s. 16, Rule 15)
adminPrivacyRouter.route("/transfers").get(listTransfers);
adminPrivacyRouter
  .route("/transfers")
  .post(validate(transferUpsertSchema), upsertTransfer);

// DPIA / SDF register (s. 10, Rule 13)
adminPrivacyRouter.route("/dpia").get(listDpias);
adminPrivacyRouter.route("/dpia").post(validate(dpiaUpsertSchema), upsertDpia);

// Audit integrity (Rule 6(c))
adminPrivacyRouter.route("/audit/verify").get(auditIntegrity);
adminPrivacyRouter.route("/audit").get(listAudit);

export default adminPrivacyRouter;
