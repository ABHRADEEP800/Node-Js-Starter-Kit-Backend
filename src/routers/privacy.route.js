import express from "express";
import authMiddleware from "../middlewares/auth.middleware.js";
import validate from "../middlewares/validate.middleware.js";
import rateLimit from "express-rate-limit";
import { baseRateLimitOptions } from "../config/rateLimit.config.js";
import {
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
} from "../controllers/privacy.controller.js";
import {
  grantConsentSchema,
  withdrawConsentSchema,
  correctionSchema,
  grievanceSchema,
  nominationSchema,
  nomineesReplaceSchema,
  nomineeEditSchema,
  nomineeClaimSchema,
  guardianConsentSchema,
  escalateGrievanceSchema,
} from "../utility/schemas.js";

const privacyRouter = express.Router();

// Conservative limits on rights endpoints (anti-abuse, not anti-rights).
const rightsLimiter = rateLimit({ ...baseRateLimitOptions, windowMs: 15 * 60 * 1000, max: 30 });
const noticeLimiter = rateLimit({ ...baseRateLimitOptions, windowMs: 15 * 60 * 1000, max: 120 });

// ---- Public notice (s. 5, Rule 3) ----
privacyRouter.route("/notice").get(noticeLimiter, getNotice);
// s. 5(2) — migration notice for pre-commencement consent.
privacyRouter.route("/notice/legacy").get(noticeLimiter, getLegacyNotice);
privacyRouter.route("/purposes").get(noticeLimiter, getPurposes);

// ---- Consent (s. 6) ----
privacyRouter.route("/consent").get(authMiddleware(), getMyConsent);
privacyRouter
  .route("/consent/grant")
  .post(authMiddleware(), rightsLimiter, validate(grantConsentSchema), grantConsent);
privacyRouter
  .route("/consent/withdraw")
  .post(authMiddleware(), rightsLimiter, validate(withdrawConsentSchema), withdrawMyConsent);

// ---- Rights (ss. 11–14) ----
privacyRouter.route("/data").get(authMiddleware(), rightsLimiter, getMyData);
privacyRouter
  .route("/correct")
  .post(authMiddleware(), rightsLimiter, validate(correctionSchema), correctMyData);
privacyRouter
  .route("/erase")
  .post(authMiddleware(), rightsLimiter, eraseMyData);
privacyRouter
  .route("/grievance")
  .post(authMiddleware(), rightsLimiter, validate(grievanceSchema), raiseGrievance);
privacyRouter
  .route("/grievance/escalate")
  .post(authMiddleware(), rightsLimiter, validate(escalateGrievanceSchema), escalateGrievance);
privacyRouter
  .route("/nominate")
  .post(authMiddleware(), rightsLimiter, validate(nominationSchema), nominate);
// s. 14 — full nominee management (list / replace / edit / remove).
privacyRouter.route("/nominees").get(authMiddleware(), listMyNominees);
privacyRouter
  .route("/nominees")
  .put(authMiddleware(), rightsLimiter, validate(nomineesReplaceSchema), setMyNominees);
privacyRouter
  .route("/nominees/:index")
  .patch(authMiddleware(), rightsLimiter, validate(nomineeEditSchema), editMyNominee)
  .delete(authMiddleware(), rightsLimiter, removeMyNominee);
privacyRouter.route("/cases").get(authMiddleware(), listMyCases);

// s. 14 — PUBLIC: a nominee submits a death/incapacity claim.
privacyRouter
  .route("/nominee-claim")
  .post(rightsLimiter, validate(nomineeClaimSchema), submitNomineeClaim);

// ---- Children / guardian (s. 9, Rule 10/11) ----
privacyRouter.route("/age-status").get(authMiddleware(), ageStatus);
privacyRouter
  .route("/guardian-consent")
  .post(authMiddleware(), rightsLimiter, validate(guardianConsentSchema), submitGuardianConsent);

// ---- Security: self-service audit-chain integrity proof (Rule 6(c)) ----
privacyRouter.route("/audit/verify").get(authMiddleware(), rightsLimiter, verifyAuditIntegrity);

export default privacyRouter;
