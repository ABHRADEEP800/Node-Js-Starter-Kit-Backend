// ===========================================================
// 🔒 PURPOSE GUARD — purpose isolation at the access layer
// ===========================================================
// Domain 3 (s. 4, s. 6(1)): a process acting under purpose A must not reach a
// record tagged purpose B. This is enforced in the data-access path, not the
// UI. `requirePurpose(purposeId)` denies (403) and audit-logs any attempt to
// read/act under a purpose the caller has not consented to or is not licensed
// for. Children's optional processing is blocked unless a valid guardian
// consent exists (s. 9).

import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import { audit } from "../events/auditLog.events.js";
import { getPurpose, isValidPurpose } from "../config/dpdp.config.js";
import { getConsentState } from "../services/consent.service.js";
import { hasValidGuardianConsent } from "../services/age.service.js";

/**
 * @param {string} purposeId registered purpose this route processes data for.
 */
const requirePurpose = (purposeId) =>
  requestHandler(async (req, res, next) => {
    if (!req.user) throw new ApiError(401, "Unauthorized request");

    if (!isValidPurpose(purposeId)) {
      throw new ApiError(
        500,
        `Misconfigured purpose '${purposeId}' — register it in dpdp.config.js`
      );
    }

    const purpose = getPurpose(purposeId);

    // Children: optional processing requires verifiable guardian consent.
    if (req.user.isChild && !purpose.required) {
      const ok = await hasValidGuardianConsent(req.user._id);
      if (!ok) {
        audit({
          userId: req.user._id,
          action: "PURPOSE_DENIED",
          category: "security",
          purposeId,
          lawfulBasis: "s.9",
          status: "FAILED",
          details: "Child without valid guardian consent",
          ip: req.ip,
        });
        throw new ApiError(
          403,
          "Parental/guardian consent is required for this processing (s. 9)."
        );
      }
    }

    // Consent-based purposes require an active grant (s. 4, s. 6).
    if (purpose.lawful_basis === "consent") {
      const state = await getConsentState(req.user._id);
      if (state[purposeId] !== true) {
        audit({
          userId: req.user._id,
          action: "PURPOSE_DENIED",
          category: "security",
          purposeId,
          lawfulBasis: "s.4",
          status: "FAILED",
          details: "No active consent for purpose",
          ip: req.ip,
        });
        throw new ApiError(
          403,
          `No lawful basis to process for purpose '${purposeId}'. Consent is required (s. 4).`
        );
      }
    } else {
      // s. 7 legitimate use — log the EXACT clause tag so the exemption is
      // auditable (s. 17 / s. 7). Never inferred from "legitimate interest".
      audit({
        userId: req.user._id,
        action: "LEGITIMATE_USE_INVOKED",
        category: "security",
        purposeId,
        lawfulBasis: purpose.lawful_basis, // e.g. "s7(a)"
        status: "SUCCESS",
        details: `legitimate use ${purpose.lawful_basis} for purpose '${purposeId}'`,
        ip: req.ip,
      });
    }

    req.activePurpose = purposeId;
    req.lawfulBasis = purpose.lawful_basis;
    next();
  });

export default requirePurpose;
