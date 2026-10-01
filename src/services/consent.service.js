// ===========================================================
// ✅ CONSENT SERVICE — s. 6, s. 6(10), s. 8(7)
// ===========================================================
// Records append-only consent artefacts, computes the current effective
// consent state per purpose, and handles withdrawal (which halts processing
// and triggers erasure under s. 8(7)).

import ApiError from "../utility/ApiError.js";
import Consent, { computeConsentEvidenceHash } from "../models/consent.model.js";
import User from "../models/user.model.js";
import { audit } from "../events/auditLog.events.js";
import { hashIdentifier, maskPII } from "../utility/piiMask.js";
import { tokenize } from "../utility/cryptoVault.js";
import { resolveClientIp } from "../utility/clientIp.js";
import {
  NOTICE_VERSION,
  DPDP_LEGAL_VERSION,
  isValidPurpose,
  requiredPurposes,
  optionalPurposes,
} from "../config/dpdp.config.js";

const hashContext = (value) =>
  value ? hashIdentifier(value, "consent-ctx") : null;

/**
 * Record a consent event (granted / withdrawn / denied) for a set of purposes.
 * Append-only: never updates prior artefacts (s. 6(10)).
 *
 * @param {object} opts
 * @param {string} opts.userId
 * @param {string[]} opts.purposes
 * @param {"granted"|"withdrawn"|"denied"} opts.action
 * @param {object} opts.req express request (for hashed context)
 * @param {string} [opts.channel]
 * @param {string} [opts.language]
 * @param {string} [opts.consentManagerRef]
 */
export const recordConsent = async ({
  userId,
  purposes,
  action,
  req,
  channel = "web",
  language = "en",
  consentManagerRef = null,
}) => {
  const clean = (purposes || []).filter(isValidPurpose);
  if (clean.length === 0) throw new ApiError(400, "No valid purposes supplied");

  const dataPrincipalRef = tokenize(String(userId), "dp");
  const capturedAt = new Date();

  // Resolve the real client IP (bridging platform headers in Next) and store
  // only its salted hash. Never the raw address (s. 6(1), Rule 6(a)).
  const clientIp = resolveClientIp(req);

  const base = {
    user_id: userId,
    data_principal_ref: dataPrincipalRef,
    notice_version: NOTICE_VERSION,
    legal_version: DPDP_LEGAL_VERSION,
    language,
    purposes: clean,
    lawful_basis: "consent:6(1)",
    action,
    captured_at: capturedAt,
    channel,
    ip_hash: hashContext(clientIp),
    user_agent_hash: hashContext(req?.headers?.["user-agent"]),
    consent_manager_ref: consentManagerRef,
  };
  const evidence_hash = computeConsentEvidenceHash(base);

  const artefact = await Consent.create({ ...base, evidence_hash });

  audit({
    userId,
    action: `CONSENT_${action.toUpperCase()}`,
    category: "consent",
    purposeId: clean.join(","),
    lawfulBasis: "consent:6(1)",
    targetType: "Consent",
    targetId: String(artefact._id),
    status: "SUCCESS",
    // Masked real IP (auditable, PII-safe) — never a placeholder or raw value.
    ip: clientIp ? maskPII(clientIp, "ip") : undefined,
    userAgent: null, // never log the raw user-agent
    details: `notice=${NOTICE_VERSION} lang=${language}`,
  });

  return artefact;
};

/**
 * Compute the effective consent state for a user: for each registered purpose,
 * whether the LAST event for it was a grant.
 * @returns {Promise<Record<string, boolean>>}
 */
export const getConsentState = async (userId) => {
  const events = await Consent.find({ user_id: userId })
    .sort({ captured_at: 1, _id: 1 })
    .lean();

  const state = {};
  for (const ev of events) {
    for (const p of ev.purposes || []) {
      state[p] = ev.action === "granted";
    }
  }
  return state;
};

/** Convenience: is a specific purpose currently consented? */
export const hasConsent = async (userId, purposeId) =>
  (await getConsentState(userId))[purposeId] === true;

/**
 * Withdraw consent for one purpose (or "all") with ease equal to granting it
 * (s. 6(4)). Records the withdrawal event and marks the account for the
 * erasure pipeline when the core `account` purpose is withdrawn (s. 8(7)).
 */
export const withdrawConsent = async ({ userId, purposeId, req, language = "en" }) => {
  const current = await getConsentState(userId);

  let purposes;
  if (!purposeId || purposeId === "all") {
    // Withdraw only what is ACTUALLY granted. Previously an empty consent state
    // fell back to the full required list (incl. `account`), so "withdraw all"
    // on a fresh account silently scheduled erasure. If nothing is granted,
    // there is nothing to withdraw.
    purposes = Object.keys(current).filter((p) => current[p]);
    if (purposes.length === 0) {
      return { consent_id: null, purposes: [], withdrawn: false };
    }
  } else {
    if (!isValidPurpose(purposeId)) throw new ApiError(400, "Unknown purpose");
    purposes = [purposeId];
  }

  const artefact = await recordConsent({
    userId,
    purposes,
    action: "withdrawn",
    req,
    language,
  });

  // Withdrawing the core `account` purpose means we can no longer provide the
  // service: halt processing and schedule erasure (s. 8(7)).
  if (purposes.includes("account")) {
    await User.findByIdAndUpdate(userId, {
      accountStatus: "erasure_pending",
      deletionRequestedAt: new Date(),
      telemetryDisabled: true,
    });
    audit({
      userId,
      action: "ERASURE_SCHEDULED",
      category: "erasure",
      purposeId: "account",
      lawfulBasis: "s.8(7)",
      status: "SUCCESS",
      details: "Consent withdrawal for account purpose → erasure pipeline",
      ip: req?.ip,
      userAgent: req?.headers?.["user-agent"],
    });
  }

  return artefact;
};

/**
 * Record the signup consent bundle. Required purposes are always recorded;
 * optional purposes only when explicitly granted (opt-in, no pre-ticked).
 * Idempotent-ish: a user consenting twice just gets two artefacts.
 */
export const recordSignupConsents = async ({ userId, optionalGranted = [], req, language = "en" }) => {
  const required = requiredPurposes().map((p) => p.id);
  // Only OPTIONAL purposes that were explicitly opted into get their own
  // artefact. `account` already lives in the required set, so it is never
  // duplicated here (previously this created a redundant account-only doc).
  const opted = optionalGranted.filter(
    (p) => isValidPurpose(p) && !required.includes(p)
  );

  const artefacts = [];
  artefacts.push(
    await recordConsent({ userId, purposes: required, action: "granted", req, language })
  );
  if (opted.length) {
    artefacts.push(
      await recordConsent({ userId, purposes: opted, action: "granted", req, language })
    );
  }

  // Level of telemetry follows the analytics opt-in; children always have
  // telemetry disabled (s. 9(3)).
  const user = await User.findById(userId);
  if (user && !user.isChild) {
    user.telemetryDisabled = !opted.includes("analytics");
    await user.save({ validateBeforeSave: false });
  }

  return artefacts;
};

/** Purposes a user has NOT yet decided on (for the Privacy Center UI). */
export const undecidedOptionalPurposes = async (userId) => {
  const state = await getConsentState(userId);
  return optionalPurposes()
    .map((p) => p.id)
    .filter((id) => state[id] === undefined);
};
