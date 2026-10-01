// ===========================================================
// 🍪 COOKIE / TRACKER CONSENT SERVICE — Domain 8
// ===========================================================
// Implements the consent-dispatch contract:
//   child / unknown age        → strictly_functional only (s. 9(3))
//   no consent yet             → strictly_functional only (never pre-set)
//   accept_all                 → all categories
//   reject_all                 → strictly_functional only
//   custom / withdrawn         → strictly_functional + the granted categories
//
// Non-consented categories must never fire; the client consent gate consumes
// `resolveDispatch()` and must not load a tag outside the returned set.

import ApiError from "../utility/ApiError.js";
import crypto from "crypto";
import CookieConsent, {
  computeCookieEvidenceHash,
} from "../models/cookieConsent.model.js";
import { audit } from "../events/auditLog.events.js";
import { hashIdentifier, maskPII } from "../utility/piiMask.js";
import { tokenize } from "../utility/cryptoVault.js";
import { resolveClientIp } from "../utility/clientIp.js";
import {
  NOTICE_VERSION,
  DPDP_LEGAL_VERSION,
  COOKIE_CATEGORIES,
  defaultCookiePreferences,
  cookieCategoryIds,
} from "../config/dpdp.config.js";

const NON_FUNCTIONAL = cookieCategoryIds().filter((c) => c !== "strictly_functional");

/** Salted hash + optional truncated form of an IP (never store raw by default). */
export const hashIp = (ip) => {
  if (!ip) return { ipHash: null, ipTruncated: null };
  const value = String(ip).trim();
  const ipHash = crypto
    .createHmac("sha256", process.env.DPDP_TOKEN_SECRET || process.env.ACCESS_TOKEN_SECRET || "dpdp-ip")
    .update(value)
    .digest("hex")
    .slice(0, 32);
  // Truncate IPv4 to /24; keep it coarse for v6.
  let ipTruncated = null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    ipTruncated = value.split(".").slice(0, 3).join(".") + ".0/24";
  } else if (value.includes(":")) {
    ipTruncated = value.split(":").slice(0, 4).join(":") + "::/64";
  }
  return { ipHash, ipTruncated };
};

/** Deterministic subject token — the same visitor maps to the same token. */
export const subjectTokenFor = ({ userId, deviceId, ip }) =>
  tokenize(String(userId || deviceId || ip || "anon"), "cookie-subject");

/**
 * Record a cookie-consent decision (append-only). `categories` is normalised
 * so non-functional categories can never be pre-set true by a malformed input.
 */
export const recordCookieConsent = async ({
  subjectToken,
  userId = null,
  action,
  categories = {},
  req,
  language = "en",
  channel = "web",
  withdrawalOf = null,
  ageAssured = false,
}) => {
  // `strictly_functional` and `consent_audit` are non-optional: the first is
  // needed for the site to work, the second holds the proof of the decision
  // (s. 6(10)). They are never disabled by a reject/custom choice.
  const ALWAYS_ON = new Set(["strictly_functional", "consent_audit"]);
  const prefs = defaultCookiePreferences(false);
  for (const id of cookieCategoryIds()) {
    if (typeof categories[id] === "boolean") {
      prefs[id] = ALWAYS_ON.has(id) ? true : categories[id];
    }
  }
  if (action === "reject_all") {
    // Turn off every NON-OPTIONAL-EXCLUDED category, keeping the two always-on.
    for (const id of NON_FUNCTIONAL) if (!ALWAYS_ON.has(id)) prefs[id] = false;
  } else if (action === "accept_all") {
    for (const id of cookieCategoryIds()) prefs[id] = true;
  }

  // Resolve the REAL client IP (bridging platform headers in Next), then store
  // only its salted hash + a truncated form — never the raw address (s. 6(1)).
  const clientIp = resolveClientIp(req);
  const { ipHash, ipTruncated } = hashIp(clientIp);
  const capturedAt = new Date();
  const base = {
    subject_token: subjectToken,
    user_id: userId,
    notice_version: NOTICE_VERSION,
    legal_version: DPDP_LEGAL_VERSION,
    language,
    channel,
    action,
    categories: prefs,
    ip_hash: ipHash,
    ip_truncated: ipTruncated,
    user_agent: req?.headers?.["user-agent"] || null,
    user_agent_hash: req?.headers?.["user-agent"]
      ? hashIdentifier(req.headers["user-agent"], "cookie-ua")
      : null,
    captured_at: capturedAt,
    withdrawal_of: withdrawalOf,
    age_assured: ageAssured === true,
  };
  const evidence_hash = computeCookieEvidenceHash(base);
  const doc = await CookieConsent.create({ ...base, evidence_hash });

  audit({
    userId: userId || undefined,
    action: `COOKIE_CONSENT_${action.toUpperCase()}`,
    category: "consent",
    purposeId: "consent_audit",
    lawfulBasis: "consent",
    targetType: "CookieConsent",
    targetId: String(doc._id),
    status: "SUCCESS",
    details: `action=${action} notice=${NOTICE_VERSION} ip_hash=${ipHash || "none"}`,
    // Mask, don't placeholder: a real masked IP is auditable evidence and is
    // already PII-safe. ipHash lives on the consent artefact.
    ip: clientIp ? maskPII(clientIp, "ip") : undefined,
    userAgent: null, // never log raw UA
  });

  return doc;
};

/**
 * Current effective preferences for a subject (latest event wins). Returns the
 * safe default when there is no decision yet.
 */
export const getCookiePreferences = async ({ subjectToken, userId }) => {
  // Consent is per DATA PRINCIPAL (s. 6). Once signed in, ONLY that account's
  // records are authoritative — never the browser's anonymous token, and never
  // another account's record. (An `$or` of user_id + subject_token would let a
  // second user on a shared browser inherit the first user's consent.) A fresh
  // sign-in therefore sees the safe default until it makes its own choice.
  const query = userId
    ? { user_id: userId }
    : { subject_token: subjectToken, user_id: null };
  const latest = await CookieConsent.findOne(query)
    .sort({ captured_at: -1, _id: -1 })
    .lean();
  if (!latest)
    return { preferences: defaultCookiePreferences(false), action: null, captured_at: null, ageAssured: false };
  return {
    preferences: latest.categories,
    action: latest.action,
    captured_at: latest.captured_at,
    notice_version: latest.notice_version,
    // Persisted adult age-assurance (Fourth Schedule) — makes the choice stick.
    ageAssured: latest.age_assured === true,
  };
};

/**
 * The consent-dispatch contract. Enforced at the tag/script layer on the
 * client; this is the authoritative server-side resolution.
 * @param {object} opts { subjectToken, userId, isChild, ageUnknown }
 * @returns {Promise<{ categories: string[], preferences: object, action: string|null }>}
 */
// Categories that are behavioural tracking / advertising — flatly prohibited
// for children and never enabled until age is confirmed adult (s. 9(3)).
const TRACKING_CATEGORIES = new Set([
  "analytics",
  "advertising",
  "personalisation",
  "social_media",
]);

export const resolveDispatch = async ({ subjectToken, userId, isChild = false, ageUnknown = false }) => {
  const { preferences, action, ageAssured } = await getCookiePreferences({ subjectToken, userId });

  // A CONFIRMED child / unknown-age-visitor gets functional + the captcha
  // SECURITY measure (captcha is bot protection, not behavioural tracking —
  // s. 9(3) targets tracking/ads), but NO tracking categories. The captcha
  // toggle is still honoured: if the user explicitly refused it, it stays off
  // and the auth pages re-ask.
  const trackingBlocked = isChild || (ageUnknown && !ageAssured);
  if (trackingBlocked) {
    const prefs = defaultCookiePreferences(true);
    // captcha is only dispatched after an AFFIRMATIVE choice. `!== false`
    // wrongly treated "never chosen" (undefined) as allowed and loaded Google's
    // tracker with no consent — require an explicit `true`.
    prefs.captcha = preferences.captcha === true;
    const categories = ["strictly_functional"];
    if (prefs.captcha) categories.push("captcha");
    return {
      categories,
      preferences: prefs,
      action: isChild ? "child-functional-only" : "unknown-age-functional-only",
      reason: isChild
        ? "s.9(3) — tracking prohibited for children; captcha is a security measure"
        : "s.9(3) — tracking off until the DP is confirmed not a child",
    };
  }

  const categories = ["strictly_functional"];
  for (const id of cookieCategoryIds()) {
    if (id === "strictly_functional") continue;
    // Defensive: never dispatch a tracking category for a child.
    if (isChild && TRACKING_CATEGORIES.has(id)) continue;
    if (preferences[id] === true) categories.push(id);
  }
  return { categories, preferences, action };
};

/** Withdraw a specific category (or all non-functional) — equal ease (s. 6(4)). */
export const withdrawCookieConsent = async ({ subjectToken, userId, category, req, language }) => {
  if (category === "strictly_functional")
    throw new ApiError(400, "Cannot withdraw strictly functional trackers");
  const current = await getCookiePreferences({ subjectToken, userId });
  const prefs = { ...current.preferences };
  if (!category || category === "all") {
    for (const cat of NON_FUNCTIONAL) prefs[cat] = false;
  } else {
    prefs[category] = false;
  }
  return recordCookieConsent({
    subjectToken,
    userId,
    action: "withdrawn",
    categories: prefs,
    req,
    language,
    // MUST carry the adult age-assurance forward — otherwise withdrawing one
    // category would silently reset a confirmed adult to functional-only.
    ageAssured: current.ageAssured === true,
  });
};

/** Public view of the category registry (for the banner). */
export const cookieCategoryRegistry = () => COOKIE_CATEGORIES;
