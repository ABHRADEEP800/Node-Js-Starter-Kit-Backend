// ===========================================================
// 🍪 COOKIE CONSENT CONTROLLER — Domain 8 (ss. 4, 5, 6; Rule 3)
// ===========================================================
// Public surfaces (a visitor can decide before signing in). A pseudonymous
// subject token is issued as a first-party cookie so an anonymous visitor's
// choice is stable across pages and sessions.

import crypto from "crypto";
import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import ApiResponse from "../utility/ApiResponse.js";
import {
  NOTICE_VERSION,
  DPDP_LEGAL_VERSION,
  getDpoContact,
  getBoardComplaintInfo,
  cookieCategoryIds,
} from "../config/dpdp.config.js";
import {
  recordCookieConsent,
  getCookiePreferences,
  resolveDispatch,
  withdrawCookieConsent,
  cookieCategoryRegistry,
} from "../services/cookie.service.js";
import { isProd } from "../middlewares/csrf.middleware.js";

const SUBJECT_COOKIE = "dpdp_subject";

/**
 * Resolve (or mint) the pseudonymous subject token for this request, and
 * ensure the cookie is set. Never stores raw PII in the token.
 */
const ensureSubjectToken = (req, res) => {
  let token = req.cookies[SUBJECT_COOKIE];
  if (!token) {
    token = crypto.randomBytes(18).toString("hex");
    res.cookie(SUBJECT_COOKIE, token, {
      httpOnly: false, // the client consent gate needs to read the token id
      secure: isProd(),
      sameSite: "lax",
      path: "/",
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });
  } else {
    // Refresh expiry on activity.
    res.cookie(SUBJECT_COOKIE, token, {
      httpOnly: false,
      secure: isProd(),
      sameSite: "lax",
      path: "/",
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });
  }
  return token;
};

/** Compute child/unknown-age status for signed-in users; unknown for guests. */
const ageContext = async (req) => {
  if (!req.user) return { isChild: false, ageUnknown: true }; // guest ⇒ safe default
  if (req.user.isChild) return { isChild: true, ageUnknown: true };
  if (!req.user.dateOfBirth) return { isChild: false, ageUnknown: true };
  return { isChild: false, ageUnknown: false };
};

// GET /api/v1/privacy/cookies — registry + current prefs + dispatch (public)
const getCookieState = requestHandler(async (req, res) => {
  const subjectToken = ensureSubjectToken(req, res);
  const { isChild, ageUnknown } = await ageContext(req);
  const userId = req.user?._id || null;

  const [{ preferences, action, notice_version, ageAssured }, dispatch] = await Promise.all([
    getCookiePreferences({ subjectToken, userId }),
    resolveDispatch({ subjectToken, userId, isChild, ageUnknown }),
  ]);

  return res.status(200).json(
    new ApiResponse(200, "Cookie consent state", {
      notice_version: notice_version || NOTICE_VERSION,
      legal_version: DPDP_LEGAL_VERSION,
      subject_token: subjectToken,
      categories: cookieCategoryRegistry(),
      preferences,
      last_action: action,
      // Echo the persisted adult age-assurance so the banner renders it checked
      // and does not silently drop the user back to functional-only.
      age_assured: ageAssured === true,
      // The consent gate MUST load only these categories.
      dispatch: dispatch.categories,
      child_or_unknown_age: isChild || ageUnknown,
      dpo: getDpoContact(),
      board: getBoardComplaintInfo(),
      // s. 5(3): English or any Eighth-Schedule language.
      available_languages_note: "Use ?language= to request the notice in another Eighth-Schedule language.",
    })
  );
});

// POST /api/v1/privacy/cookies/consent — record a decision (public)
const postCookieConsent = requestHandler(async (req, res) => {
  const subjectToken = ensureSubjectToken(req, res);
  const { action, categories, language, ageAssurance } = req.body;

  if (!["accept_all", "reject_all", "custom"].includes(action))
    throw new ApiError(400, "action must be accept_all, reject_all or custom");

  // A confirmed child can only ever hold functional consent (s. 9(3)); parental
  // consent does NOT unlock tracking of children. `ageAssurance` is the Fourth
  // Schedule permitted purpose of "confirming that the DP is not a child": an
  // affirmative adult assertion clears `ageUnknown` so an adult may consent.
  const { isChild, ageUnknown } = await ageContext(req);
  const effectiveIntendedAdult = ageAssurance === true && !isChild;
  const functionalOnly = isChild || (ageUnknown && !effectiveIntendedAdult);

  // For a child / unknown age we strip only the TRACKING categories
  // (analytics/advertising/personalisation/social_media — s. 9(3)). The
  // functional, captcha (security) and consent-evidence categories remain
  // user-toggleable: captcha is not behavioural tracking, so a visitor can
  // still refuse it and the auth pages will re-ask.
  const TRACKING = new Set(["analytics", "advertising", "personalisation", "social_media"]);
  const safeCategories = { ...(categories || {}) };
  if (functionalOnly) {
    for (const id of Object.keys(safeCategories)) {
      if (TRACKING.has(id)) safeCategories[id] = false;
    }
  }

  const doc = await recordCookieConsent({
    subjectToken,
    userId: req.user?._id || null,
    action,
    categories: safeCategories,
    req,
    language: language || "en",
    // Persist the adult assertion so the dispatch survives later GET re-resolves.
    ageAssured: effectiveIntendedAdult,
  });

  const dispatch = await resolveDispatch({
    subjectToken,
    userId: req.user?._id || null,
    isChild,
    ageUnknown: ageUnknown && !effectiveIntendedAdult,
  });

  return res.status(201).json(
    new ApiResponse(201, "Cookie consent recorded", {
      consent_id: doc._id,
      evidence_hash: doc.evidence_hash,
      notice_version: doc.notice_version,
      categories: doc.categories,
      dispatch: dispatch.categories,
      functional_only: functionalOnly,
    })
  );
});

// POST /api/v1/privacy/cookies/withdraw — equal ease (s. 6(4))
const withdrawCookie = requestHandler(async (req, res) => {
  const subjectToken = ensureSubjectToken(req, res);
  const { category, language } = req.body;

  if (category && category !== "all" && !cookieCategoryIds().includes(category))
    throw new ApiError(400, "Unknown cookie category");

  // Withdrawing the audit category would erase the proof of the decision
  // itself; only non-functional tracking may be withdrawn.
  if (category === "consent_audit")
    throw new ApiError(400, "The consent-evidence category cannot be withdrawn separately");

  await withdrawCookieConsent({
    subjectToken,
    userId: req.user?._id || null,
    category,
    req,
    language: language || "en",
  });

  const dispatch = await resolveDispatch({
    subjectToken,
    userId: req.user?._id || null,
    isChild: req.user?.isChild || false,
    ageUnknown: !req.user || !req.user.dateOfBirth,
  });

  return res.status(200).json(
    new ApiResponse(200, "Cookie consent withdrawn. Tracking for that category has stopped.", {
      dispatch: dispatch.categories,
    })
  );
});

export { getCookieState, postCookieConsent, withdrawCookie };
