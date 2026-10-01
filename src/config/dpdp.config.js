// ===========================================================
// 🇮🇳 DPDP CONFIG — Digital Personal Data Protection Act, 2023
//   + Digital Personal Data Protection Rules, 2025 (G.S.R. 846(E))
// ===========================================================
// Single source of truth for lawful purposes, notice content, retention,
// rights SLAs, cookie categories and breach deadlines. Every processing
// activity in this server MUST reference a `purpose_id` declared here
// (s. 4, s. 5(ii), Rule 3).
//
// Legal version relied upon (verify against the Gazette — see §12 of the
// skill): Act No. 22 of 2023 (assented 11 Aug 2023); DPDP Rules 2025,
// G.S.R. 846(E), notified 13/14 Nov 2025; corrigenda G.S.R. 892(E).

export const DPDP_ACT_VERSION = "Act 22 of 2023";
export const DPDP_RULES_VERSION = "G.S.R. 846(E) (2025)";
export const DPDP_LEGAL_VERSION = `DPDP ${DPDP_ACT_VERSION} + Rules ${DPDP_RULES_VERSION}`;

// Bump this whenever the notice text or purpose set changes materially. Every
// consent artefact stores the notice version it was captured against (s. 5,
// s. 6(10)) so we can prove what the Data Principal actually agreed to.
export const NOTICE_VERSION = "2026.2";

// s. 5(2): legacy consent given before commencement must be covered by a
// migration notice served "as soon as reasonably practicable"; processing may
// continue until the DP withdraws. Version the migration notice separately.
export const LEGACY_NOTICE_VERSION = "legacy-2026.1";

// s. 2(i): who is accountable. Kept here so every response can cite it.
export const DATA_FIDUCIARY_NAME = process.env.PROJECT_NAME || "Starter Kit";

// ===========================================================
// 📐 RIGHTS / BREACH / RETENTION constants
// ===========================================================
// Rule 14(3): the DF/Consent Manager must prominently publish a period for
// responding to grievances, "not exceeding ninety days", and implement measures
// to respond within it. So 90 days is the statutory CEILING. Our policy:
// target 30 days; never exceed 90.
export const RIGHTS_SLA_DAYS = 30;
export const RIGHTS_HARD_CEILING_DAYS = 90;
export const RIGHTS_RULE_REF = "Rule 14(3) — period not exceeding 90 days (target 30)";

// Breach notification — Rule 7. First report to the Board "without delay"
// (target < 24h), detailed report within 72h (extendable in writing).
export const BREACH_FIRST_REPORT_HOURS = 24;
export const BREACH_DETAILED_REPORT_HOURS = 72;

// Rule 8(3) + Seventh Schedule: retain personal data, associated traffic data
// and logs for at least 1 year from processing, then erase unless longer
// retention is legally required.
export const LOG_RETENTION_DAYS = 365;

// Rule 8(2): warn the Data Principal at least 48 hours before erasure of data
// belonging to an inactive Data Principal. The warning must tell her the data
// will be erased unless she logs in / contacts the DF / exercises rights.
export const ERASURE_WARNING_HOURS = 48;

// Rule 8(1) + Third Schedule inactivity period. The 3-year figure applies to
// e-commerce ≥2 crore users, online-gaming ≥50 lakh users and social-media
// ≥2 crore users. For a general Data Fiduciary this is configurable; default
// 3 years (1095 days).
export const INACTIVITY_ERASURE_DAYS = process.env.DPDP_INACTIVITY_DAYS
  ? parseInt(process.env.DPDP_INACTIVITY_DAYS, 10)
  : 1095;

// Third Schedule carve-out: the erasure obligation does NOT apply to
// processing that (a) enables the DP to access her user account, or (b)
// enables access to a virtual token issued by/on behalf of the DF and usable
// to get money, goods or services. We therefore NEVER schedule the
// account-access / token-access record for erasure on the inactivity clock.
export const THIRD_SCHEDULE_CARVEOUT_PURPOSES = [
  "account", // enables the DP to access her user account
  "virtual-token-access", // access to a virtual token usable for money/goods/services
];

// s. 5(3): notice must be available in English or any of the 22 languages in
// the Eighth Schedule. English is authored; the rest are exposed as options
// (fall back to English with an explicit translation_status flag).
export const EIGHTH_SCHEDULE_LANGUAGES = [
  { code: "en", label: "English" },
  { code: "hi", label: "हिन्दी (Hindi)" },
  { code: "bn", label: "বাংলা (Bengali)" },
  { code: "ta", label: "தமிழ் (Tamil)" },
  { code: "te", label: "తెలుగు (Telugu)" },
  { code: "mr", label: "मराठी (Marathi)" },
  { code: "gu", label: "ગુજરાતી (Gujarati)" },
  { code: "kn", label: "ಕನ್ನಡ (Kannada)" },
  { code: "ml", label: "മലയാളം (Malayalam)" },
  { code: "pa", label: "ਪੰਜਾਬੀ (Punjabi)" },
  { code: "or", label: "ଓଡ଼ିଆ (Odia)" },
  { code: "as", label: "অসমীয়া (Assamese)" },
  { code: "ur", label: "اردو (Urdu)" },
  { code: "sa", label: "संस्कृतम् (Sanskrit)" },
];

// ===========================================================
// 📋 PURPOSE REGISTRY (s. 4(1), s. 5(ii) — itemised, not blanket)
// ===========================================================
// `required: true`  → necessary to provide the service the user asked for.
// `required: false` → optional processing that MUST be separately opted-in
//                     and can be withdrawn without losing the service.
// `lawful_basis`    → "consent" (s. 6) or the exact s. 7 clause tag.
// `fields` documents the itemised personal data each purpose uses.
// `retention_days: null` → retained while the purpose is served / account is
//                     active, then erased (s. 8(7)).
//
// s. 7 legitimate-use tags (Gazette, exactly (a)–(i)):
//   s7(a) voluntary provision, no non-consent indicated
//   s7(b) State subsidy/benefit/service/certificate/licence/permit (Rule 5)
//   s7(c) State function under law / sovereignty / security
//   s7(d) legal obligation to disclose to the State
//   s7(e) compliance with a judgment/decree/order
//   s7(f) medical emergency (threat to life / immediate health threat)
//   s7(g) medical treatment / health services during epidemic/outbreak/health threat
//   s7(h) safety/assistance during disaster or breakdown of public order
//   s7(i) employment purposes / safeguarding employer from loss or liability
export const PURPOSES = [
  {
    id: "account",
    label: "Account & authentication",
    description:
      "Create and secure your account, sign in, verify your email address and protect the account from unauthorised access.",
    lawful_basis: "consent",
    required: true,
    retention_days: null,
    third_schedule_carveout: true,
    fields: [
      "firstName",
      "lastName",
      "username",
      "email",
      "passwordHash",
      "dateOfBirth",
    ],
  },
  {
    id: "strictly-functional",
    label: "Session, security & load-balancing cookies",
    description:
      "Strictly functional cookies needed to keep you signed in, protect against CSRF attacks, enforce security and balance traffic. There is NO 'strictly necessary' exemption under the DPDP Act, so we register this under s. 7(a) (data you voluntarily provided for the specified purpose, with no indication of non-consent).",
    lawful_basis: "s7(a)",
    required: true,
    retention_days: null,
    cookie_category: "strictly_functional",
    fields: ["sessionId", "deviceId", "csrfToken", "securityCookie"],
  },
  {
    id: "service-email",
    label: "Transactional email",
    description:
      "Send essential account emails: email verification, password resets, security alerts and breach notifications.",
    lawful_basis: "consent",
    required: true,
    retention_days: null,
    fields: ["email", "firstName", "lastName"],
  },
  {
    id: "security",
    label: "Security, audit & fraud prevention",
    description:
      "Maintain security and audit logs, detect suspicious sign-ins and prevent abuse (s. 8(5), Rule 6(c)).",
    lawful_basis: "consent",
    required: true,
    retention_days: LOG_RETENTION_DAYS,
    fields: ["ipAddress", "userAgent", "sessionMetadata", "loginHistory"],
  },
  {
    // Google reCAPTCHA. Functional/security processing: it sets Google
    // cookies and transmits a risk score while creating an account or signing
    // in. DPDP has no "strictly necessary" exemption, so this rests on s. 7(a)
    // (data you voluntarily provided for the specified purpose, no
    // non-consent indicated) — and, because the s. 7(a) basis for security
    // trackers is a genuine textual gap, the banner asks for an explicit
    // choice before the script loads and re-asks if it was refused.
    id: "captcha",
    label: "Anti-bot / reCAPTCHA (Google)",
    description:
      "Google reCAPTCHA checks that you are a real person and not a bot when you sign up, sign in or reset your password. It sets Google cookies (for example _GRECAPTCHA) and sends Google your IP address, browser signals and a risk score. Without it we cannot safely accept the form. Basis: s. 7(a) — data you voluntarily provided for this security purpose; you may refuse, but then the anti-bot form cannot be processed.",
    lawful_basis: "s7(a)",
    required: false,
    retention_days: null,
    cookie_category: "captcha",
    vendor: "Google LLC (reCAPTCHA v3)",
    vendor_policy_url: "https://policies.google.com/privacy",
    fields: ["ipAddress", "browserSignals", "riskScore", "googleCookies"],
  },
  {
    id: "consent_audit",
    label: "Consent evidence (IP & context)",
    description:
      "Record a hashed form of your IP address, browser and timestamp alongside each consent decision, so we can prove that notice was given and consent was taken (s. 6(10), burden of proof on us). This is a separate, dedicated purpose — never bundled into marketing or advertising.",
    lawful_basis: "consent",
    required: true,
    retention_days: LOG_RETENTION_DAYS,
    cookie_category: "consent_audit",
    fields: ["ipHash", "userAgent", "timestamp"],
  },
  {
    id: "twofa",
    label: "Two-factor authentication",
    description:
      "Enrol and verify a second authentication factor and store recovery backup codes.",
    lawful_basis: "consent",
    required: false,
    retention_days: null,
    fields: ["totpSecret", "backupCodes"],
  },
  {
    id: "passkey",
    label: "Passkeys (WebAuthn)",
    description:
      "Register and verify passkeys used to sign in without a password.",
    lawful_basis: "consent",
    required: false,
    retention_days: null,
    fields: ["credentialId", "publicKey", "deviceLabel"],
  },
  {
    id: "marketing",
    label: "Product updates & marketing",
    description:
      "Send optional product news, feature announcements and promotional email.",
    lawful_basis: "consent",
    required: false,
    retention_days: null,
    fields: ["email", "firstName"],
  },
  {
    id: "analytics",
    label: "Product analytics",
    description:
      "Measure feature usage in aggregate to improve the product. A separate consent from advertising; no advertising identifiers or cross-site tracking.",
    lawful_basis: "consent",
    required: false,
    retention_days: LOG_RETENTION_DAYS,
    cookie_category: "analytics",
    fields: ["usageEvents"],
  },
  {
    id: "advertising",
    label: "Advertising & retargeting",
    description:
      "Serve targeted/retargeted advertising and measure ad performance. A separate consent from analytics; never used for children.",
    lawful_basis: "consent",
    required: false,
    retention_days: null,
    cookie_category: "advertising",
    fields: ["adId", "adEvents"],
  },
  {
    id: "personalisation",
    label: "Personalisation",
    description:
      "Tailor recommendations and content to you. A separate consent; never used for children.",
    lawful_basis: "consent",
    required: false,
    retention_days: null,
    cookie_category: "personalisation",
    fields: ["preferences", "usageEvents"],
  },
  {
    id: "social_media",
    label: "Social media & third-party embeds",
    description:
      "Load third-party social widgets/embeds and share buttons. A separate consent; never used for children.",
    lawful_basis: "consent",
    required: false,
    retention_days: null,
    cookie_category: "social_media",
    fields: ["embedInteraction"],
  },
  {
    id: "children-service",
    label: "Service for children (guardian-consented)",
    description:
      "Provide the service to a user under 18 only after verifiable parental/lawful-guardian consent (s. 9, Rule 10). Tracking, behavioural monitoring and targeted advertising are disabled.",
    lawful_basis: "consent",
    required: false,
    retention_days: null,
    fields: ["firstName", "username", "guardianContact", "guardianConsentProof"],
  },
];

/** Look up a purpose by id. */
export const getPurpose = (id) => PURPOSES.find((p) => p.id === id) || null;

/** All purpose ids. */
export const purposeIds = () => PURPOSES.map((p) => p.id);

/** True when `id` is a registered purpose. */
export const isValidPurpose = (id) => purposeIds().includes(id);

/** Purposes that must be consented to at signup (core service). */
export const requiredPurposes = () => PURPOSES.filter((p) => p.required);

/** Optional purposes a user may separately opt into. */
export const optionalPurposes = () => PURPOSES.filter((p) => !p.required);

/** True when the purpose's lawful basis is a s. 7 legitimate use (not consent). */
export const isLegitimateUse = (id) => {
  const p = getPurpose(id);
  return Boolean(p && p.lawful_basis !== "consent");
};

/**
 * A record for this purpose must NEVER be erased on the inactivity clock
 * (Third Schedule carve-out: account access + virtual-token access).
 */
export const isThirdScheduleCarveout = (id) =>
  THIRD_SCHEDULE_CARVEOUT_PURPOSES.includes(id) ||
  Boolean(getPurpose(id)?.third_schedule_carveout);

// ===========================================================
// 🍪 COOKIE / TRACKER CATEGORY REGISTRY (Domain 8)
// ===========================================================
// There is NO "strictly necessary" exemption under DPDP. Each category maps
// to a registered purpose; non-essential categories default OFF.
// `consent_required: false` means the tracker may load without a choice, but
// it is still noticed and rests on s. 7(a) — not on an invented exemption.
export const COOKIE_CATEGORIES = [
  {
    id: "strictly_functional",
    label: "Strictly functional",
    description:
      "Keep you signed in, protect against CSRF, enforce security and balance traffic.",
    purpose_id: "strictly-functional",
    lawful_basis: "s7(a)",
    consent_required: false,
    // Locked-on: the site cannot function without these.
    locked: true,
    default: true,
    examples: ["session", "auth", "csrf", "security", "load-balancing", "fraud"],
  },
  {
    // Google reCAPTCHA — a functional/security tracker. Default ON (needed to
    // accept sign-up/sign-in forms) but the user MAY turn it off; if they do,
    // the auth pages re-ask with a full what/why explanation before loading.
    id: "captcha",
    label: "Anti-bot check (Google reCAPTCHA)",
    description:
      "Google reCAPTCHA confirms you are a real person, not a bot, when you sign up, sign in or reset your password. It sets Google cookies (e.g. _GRECAPTCHA) and sends Google your IP address, browser signals and a risk score. Basis: s. 7(a) — you voluntarily provided this for the security purpose. You may turn it off, but then we cannot safely accept the form.",
    purpose_id: "captcha",
    lawful_basis: "s7(a)",
    consent_required: false,
    // Toggleable (unlike strictly_functional) so the user can refuse it.
    locked: false,
    // OFF by default: DPDP has no "strictly necessary" exemption and the auth
    // pages present an explicit what/why gate before the script may load. A
    // default-true value would load Google's tracker with no affirmative act.
    default: false,
    vendor: "Google LLC (reCAPTCHA v3)",
    vendor_policy_url: "https://policies.google.com/privacy",
    examples: ["_GRECAPTCHA", "reCAPTCHA risk score", "IP address", "browser signals"],
  },
  {
    id: "analytics",
    label: "Analytics",
    description:
      "Measure feature usage and performance in aggregate to improve the product.",
    purpose_id: "analytics",
    lawful_basis: "consent",
    consent_required: true,
    default: false,
    examples: ["product analytics", "performance measurement"],
  },
  {
    id: "advertising",
    label: "Advertising",
    description:
      "Serve targeted/retargeted advertising and measure ad performance.",
    purpose_id: "advertising",
    lawful_basis: "consent",
    consent_required: true,
    default: false,
    examples: ["targeted ads", "retargeting", "ad measurement"],
  },
  {
    id: "personalisation",
    label: "Personalisation",
    description: "Tailor recommendations and content to you.",
    purpose_id: "personalisation",
    lawful_basis: "consent",
    consent_required: true,
    default: false,
    examples: ["recommendations", "content tailoring"],
  },
  {
    id: "social_media",
    label: "Social media & embeds",
    description: "Load third-party social widgets, embeds and share buttons.",
    purpose_id: "social_media",
    lawful_basis: "consent",
    consent_required: true,
    default: false,
    examples: ["embeds", "share widgets"],
  },
  {
    id: "consent_audit",
    label: "Consent evidence",
    description:
      "Record a hashed IP, user-agent and timestamp with each consent decision to prove notice + consent (s. 6(10)).",
    purpose_id: "consent_audit",
    lawful_basis: "consent",
    consent_required: false,
    // Locked-on: this IS the record proving the consent decision (s. 6(10)),
    // so it can never be switched off by the user.
    locked: true,
    default: true,
    examples: ["ip hash", "user agent", "timestamp"],
  },
];

export const cookieCategoryIds = () => COOKIE_CATEGORIES.map((c) => c.id);

/** Categories a user must actively consent to (all but functional/audit). */
export const consentRequiredCookieCategories = () =>
  COOKIE_CATEGORIES.filter((c) => c.consent_required).map((c) => c.id);

/**
 * Default cookie-category grant map for a fresh subject (never pre-set any
 * non-essential category). `ageUnknownOrChild` forces functional-only
 * (s. 9(3), default-safe).
 */
export const defaultCookiePreferences = (ageUnknownOrChild = false) => {
  const prefs = {};
  // For a child / unknown age: only the functional + security-necessity
  // categories are on. `captcha` (bot protection) is kept because it is a
  // security measure the guardian consents to at sign-up — NOT behavioural
  // tracking or targeted advertising, which s. 9(3) absolutely prohibits.
  // Only strictly-functional is safe to keep on without an affirmative choice;
  // reCAPTCHA is a third-party tracker and must NOT be pre-enabled for a child
  // or an unknown-age visitor.
  const childSafe = new Set(["strictly_functional"]);
  for (const c of COOKIE_CATEGORIES) {
    prefs[c.id] = ageUnknownOrChild ? childSafe.has(c.id) : c.default;
  }
  return prefs;
};

// ===========================================================
// 🏛️ DPO / grievance contact (s. 5(iv), s. 8(9), Rule 9)
// ===========================================================
export const getDpoContact = () => ({
  name: process.env.DPO_NAME || "Data Protection Officer",
  email: process.env.DPO_EMAIL || "dpo@example.com",
  phone: process.env.DPO_PHONE || "",
  address: process.env.DPO_ADDRESS || "",
});

/** Data Protection Board of India — how to complain (s. 13, s. 18). */
export const getBoardComplaintInfo = () => ({
  name: "Data Protection Board of India",
  url: process.env.DPB_COMPLAINT_URL || "https://www.meity.gov.in/data-protection-framework",
  note: "You must first exhaust our grievance mechanism (s. 13(3)) before approaching the Board.",
});

/**
 * Compute the Third Schedule / Rule 8(1) erasure-due date for an inactive
 * Data Principal. The period runs from the LATER of (a) the date she last
 * approached us / exercised a right, and (b) Rules commencement — we model
 * (a) here and treat the config baseline as covering (b).
 */
export const computeErasureDueAt = (lastActiveAt, days = INACTIVITY_ERASURE_DAYS) => {
  const base = lastActiveAt ? new Date(lastActiveAt) : new Date();
  return new Date(base.getTime() + days * 24 * 60 * 60 * 1000);
};

/** Rights request SLA due date (Rule 14). */
export const computeSlaDueAt = (from = new Date()) =>
  new Date(new Date(from).getTime() + RIGHTS_SLA_DAYS * 24 * 60 * 60 * 1000);

export default {
  DPDP_LEGAL_VERSION,
  NOTICE_VERSION,
  LEGACY_NOTICE_VERSION,
  PURPOSES,
  getPurpose,
  purposeIds,
  isValidPurpose,
  requiredPurposes,
  optionalPurposes,
  isLegitimateUse,
  isThirdScheduleCarveout,
  COOKIE_CATEGORIES,
  cookieCategoryIds,
  consentRequiredCookieCategories,
  defaultCookiePreferences,
  getDpoContact,
  getBoardComplaintInfo,
  computeErasureDueAt,
  computeSlaDueAt,
};
