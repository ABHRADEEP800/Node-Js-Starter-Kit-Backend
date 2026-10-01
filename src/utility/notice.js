// ===========================================================
// 📜 NOTICE BUILDER — s. 5 + Rule 3
// ===========================================================
// Produces the itemised consent notice the Data Principal must see BEFORE or
// AT THE TIME of collection, in clear plain language, independently
// understandable, and including every element required by s. 5 + Rule 3:
//   1. itemised personal data being collected
//   2. the specific purpose + goods/services/uses it enables
//   3. how to withdraw consent (s. 6(4)/(6)) and raise a grievance (s. 13)
//   4. how to complain to the Data Protection Board
//   5. contact details of the DPO / authorised person
//   6. a link/means to withdraw consent with ease comparable to giving it
// Plus the language parameter required by s. 5(3).
//
// All user-facing strings (headings, statements, labels, itemised purpose and
// cookie text) are localised via `noticeI18n`. Languages without a full
// translation fall back to English PER KEY, and `translation_status` is set to
// "english-fallback" so the UI can disclose that honestly.

import {
  NOTICE_VERSION,
  LEGACY_NOTICE_VERSION,
  PURPOSES,
  DPDP_LEGAL_VERSION,
  DATA_FIDUCIARY_NAME,
  COOKIE_CATEGORIES,
  EIGHTH_SCHEDULE_LANGUAGES,
  getDpoContact,
  getBoardComplaintInfo,
} from "../config/dpdp.config.js";
import {
  stringsFor,
  purposeLabel,
  cookieLabel,
  isTranslated,
  translatedLanguageCodes,
} from "./noticeI18n.js";

const LANGUAGE_CODES = new Set(EIGHTH_SCHEDULE_LANGUAGES.map((l) => l.code));

/**
 * Build the structured consent notice.
 * @param {string} language Eighth-Schedule language code (default "en")
 * @param {object} opts { purposes?: string[] } restrict to a subset
 */
export const buildNotice = (language = "en", opts = {}) => {
  const lang = LANGUAGE_CODES.has(language) ? language : "en";
  const t = stringsFor(lang);
  const translated = isTranslated(lang);

  const purposeList = opts.purposes
    ? PURPOSES.filter((p) => opts.purposes.includes(p.id))
    : PURPOSES;

  const dpo = getDpoContact();
  const board = getBoardComplaintInfo();

  return {
    notice_version: NOTICE_VERSION,
    legal_version: DPDP_LEGAL_VERSION,
    language: lang,
    // "authored" (English), "translated" (full translation), or "english-fallback".
    translation_status: lang === "en" ? "authored" : translated ? "translated" : "english-fallback",
    // Only languages we can actually render are offered in the dropdown.
    available_languages: EIGHTH_SCHEDULE_LANGUAGES.filter((l) =>
      translatedLanguageCodes().includes(l.code)
    ),
    // Full Eighth Schedule list is still reported for compliance transparency,
    // even though only translated ones are selectable.
    eighth_schedule_languages: EIGHTH_SCHEDULE_LANGUAGES,
    heading: t.heading,

    // The full localised UI dictionary so the client renders entirely in the
    // chosen language (section titles, labels, statements) — not just a couple
    // of strings. Clients should render from here, not from hardcoded English.
    strings: t,

    // s. 5(i) — who is processing + DPO contact (Rule 9).
    data_fiduciary: {
      name: DATA_FIDUCIARY_NAME,
      role: "Data Fiduciary (s. 2(i))",
      dpo,
    },

    // s. 5(i) + Rule 3 — itemised personal data and the specific purpose.
    // Labels/descriptions are localised.
    items: purposeList.map((p) => {
      const localized = purposeLabel(lang, p);
      return {
        purpose_id: p.id,
        personal_data: p.fields,
        purpose: localized.label,
        purpose_description: localized.description,
        lawful_basis: p.lawful_basis,
        required: p.required,
        retention_days: p.retention_days,
      };
    }),

    // Domain 8 — cookie/tracker categories, localised.
    cookie_categories: COOKIE_CATEGORIES.map((c) => {
      const localized = cookieLabel(lang, c);
      return {
        id: c.id,
        label: localized.label,
        description: localized.description,
        lawful_basis: c.lawful_basis,
        consent_required: c.consent_required,
        default_on: c.default,
        examples: c.examples,
      };
    }),

    // s. 5(ii) — what we will NOT collect without separate consent.
    not_collected_without_consent: t.notCollectedWithoutConsent || [
      "IP address beyond the security and consent-audit purposes (we store a salted hash, not the raw address)",
      "device / OS fingerprinting for advertising",
      "precise geolocation",
      "advertising identifiers",
      "cross-site behavioural tracking",
    ],

    // s. 5(iii) + Rule 3 — how to exercise rights and withdraw consent.
    rights: {
      access: "GET /api/v1/privacy/data",
      correction: "POST /api/v1/privacy/correct",
      erasure: "POST /api/v1/privacy/erase",
      withdraw: "POST /api/v1/privacy/consent/withdraw",
      grievance: "POST /api/v1/privacy/grievance",
      nomination: "POST /api/v1/privacy/nominate",
    },
    // Localised one-line descriptions for the rights surface.
    rights_descriptions: t.rights,

    // s. 5(iv) — how to complain to the Board, after exhausting our grievance
    // mechanism (s. 13).
    board_complaint: board,

    // s. 6(2)/(5)/(8(1)) + validity statement — all localised.
    severability_statement: t.severabilityStatement,
    consent_statement: t.consentStatement,
    consent_label: t.consentLabel || "I have read and understood the above and I consent to the itemised collection and processing.",
    withdrawal_consequences: t.withdrawalConsequences,
    accountability_statement: t.accountabilityStatement,

    // s. 15 — Data Principal duties we must surface.
    data_principal_duties: t.duties,
  };
};

/**
 * s. 5(2) — migration notice for consent given BEFORE commencement. We served
 * the notice after the fact and may continue processing until the DP
 * withdraws. Served to legacy accounts by the retention/migration job.
 */
export const buildLegacyMigrationNotice = (language = "en") => {
  const board = getBoardComplaintInfo();
  const dpo = getDpoContact();
  const t = stringsFor(language);
  return {
    notice_version: LEGACY_NOTICE_VERSION,
    legal_version: DPDP_LEGAL_VERSION,
    language,
    kind: "legacy-migration",
    heading: t.legacyHeading || "Updated privacy notice for your existing account",
    body:
      t.legacyBody ||
      "You gave us your data before the DPDP Act's notice requirements took " +
        "effect. This notice describes the personal data we hold, the purpose it " +
        "is used for, your rights, and how to complain to the Data Protection " +
        "Board. We will continue to process your data on this basis until you " +
        "withdraw consent (s. 5(2)).",
    rights: buildNotice(language).rights,
    dpo,
    board_complaint: board,
    withdraw_link: "POST /api/v1/privacy/consent/withdraw",
  };
};

export default buildNotice;
