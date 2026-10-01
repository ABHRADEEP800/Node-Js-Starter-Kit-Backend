import { z } from "zod";

export const loginSchema = z.object({
  user: z.object({
    username: z.string().optional(),
    email: z.string().email().optional(),
    password: z.string().min(1),
    rememberMe: z.boolean().optional(),
    recaptchaToken: z.string().min(1),
  }),
});

export const changePassSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8),
});

export const changeNameSchema = z.object({
  firstName: z.string().min(1),
  lastName: z.string().min(1),
});

export const verify2FASchema = z.object({
  code: z.string().min(6), // 6 digit OTP or 8 hex backup code
  enable: z.boolean().optional(),
});

export const revokeSessionSchema = z.object({
  // Session _ids are 64-char hex (crypto.randomBytes(32).toString("hex")).
  // Validating the shape avoids a Mongoose CastError -> 500 on bad input.
  sessionId: z.string().regex(/^[a-f0-9]{64}$/i, "Invalid session id"),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email(),
  recaptchaToken: z.string().min(1),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(8),
});

// ==========================================
// 🔑 PASSKEY (WEBAUTHN) SCHEMAS
// ==========================================

export const passkeyRegisterOptionsSchema = z.object({
  name: z.string().min(1).max(64),
});

export const passkeyRegisterVerifySchema = z.object({
  name: z.string().min(1).max(64),
  response: z.any(),
});

export const passkeyLoginOptionsSchema = z.object({
  // Empty string is treated as "no identifier" (empty allow-list) by the
  // handler, so the field must accept "" as well as undefined.
  identifier: z
    .string()
    .trim()
    .max(320)
    .optional()
    .transform((v) => v || ""),
  recaptchaToken: z.string().min(1),
});

export const passkeyLoginVerifySchema = z.object({
  response: z.any(),
  // Without declaring this, Zod strips it and "remember me" never works for
  // passkey logins (the controller reads req.body.rememberMe).
  rememberMe: z.boolean().optional(),
});

export const passkeyDeleteSchema = z.object({
  // Mongo ObjectId hex — reject malformed ids before the DB query.
  id: z.string().regex(/^[a-f0-9]{24}$/i, "Invalid passkey id"),
});

// ==========================================
// 🇮🇳 DPDP SCHEMAS (ss. 5–14)
// ==========================================

// Signup now carries the age gate + itemised consent (s. 6, s. 9).
// `optionalConsent` is a per-purpose opt-in map; absent/false means NO consent
// (no pre-ticked boxes). `ageConfirmed` is an explicit affirmative act.
export const signupSchema = z.object({
  user: z.object({
    firstName: z.string().min(1),
    lastName: z.string().min(1),
    username: z
      .string()
      .min(3)
      .regex(/^[a-zA-Z0-9_]+$/),
    email: z.string().email(),
    password: z.string().min(8),
    recaptchaToken: z.string().min(1),
    // Age gate — ISO date string (YYYY-MM-DD).
    dateOfBirth: z.string().min(4),
    // Explicit, unticked-by-default consent to the core notice (s. 6).
    consentAccepted: z.literal(true),
    noticeVersion: z.string().min(1),
    language: z.string().min(2).max(10).optional(),
    // Optional purposes the user separately opted into.
    optionalConsent: z.array(z.string()).optional().default([]),
    // For a child, guardian identity for verifiable parental consent (Rule 10).
    guardian: z
      .object({
        relationship: z.enum(["parent", "guardian", "lawful_guardian"]).optional(),
        name: z.string().min(1),
        email: z.string().email().optional(),
        phone: z.string().min(4).optional(),
        verificationMethod: z
          .enum([
            "existing_reliable_identity",
            "voluntarily_provided_identity",
            "virtual_token",
            "digital_locker",
          ])
          .optional(),
      })
      .optional(),
  }),
});

export const grantConsentSchema = z.object({
  purposes: z.array(z.string().min(1)).min(1),
  language: z.string().min(2).max(10).optional(),
  consentManagerRef: z.string().optional(),
});

export const withdrawConsentSchema = z.object({
  purposeId: z.string().min(1).optional(), // omit or "all"
  language: z.string().min(2).max(10).optional(),
});

export const correctionSchema = z.object({
  firstName: z.string().min(1).optional(),
  lastName: z.string().min(1).optional(),
  email: z.string().email().optional(),
  language: z.string().min(2).max(10).optional(),
});

export const grievanceSchema = z.object({
  subject: z.string().min(1).max(200),
  message: z.string().min(1).max(5000),
  language: z.string().min(2).max(10).optional(),
});

export const escalateGrievanceSchema = z.object({
  case_id: z.string().min(1),
  board_reference: z.string().optional(),
});

export const nominationSchema = z.object({
  nominees: z
    .array(
      z.object({
        name: z.string().min(1).max(120),
        relationship: z.string().max(60).optional(),
        email: z.string().email().optional(),
        phone: z.string().min(4).optional(),
        share: z.string().max(40).optional(),
      })
    )
    .min(1)
    .max(5),
  language: z.string().min(2).max(10).optional(),
});

// Replacing the nominee list (PUT /nominees).
export const nomineesReplaceSchema = z.object({
  nominees: z
    .array(
      z.object({
        name: z.string().min(1).max(120),
        relationship: z.string().max(60).optional(),
        email: z.string().email().optional(),
        phone: z.string().min(4).optional(),
        share: z.string().max(40).optional(),
      })
    )
    .max(5),
  language: z.string().min(2).max(10).optional(),
});

// Editing a single nominee (PATCH /nominees/:index).
export const nomineeEditSchema = z.object({
  name: z.string().min(1).max(120).optional(),
  relationship: z.string().max(60).optional(),
  email: z.string().email().optional(),
  phone: z.string().min(4).optional(),
  share: z.string().max(40).optional(),
});

// Public nominee claim (s. 14 — death/incapacity).
export const nomineeClaimSchema = z.object({
  dataPrincipalId: z.string().min(1),
  nomineeIndex: z.coerce.number().int().min(0).max(4).optional().default(0),
  claimantName: z.string().min(1).max(120),
  claimantContact: z.string().max(200).optional(),
  claimantRelationship: z.string().max(60).optional(),
  basis: z.enum(["death", "incapacity"]),
  evidenceReference: z.string().max(300).optional(),
  note: z.string().max(2000).optional(),
});

// Admin decision on a claim.
export const nomineeClaimDecisionSchema = z.object({
  decision: z.enum(["approve", "reject"]),
  note: z.string().max(2000).optional(),
});

export const guardianConsentSchema = z.object({
  relationship: z.enum(["parent", "guardian", "lawful_guardian"]).optional(),
  guardianName: z.string().min(1).max(120),
  guardianEmail: z.string().email().optional(),
  guardianPhone: z.string().min(4).optional(),
  verificationMethod: z.enum([
    "existing_reliable_identity",
    "voluntarily_provided_identity",
    "virtual_token",
    "digital_locker",
  ]),
});

// ---- Admin: breach / transfer / DPIA / retention ----
export const breachCreateSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().min(1),
  impact: z
    .object({
      confidentiality: z.boolean().optional(),
      integrity: z.boolean().optional(),
      availability: z.boolean().optional(),
    })
    .optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  nature: z.string().optional(),
  extent: z.string().optional(),
  location: z.string().optional(),
  likely_impact: z.string().optional(),
  dataCategories: z.array(z.string()).optional(),
  affectedCount: z.number().int().nonnegative().optional(),
  affectedUserRefs: z.array(z.string()).optional(),
  involvesChildren: z.boolean().optional(),
  cause: z.string().optional(),
  occurredAt: z.string().optional(),
  detectedAt: z.string().optional(),
  incidentCommander: z.string().optional(),
});

export const breachNotifySchema = z.object({
  stage: z.enum(["board_first", "board_detailed", "data_principals", "contained", "close", "extension"]),
  note: z.string().max(2000).optional(),
});

export const transferUpsertSchema = z.object({
  id: z.string().optional(),
  country: z.string().min(2).max(3),
  recipient: z.string().min(1),
  recipient_type: z
    .enum(["processor", "sub_processor", "group_company", "foreign_state_entity"])
    .optional(),
  purpose_id: z.string().min(1),
  lawful_basis: z.string().min(1),
  data_categories: z.array(z.string()).optional(),
  safeguards: z.array(z.string()).optional(),
  mechanism: z.string().optional(),
  is_foreign_state_entity: z.boolean().optional(),
  restricted: z.boolean().optional(),
  restricted_reference: z.string().optional(),
  active: z.boolean().optional(),
});

export const dpiaUpsertSchema = z.object({
  id: z.string().optional(),
  activity_name: z.string().min(1),
  purpose_ids: z.array(z.string()).optional(),
  lawful_basis: z.string().optional(),
  data_categories: z.array(z.string()).optional(),
  data_principals: z
    .object({
      adults: z.boolean().optional(),
      children: z.boolean().optional(),
      persons_with_disability: z.boolean().optional(),
    })
    .optional(),
  volume: z.string().optional(),
  retention: z.string().optional(),
  processors: z.array(z.string()).optional(),
  cross_border: z.boolean().optional(),
  automated_decisions: z.boolean().optional(),
  ai_models: z.array(z.string()).optional(),
  necessity_notes: z.string().optional(),
  risks: z.array(z.any()).optional(),
  controls_verified: z.record(z.string(), z.boolean()).optional(),
  residual_rating: z.enum(["low", "medium", "high", "unacceptable"]).optional(),
  decision: z.enum(["proceed", "proceed_with_conditions", "do_not_proceed"]).optional(),
  conditions: z.array(z.string()).optional(),
  is_sdf: z.boolean().optional(),
  dpo_name: z.string().optional(),
  dpo_india_based: z.boolean().optional(),
  auditor_name: z.string().optional(),
  auditor_significant_observations: z.string().optional(),
  localisation_notes: z.string().optional(),
  next_review_due_at: z.string().optional(),
});

export const retentionRunSchema = z.object({
  dryRun: z.boolean().optional(),
});

// ==========================================
// 🍪 DOMAIN 8 COOKIE / TRACKER CONSENT
// ==========================================
export const cookieConsentSchema = z.object({
  action: z.enum(["accept_all", "reject_all", "custom"]),
  categories: z
    .object({
      strictly_functional: z.boolean().optional(),
      captcha: z.boolean().optional(),
      analytics: z.boolean().optional(),
      advertising: z.boolean().optional(),
      personalisation: z.boolean().optional(),
      social_media: z.boolean().optional(),
      consent_audit: z.boolean().optional(),
    })
    .optional()
    .default({}),
  language: z.string().min(2).max(10).optional(),
  // Fourth Schedule: affirmatively confirming the DP is not a child.
  ageAssurance: z.boolean().optional().default(false),
});

export const cookieWithdrawSchema = z.object({
  category: z
    .enum([
      "all",
      "captcha",
      "analytics",
      "advertising",
      "personalisation",
      "social_media",
    ])
    .optional(),
  language: z.string().min(2).max(10).optional(),
});
