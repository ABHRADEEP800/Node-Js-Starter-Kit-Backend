// ===========================================================
// 👶 AGE VERIFICATION & GUARDIAN CONSENT — s. 9, Rules 10/11/12
// ===========================================================
// A child is anyone under 18 (s. 2(f)). Age is verified at onboarding before
// any processing. If the user is a child we block optional processing, disable
// telemetry/tracking/targeted ads, and require verifiable parental/lawful-
// guardian consent from an identifiable adult (Rules 10–11). If age is unknown
// we treat the user as a child until verified otherwise (deny-by-default).

import crypto from "crypto";
import GuardianConsent from "../models/guardianConsent.model.js";
import User from "../models/user.model.js";
import { encryptField } from "../utility/cryptoVault.js";
import { hashIdentifier } from "../utility/piiMask.js";

export const CHILD_AGE_LIMIT = 18;

/** Coarse age from a date of birth (in whole years). */
export const ageFromDob = (dob) => {
  if (!dob) return null;
  const birth = new Date(dob);
  if (Number.isNaN(birth.getTime())) return null;
  const now = new Date();
  let age = now.getFullYear() - birth.getFullYear();
  const m = now.getMonth() - birth.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < birth.getDate())) age -= 1;
  return age;
};

/**
 * Is this person a child for DPDP purposes? Unknown/absent DOB ⇒ true
 * (treat as a child until verified — s. 9).
 */
export const isChildDob = (dob) => {
  const age = ageFromDob(dob);
  if (age === null) return true;
  return age < CHILD_AGE_LIMIT;
};

/**
 * Store verifiable guardian consent (Rule 10/11). Guardian identity is
 * ENCRYPTED at rest; only hashes/outcome are used for proof (Rule 6(a)).
 */
export const recordGuardianConsent = async ({
  childUserId,
  relationship,
  guardianName,
  guardianEmail,
  guardianPhone,
  verificationMethod,
  verifier,
  verificationReference = null,
  rule12Exemption = null,
  expiresAt = null,
}) => {
  const evidence = crypto
    .createHash("sha256")
    .update(
      [
        String(childUserId),
        relationship,
        verificationMethod,
        verifier,
        hashIdentifier(String(childUserId), "guardian"),
      ].join("|")
    )
    .digest("hex");

  const doc = await GuardianConsent.create({
    child_user_id: childUserId,
    relationship,
    guardian_name_enc: encryptField(guardianName),
    guardian_email_enc: guardianEmail ? encryptField(guardianEmail) : null,
    guardian_phone_enc: guardianPhone ? encryptField(guardianPhone) : null,
    verification_method: verificationMethod,
    verifier,
    verification_reference: verificationReference,
    evidence_hash: evidence,
    expires_at: expiresAt,
    rule12_exemption: rule12Exemption,
  });

  await User.findByIdAndUpdate(childUserId, {
    guardianVerified: true,
    guardianConsentId: doc._id,
    // s. 9(3): never track/behaviourally monitor/target-ads a child.
    telemetryDisabled: true,
  });

  return doc;
};

/**
 * Does this user have a CURRENT, valid guardian consent on file?
 * A child with no valid guardian consent must not have optional processing.
 */
export const hasValidGuardianConsent = async (userId) => {
  const now = new Date();
  const doc = await GuardianConsent.findOne({
    child_user_id: userId,
    status: "active",
    $or: [{ expires_at: null }, { expires_at: { $gt: now } }],
  }).lean();
  return Boolean(doc);
};
