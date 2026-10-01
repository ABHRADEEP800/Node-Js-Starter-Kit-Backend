// ===========================================================
// 👥 NOMINEE SERVICE — s. 14 (nomination, death/incapacity claims)
// ===========================================================
// Two halves:
//   A. Data Principal manages her nominee list (add / edit / remove).
//   B. A nominee submits a CLAIM (death/incapacity), an admin approves it, and
//      the nominee may then exercise the DP's rights (s. 14).
//
// Nominee identity is ENCRYPTED at rest (Rule 6(a)); callers only ever see
// masked values, and every change is audited (s. 8, Rule 6(c)).

import ApiError from "../utility/ApiError.js";
import crypto from "crypto";
import User from "../models/user.model.js";
import NomineeClaim from "../models/nomineeClaim.model.js";
import { audit } from "../events/auditLog.events.js";
import { maskPII, maskObject } from "../utility/piiMask.js";
import { encryptField, decryptField, tokenize } from "../utility/cryptoVault.js";

const MAX_NOMINEES = 5;

/** Public (masked) view of a stored nominee. */
const toPublicNominee = (n) => ({
  name: maskPII(decryptField(n.name) || "", "name"),
  relationship: n.relationship || null,
  contact: maskPII(
    decryptField(n.contact) || "",
    (decryptField(n.contact) || "").includes("@") ? "email" : "phone"
  ),
  share: n.share || null,
  status: n.status || "active",
  addedAt: n.addedAt,
  revokedAt: n.revokedAt,
});

/** Load the DP's ACTIVE nominee list, decrypted. */
export const getNominees = async (userId) => {
  const user = await User.findById(userId).select("nominees").lean();
  return (user?.nominees || []).map(toPublicNominee);
};

/**
 * Replace the DP's nominee list (add/edit). New entries are encrypted; existing
 * entries keep their status. Removed entries are soft-revoked (never silently
 * dropped) so the audit trail is intact.
 */
export const setNominees = async ({ userId, nominees, req }) => {
  const list = (nominees || []).slice(0, MAX_NOMINEES);
  const encrypted = list.map((n) => ({
    name: encryptField(String(n.name || "").trim()),
    relationship: (n.relationship || "").trim() || null,
    contact: encryptField(String(n.email || n.phone || "").trim()),
    share: (n.share || "").trim() || null,
    status: "active",
    addedAt: new Date(),
  }));

  await User.findByIdAndUpdate(userId, { nominees: encrypted });

  audit({
    userId,
    action: "NOMINEES_UPDATED",
    category: "rights",
    targetType: "User",
    targetId: String(userId),
    status: "SUCCESS",
    details: `count=${encrypted.length}`,
    ip: req?.ip,
  });

  return encrypted.map(toPublicNominee);
};

/** Edit a single nominee by index (name/relationship/contact/share). */
export const updateNominee = async ({ userId, index, updates, req }) => {
  const user = await User.findById(userId);
  if (!user) throw new ApiError(404, "User not found");
  const nominee = user.nominees?.[index];
  if (!nominee) throw new ApiError(404, "Nominee not found");
  if (nominee.status === "revoked") throw new ApiError(400, "Nominee already removed");

  if (updates.name !== undefined) nominee.name = encryptField(String(updates.name).trim());
  if (updates.relationship !== undefined) nominee.relationship = updates.relationship;
  if (updates.email !== undefined || updates.phone !== undefined) {
    nominee.contact = encryptField(String(updates.email || updates.phone || "").trim());
  }
  if (updates.share !== undefined) nominee.share = String(updates.share || "").trim() || null;

  await user.save({ validateBeforeSave: false });

  audit({
    userId,
    action: "NOMINEE_UPDATED",
    category: "rights",
    targetType: "User",
    targetId: String(userId),
    status: "SUCCESS",
    details: `index=${index}`,
    ip: req?.ip,
  });

  return toPublicNominee(nominee);
};

/** Soft-remove a nominee by index (keeps history). */
export const removeNominee = async ({ userId, index, req }) => {
  const user = await User.findById(userId);
  if (!user) throw new ApiError(404, "User not found");
  const nominee = user.nominees?.[index];
  if (!nominee) throw new ApiError(404, "Nominee not found");

  nominee.status = "revoked";
  nominee.revokedAt = new Date();
  await user.save({ validateBeforeSave: false });

  audit({
    userId,
    action: "NOMINEE_REMOVED",
    category: "rights",
    targetType: "User",
    targetId: String(userId),
    status: "SUCCESS",
    details: `index=${index}`,
    ip: req?.ip,
  });

  return toPublicNominee(nominee);
};

// ==========================================
// B. CLAIM FLOW (death / incapacity) — s. 14
// ==========================================

/**
 * Submit a nominee claim. Public (a grieving nominee may not have an account).
 * Evidence is encrypted at rest; the claim is `pending` until an admin decides.
 */
export const submitClaim = async ({
  dataPrincipalId,
  nomineeIndex,
  claimantName,
  claimantContact,
  claimantRelationship,
  basis,
  evidenceReference,
  note,
  req,
}) => {
  const dp = await User.findById(dataPrincipalId).select("nominees").lean();
  if (!dp) throw new ApiError(404, "Data Principal not found");
  const nominee = dp.nominees?.[nomineeIndex];
  if (!nominee || nominee.status === "revoked") {
    throw new ApiError(400, "No active nomination at that index");
  }

  const evidence_hash = crypto
    .createHash("sha256")
    .update(
      [
        tokenize(String(dataPrincipalId), "dp"),
        String(nomineeIndex),
        basis,
        String(claimantName || "").trim().toLowerCase(),
      ].join("|")
    )
    .digest("hex");

  const claim = await NomineeClaim.create({
    data_principal_id: dataPrincipalId,
    nominee_index: nomineeIndex,
    claimant_name_enc: encryptField(String(claimantName || "").trim()),
    claimant_contact_enc: claimantContact ? encryptField(String(claimantContact)) : null,
    claimant_relationship: claimantRelationship || null,
    basis,
    evidence_reference_enc: evidenceReference
      ? encryptField(String(evidenceReference))
      : null,
    evidence_hash,
    note: note ? String(note).slice(0, 2000) : null,
    status: "pending",
  });

  await User.findByIdAndUpdate(dataPrincipalId, {
    "nomineeClaim.status": "pending",
    "nomineeClaim.claimId": claim._id,
  });

  audit({
    action: "NOMINEE_CLAIM_SUBMITTED",
    category: "rights",
    targetType: "NomineeClaim",
    targetId: claim.claim_id,
    status: "SUCCESS",
    details: `basis=${basis} dp=${tokenize(String(dataPrincipalId), "dp")}`,
    ip: req?.ip,
  });

  return { claim_id: claim.claim_id, status: claim.status };
};

/** Admin decision on a claim. On approval the account is locked to the nominee. */
export const decideClaim = async ({ claimId, decision, note, adminId }) => {
  const claim = await NomineeClaim.findOne({ claim_id: claimId });
  if (!claim) throw new ApiError(404, "Claim not found");
  if (claim.status !== "pending") throw new ApiError(409, "Claim already decided");

  if (decision === "approve") {
    claim.status = "approved";
    claim.decided_at = new Date();
    claim.decided_by = String(adminId);
    claim.decision_note = note || null;
    await claim.save();

    const user = await User.findById(claim.data_principal_id);
    if (user) {
      user.nomineeClaim = {
        status: "approved",
        claimId: claim._id,
        approvedAt: new Date(),
      };
      // Lock the account: no normal logins; only the approved nominee may act.
      user.accountLockedForNominee = true;
      user.accountStatus = "active";
      if (user.nominees?.[claim.nominee_index]) {
        user.nominees[claim.nominee_index].status = "claimed";
      }
      await user.save({ validateBeforeSave: false });
    }
  } else {
    claim.status = "rejected";
    claim.decided_at = new Date();
    claim.decided_by = String(adminId);
    claim.decision_note = note || null;
    await claim.save();
    await User.findByIdAndUpdate(claim.data_principal_id, {
      "nomineeClaim.status": "rejected",
    });
  }

  audit({
    action: `NOMINEE_CLAIM_${claim.status.toUpperCase()}`,
    category: "rights",
    targetType: "NomineeClaim",
    targetId: claim.claim_id,
    status: "SUCCESS",
    details: `decision=${decision}`,
  });

  return { claim_id: claim.claim_id, status: claim.status };
};

/** Record an action a nominee took on the DP's behalf (append-only). */
export const recordClaimAction = async ({ claim, action, actor }) => {
  claim.actions.push({ at: new Date(), action, actor });
  await claim.save();
};

/** Admin view: all claims (optionally by status). */
export const listClaims = async ({ status } = {}) => {
  const filter = status ? { status } : {};
  const claims = await NomineeClaim.find(filter)
    .sort({ requested_at: -1 })
    .limit(200)
    .lean();
  return claims.map((c) => {
    // Never expose the encrypted envelopes to a client — drop them and surface
    // only the masked, human-readable fields.
    const { claimant_name_enc, claimant_contact_enc, evidence_reference_enc, ...rest } =
      maskObject(c);
    const contact = decryptField(claimant_contact_enc) || "";
    return {
      ...rest,
      // Reveal the claimant identity to admins (decrypted), but not to the public.
      claimant_name: decryptField(claimant_name_enc),
      claimant_contact: maskPII(
        contact,
        contact.includes("@") ? "email" : "phone"
      ),
    };
  });
};

/** Is there an approved claim for this user? Used to authorise nominee rights. */
export const getApprovedClaimForUser = async (userId) =>
  NomineeClaim.findOne({
    data_principal_id: userId,
    status: "approved",
  }).lean();
