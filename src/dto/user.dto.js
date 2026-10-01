import { z } from "zod";

// ==========================================
// 📦 USER OUTPUT DTO (whitelist)
// ==========================================
// Single source of truth for which user fields may leave the server. Zod
// strips anything not declared here, so sensitive/internal fields can never
// leak even if a handler passes a full Mongoose document. Keep this list in
// sync with what the frontend actually consumes.
export const userOutputSchema = z
  .object({
    _id: z.any().optional(),
    firstName: z.string(),
    lastName: z.string(),
    username: z.string(),
    email: z.string().email(),
    role: z.enum(["user", "admin"]),
    createdAt: z.any().optional(),
    // DPDP: age/guardian status so the client can gate features and render the
    // Privacy Center. dateOfBirth and all secrets are intentionally excluded.
    isChild: z.boolean().optional(),
    guardianVerified: z.boolean().optional(),
    telemetryDisabled: z.boolean().optional(),
    accountStatus: z.enum(["active", "erasure_pending", "erased"]).optional(),
  })
  .strip();

/**
 * Convert a Mongoose user document (or plain object) into the output DTO.
 * Only whitelisted fields survive; anything undeclared is dropped.
 */
export const toUserDTO = (user) =>
  userOutputSchema.parse(user?.toObject ? user.toObject() : user);

export default toUserDTO;
