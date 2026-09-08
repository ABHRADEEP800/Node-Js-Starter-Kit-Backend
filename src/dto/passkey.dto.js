import { z } from "zod";

// ==========================================
// 📦 PASSKEY OUTPUT DTO (whitelist)
// ==========================================
// Only whitelisted fields may leave the server. The public key and challenge
// are internal and must never be serialized to the client.
export const passkeyOutputSchema = z
  .object({
    _id: z.any().optional(),
    name: z.string(),
    transports: z.array(z.string()).optional(),
    credential_device_type: z.string().optional(),
    createdAt: z.any().optional(),
    last_used_at: z.any().nullable().optional(),
  })
  .strip();

/**
 * Convert a Passkey document (or plain object) into the output DTO.
 * The raw `public_key` and `counter` are deliberately stripped.
 */
export const toPasskeyDTO = (passkey) =>
  passkeyOutputSchema.parse(passkey?.toObject ? passkey.toObject() : passkey);

export default toPasskeyDTO;
