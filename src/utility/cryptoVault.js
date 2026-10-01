// ===========================================================
// 🔐 CRYPTO VAULT — Encryption/obfuscation at rest (Rule 6(a), s. 8(4))
// ===========================================================
// AES-256-GCM envelope encryption for sensitive fields, plus deterministic
// HMAC virtual tokens (Rule 6(a)) for cross-system references. The master key
// comes from the environment (DPDP_FIELD_KEY) and is never hardcoded. In
// production, source it from a KMS / secret manager and rotate — this module
// supports key rotation via a key-id prefix on every ciphertext.
//
// Envelope format: `v1:<keyId>:<ivB64>:<tagB64>:<cipherB64>`

import crypto from "crypto";

const MASTER_KEY_RAW =
  process.env.DPDP_FIELD_KEY || process.env.ACCESS_TOKEN_SECRET || "";

if (!MASTER_KEY_RAW) {
  // Same posture as the existing PASSWORD_PEPPER guard: refuse to start
  // silently without a key, otherwise "encryption" would be a no-op.
  throw new Error(
    "DPDP_FIELD_KEY (or ACCESS_TOKEN_SECRET as fallback) is required for DPDP field encryption. Add it to your .env."
  );
}

// Derive a 32-byte key. We accept either a base64/hex key or a passphrase and
// normalise via scrypt with a fixed (non-secret) salt — the secret is the
// input, not the salt, and key rotation is handled by the keyId prefix.
const KEY_ID = process.env.DPDP_FIELD_KEY_ID || "v1";
const derivate = (material) =>
  crypto.scryptSync(material, "dpdp-field-encryption", 32);

let keys = { [KEY_ID]: derivate(MASTER_KEY_RAW) };

/** Register an additional decryption-only key for rotation. */
export const registerKey = (keyId, material) => {
  keys[keyId] = derivate(material);
};

const currentKey = () => keys[KEY_ID];

/**
 * Encrypt a string field. Returns null for nullish input.
 * @param {string} plain
 */
export const encryptField = (plain) => {
  if (plain === undefined || plain === null || plain === "") return plain;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", currentKey(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(String(plain), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [
    "v1",
    KEY_ID,
    iv.toString("base64"),
    tag.toString("base64"),
    ciphertext.toString("base64"),
  ].join(":");
};

/**
 * Decrypt an envelope produced by `encryptField`. Plain values (legacy, not
 * yet migrated) are returned unchanged so reads never break mid-migration.
 * @param {string} envelope
 */
export const decryptField = (envelope) => {
  if (!envelope) return envelope;
  const parts = String(envelope).split(":");
  if (parts.length !== 5 || parts[0] !== "v1") return envelope; // legacy plain

  const [, keyId, ivB64, tagB64, dataB64] = parts;
  const key = keys[keyId];
  if (!key) throw new Error(`No DPDP field key registered for keyId=${keyId}`);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivB64, "base64")
  );
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64")),
    decipher.final(),
  ]);
  return plain.toString("utf8");
};

/** True when a value looks like a v1 envelope (already encrypted). */
export const isEncrypted = (value) =>
  typeof value === "string" && value.startsWith("v1:") && value.split(":").length === 5;

/**
 * Deterministic virtual token for an identifier (Rule 6(a)). Deterministic so
 * it can be used as a stable join key; the tokenising secret is the master key.
 */
export const tokenize = (value, scope = "default") => {
  if (value === undefined || value === null || value === "") return value;
  return crypto
    .createHmac("sha256", currentKey())
    .update(`${scope}:${value}`)
    .digest("hex");
};

export default { encryptField, decryptField, isEncrypted, tokenize, registerKey };
