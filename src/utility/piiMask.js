// ===========================================================
// 🎭 PII MASKING — Rule 6(a), s. 8(5)
// ===========================================================
// A single canonical `maskPII(value, kind)` is the ONLY permitted path to
// render personal data into logs, terminals, exceptions or analytics. Raw PII
// must never reach a log sink. This module also exposes `maskObject` (recursive
// redaction of structured payloads) and `hashIdentifier` (stable pseudonymous
// key = HMAC-SHA256, so we can correlate without exposing the value).
//
// See references/pii-masking.md for the canonical patterns.

import crypto from "crypto";

/**
 * Mask a single value.
 * @param {*} value raw value
 * @param {string} kind email|phone|aadhaar|pan|card|account|name|address|dob|ip|geo|child|secret
 */
export const maskPII = (value, kind = "default") => {
  if (value === undefined || value === null) return value;
  const str = String(value);

  switch (kind) {
    case "email": {
      const [local, domain] = str.split("@");
      if (!domain) return "[REDACTED_EMAIL]";
      return `${local.slice(0, 1)}${"*".repeat(Math.max(1, local.length - 1))}@${domain}`;
    }
    case "phone": {
      const digits = str.replace(/[^\d+]/g, "");
      const last4 = digits.slice(-4);
      const country = digits.startsWith("+") ? digits.slice(0, 3) : "";
      return `${country} ${"*".repeat(6)}${last4}`.trim();
    }
    case "aadhaar": {
      const d = str.replace(/\D/g, "");
      return `XXXX XXXX ${d.slice(-4)}`;
    }
    case "pan": {
      const s = str.toUpperCase();
      // Always keep the last char, but reveal at most the first 2 chars and
      // never the whole value (the old formula unmasked a 6-char PAN).
      if (s.length <= 4) return "*".repeat(Math.max(6, s.length));
      return `${s.slice(0, 2)}${"*".repeat(s.length - 3)}${s.slice(-1)}`;
    }
    case "card": {
      const d = str.replace(/\D/g, "");
      return `**** **** **** ${d.slice(-4)}`;
    }
    case "account": {
      const d = str.replace(/\s/g, "");
      return `${"*".repeat(Math.max(4, d.length - 4))}${d.slice(-4)}`;
    }
    case "name": {
      return str
        .split(/\s+/)
        .filter(Boolean)
        .map((part) => `${part.slice(0, 1)}${"*".repeat(Math.max(1, part.length - 1))}`)
        .join(" ");
    }
    case "address":
      return "[REDACTED_ADDRESS]";
    case "dob": {
      const m = str.match(/^(\d{4})/);
      return m ? `${m[1]}-**-**` : "[REDACTED_DOB]";
    }
    case "ip": {
      if (str.includes(":")) return "[REDACTED_IPV6]";
      const parts = str.split(".");
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
      return "[REDACTED_IP]";
    }
    case "geo":
      return "[REDACTED_GEO]";
    case "child":
      return "[CHILD_PII_REDACTED]";
    case "secret":
    case "token":
    case "password":
    case "otp":
      return "[REDACTED]";
    default:
      return str.length <= 4 ? "****" : `${str.slice(0, 2)}${"*".repeat(str.length - 2)}`;
  }
};

// Field-name denylist applied recursively to structured logs. Names are
// lowercased before comparison. Raw values of these fields are replaced.
const DENYLIST = new Set([
  "password",
  "pass",
  "passwordhash",
  "currentpassword",
  "newpassword",
  "otp",
  "totp",
  "twofacode",
  "backupcodes",
  "token",
  "accesstoken",
  "refreshtoken",
  "emailverificationtoken",
  "passwordresettoken",
  "secret",
  "apikey",
  "authorization",
  "cookie",
  "setcookie",
  "aadhaar",
  "aadhaarnumber",
  "pan",
  "pannumber",
  "cvv",
  "cardnumber",
  "accountnumber",
  "ssn",
  "dateofbirth",
  "dob",
  "ip",
  "ipaddress",
  "geolocation",
  "latitude",
  "longitude",
  "guardianname",
  "guardianemail",
  "childname",
  "nominees",
  "nominee",
  "guardianname_enc",
  "guardianemail_enc",
  "guardianphone_enc",
  "guardian_name_enc",
  "guardian_email_enc",
  "guardian_phone_enc",
]);

// Field-name → mask kind for fields we want partially masked (not fully
// redacted) when surfaced in logs.
const FIELD_KIND = {
  email: "email",
  phonenumber: "phone",
  phone: "phone",
  useragent: "default",
};

/**
 * Recursively mask a structured object/array for logging. Never mutates input.
 * @param {*} input
 * @param {number} depth guard against cycles
 */
export const maskObject = (input, depth = 0) => {
  if (input === null || input === undefined) return input;
  if (depth > 6) return "[TRUNCATED]";
  if (Array.isArray(input)) return input.map((v) => maskObject(v, depth + 1));
  if (typeof input !== "object") return input;

  // Preserve scalar-like objects instead of recursing them into `{}`:
  // Date → ISO string, Buffer → redacted, RegExp/etc → string, and any object
  // exposing toJSON (Mongoose ObjectId/Decimal128) → its JSON form.
  if (input instanceof Date) return input.toISOString();
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(input)) return "[REDACTED_BUFFER]";
  if (input instanceof RegExp) return String(input);
  if (typeof input.toJSON === "function") {
    const j = input.toJSON();
    // ObjectId → hex string, Decimal128 → { $numberDecimal }, etc. Use the
    // JSON form rather than recursing the raw instance (which would yield {}).
    if (j === null || typeof j !== "object") return j;
    if (j !== input) return maskObject(j, depth + 1);
  }

  const out = {};
  for (const [key, value] of Object.entries(input)) {
    const lower = key.toLowerCase();
    if (DENYLIST.has(lower)) {
      out[key] = "[REDACTED]";
    } else if (FIELD_KIND[lower] && typeof value === "string") {
      out[key] = maskPII(value, FIELD_KIND[lower]);
    } else if (value && typeof value === "object") {
      out[key] = maskObject(value, depth + 1);
    } else {
      out[key] = value;
    }
  }
  return out;
};

/**
 * Stable pseudonymous identifier: HMAC-SHA256(secret, "scope:value").
 *
 * IMPORTANT: the second argument is a DOMAIN-SEPARATION SCOPE (a public label
 * such as "actor" or "cookie-ua"), NOT the HMAC key. The key always comes from
 * the server secret (DPDP_TOKEN_SECRET / ACCESS_TOKEN_SECRET) and never from a
 * caller-supplied string — otherwise the "pseudonymous" token would be signed
 * with a public constant and trivially forgeable/reversible.
 *
 * Use this instead of logging the raw value so correlation/joins still work
 * (Rule 6(a) virtual tokens). Falls back to a process-local random key only
 * when no secret is configured (dev).
 */
let fallbackKey = null;
export const hashIdentifier = (
  value,
  scope = "default",
  key = process.env.DPDP_TOKEN_SECRET || process.env.ACCESS_TOKEN_SECRET
) => {
  if (value === undefined || value === null || value === "") return null;
  let secret = key;
  if (!secret) {
    if (!fallbackKey) fallbackKey = crypto.randomBytes(32).toString("hex");
    secret = fallbackKey;
  }
  return crypto
    .createHmac("sha256", secret)
    .update(`${scope}:${String(value)}`)
    .digest("hex")
    .slice(0, 32);
};

export default { maskPII, maskObject, hashIdentifier };
