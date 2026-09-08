// ==========================================
// 🎛️ WEBAUTHN RELYING PARTY CONFIG
// ==========================================
// rpID is derived from the origin hostname by default so the two can never
// drift apart. In production set PASSKEY_ORIGIN to the HTTPS origin and, if
// needed, PASSKEY_RP_ID to the explicit domain.
const ORIGIN = process.env.PASSKEY_ORIGIN || "http://localhost:5173";

export const passkeyConfig = {
  rpID: process.env.PASSKEY_RP_ID || new URL(ORIGIN).hostname,
  rpName: process.env.PASSKEY_RP_NAME || "Starter Kit",
  origin: ORIGIN,
  challengeTtlMs: 2 * 60 * 1000, // 2 minutes
};
