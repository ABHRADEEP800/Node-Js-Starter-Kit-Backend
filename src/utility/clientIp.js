// ===========================================================
// 🌐 CLIENT IP RESOLVER — evidence capture for consent records
// ===========================================================
// Captures the best available client IP for s. 6(10) consent evidence WITHOUT
// changing the rate-limiter's trust model (which deliberately refuses to trust
// forwarded headers unless TRUST_PROXY is set — Issue 27/124).
//
// Precedence:
//   1. req.clientIp  — set by the Next.js bridge from a trustworthy platform
//                      header (x-forwarded-for / x-real-ip / cf-connecting-ip)
//   2. x-forwarded-for / x-real-ip / cf-connecting-ip headers (direct)
//   3. req.ip        — Express (already trust-proxy aware) / bridge fallback
//
// The result is normalised so `::ffff:127.0.0.1` and `::1` become `127.0.0.1`,
// which lets the masking/truncation helpers recognise a real IPv4 address.

export const normalizeIp = (ip) => {
  if (!ip) return null;
  let v = String(ip).trim();
  // Strip a bracketed IPv6 form: [::1]
  if (v.startsWith("[") && v.includes("]")) v = v.slice(1, v.indexOf("]"));
  // IPv4-mapped IPv6
  if (v.startsWith("::ffff:")) v = v.slice(7);
  if (v === "::1") return "127.0.0.1";
  return v;
};

const firstHeaderValue = (value) => {
  if (!value) return null;
  const first = String(value).split(",")[0].trim();
  return first || null;
};

export const resolveClientIp = (req) => {
  if (!req) return null;
  const headers = req.headers || {};

  // 1. A value the bridge already vetted.
  const fromBridge = normalizeIp(req.clientIp);
  if (fromBridge) return fromBridge;

  // 2. Forwarded headers commonly set by hosting platforms.
  const forwarded =
    firstHeaderValue(headers["x-forwarded-for"]) ||
    firstHeaderValue(headers["x-real-ip"]) ||
    firstHeaderValue(headers["cf-connecting-ip"]);
  if (forwarded) return normalizeIp(forwarded);

  // 3. Express's trust-proxy-aware value — but only if it is actually an IP.
  //    The Next bridge's rate-limit fallback is a synthetic UA hash, which must
  //    never be mistaken for an address.
  const fallback = normalizeIp(req.ip);
  return looksLikeIp(fallback) ? fallback : null;
};

/** True when the string looks like an IPv4/IPv6 address (not an opaque hash). */
export const looksLikeIp = (value) => {
  if (!value) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return true;
  return value.includes(":");
};

export default { resolveClientIp, normalizeIp, looksLikeIp };
