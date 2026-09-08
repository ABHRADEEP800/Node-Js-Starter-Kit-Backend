// Issue 9: token bound to session id so cross-session replay fails.
// Issue 10: timing-safe cookie-vs-header equality.
// Issue 53/54: cookie maxAge matches the signed-token expiry window.
import crypto from "crypto";
import ApiError from "../utility/ApiError.js";
import requestHandler from "../utility/requestHandeller.js";

const CSRF_SECRET = process.env.ACCESS_TOKEN_SECRET;
if (!CSRF_SECRET) {
  throw new Error(
    "ACCESS_TOKEN_SECRET is required (it also signs CSRF tokens). Add it to your .env."
  );
}
const CSRF_EXPIRY = 2 * 60 * 60 * 1000; // 2 hours

// Issue 3 / 125: single source of truth for prod detection.
export const isProd = () =>
  process.env.NODE_ENV === "production" ||
  process.env.NODE_ENVIRONMENT === "production";

const secureFlag = isProd;

/** Timing-safe equality for two equal-length ASCII strings (hex tokens). */
function timingSafeStringEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function generateToken(req) {
  const salt = crypto.randomBytes(16).toString("hex");
  const timestamp = Date.now();
  const sessionKey = req.cookies.session_id || req.cookies.device_id || "anon";
  const message = `${salt}.${timestamp}.${sessionKey}`;
  const signature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(message)
    .digest("hex");

  return `${salt}.${timestamp}.${sessionKey}.${signature}`;
}

function verifyTokenSignature(token, expectedSessionKey) {
  const parts = token.split(".");
  if (parts.length !== 4) return { valid: false, expired: false };

  const [salt, timestampStr, sessionKey, signature] = parts;
  if (sessionKey !== expectedSessionKey) return { valid: false, expired: false };

  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp)) return { valid: false, expired: false };
  if (Date.now() - timestamp > CSRF_EXPIRY) {
    return { valid: false, expired: true };
  }

  const expectedSignature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(`${salt}.${timestamp}.${sessionKey}`)
    .digest("hex");

  const sigBuf = Buffer.from(signature, "hex");
  const expBuf = Buffer.from(expectedSignature, "hex");
  if (sigBuf.length !== expBuf.length) return { valid: false, expired: false };
  return {
    valid: crypto.timingSafeEqual(sigBuf, expBuf),
    expired: false,
  };
}

export const csrfProtection = requestHandler(async (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const tokenFromCookie = req.cookies["_csrf_token"];
  const tokenFromHeader = req.headers["x-csrf-token"];

  if (
    !tokenFromCookie ||
    !tokenFromHeader ||
    !timingSafeStringEqual(tokenFromCookie, tokenFromHeader)
  ) {
    throw new ApiError(403, "Invalid CSRF Token. Session may have expired.");
  }

  try {
    const sessionKey =
      req.cookies.session_id || req.cookies.device_id || "anon";
    const { valid, expired } = verifyTokenSignature(
      tokenFromHeader,
      sessionKey
    );
    if (!valid) {
      throw new Error(
        expired ? "Token expired" : "Signature or binding invalid"
      );
    }
  } catch {
    throw new ApiError(
      403,
      "CSRF validation failed. Token invalid or expired."
    );
  }

  next();
});

export const generateCsrfToken = (req, res) => {
  const token = generateToken(req);
  res.cookie("_csrf_token", token, {
    httpOnly: true,
    secure: secureFlag(),
    sameSite: "strict",
    path: "/",
    maxAge: CSRF_EXPIRY,
  });
  res.status(200).json({ success: true, csrfToken: token });
};

export const rotateCsrfToken = (req, res) => {
  const token = generateToken(req);
  res.cookie("_csrf_token", token, {
    httpOnly: true,
    secure: secureFlag(),
    sameSite: "strict",
    path: "/",
    maxAge: CSRF_EXPIRY,
  });
  return token;
};

export default csrfProtection;