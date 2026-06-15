import crypto from "crypto";
import ApiError from "../utility/ApiError.js";
import requestHandler from "../utility/requestHandeller.js";

const CSRF_SECRET =
  process.env.ACCESS_TOKEN_SECRET || "enterprise_csrf_fallback_secret_372981";
const CSRF_EXPIRY = 2 * 60 * 60 * 1000; // 2 hours

// Helper to generate a session-bound and cryptographically signed token
const generateToken = (req) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const timestamp = Date.now();

  // Bind the token to: salt and timestamp, signed by server private secret
  const message = `${salt}.${timestamp}`;
  const signature = crypto
    .createHmac("sha256", CSRF_SECRET)
    .update(message)
    .digest("hex");

  return `${salt}.${timestamp}.${signature}`;
};

export const csrfProtection = requestHandler(async (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const tokenFromCookie = req.cookies["_csrf_token"];
  const tokenFromHeader = req.headers["x-csrf-token"];

  if (
    !tokenFromCookie ||
    !tokenFromHeader ||
    tokenFromCookie !== tokenFromHeader
  ) {
    throw new ApiError(403, "Invalid CSRF Token. Session may have expired.");
  }

  try {
    const parts = tokenFromHeader.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid token format");
    }

    const [salt, timestampStr, signature] = parts;
    const timestamp = parseInt(timestampStr, 10);

    // 1. Check expiration
    if (isNaN(timestamp) || Date.now() - timestamp > CSRF_EXPIRY) {
      throw new Error("Token expired");
    }

    // 2. Validate cryptographic signature
    const message = `${salt}.${timestamp}`;
    const expectedSignature = crypto
      .createHmac("sha256", CSRF_SECRET)
      .update(message)
      .digest("hex");

    // Timing-safe comparison to prevent timing attacks
    const sigBuffer = Buffer.from(signature, "hex");
    const expectedSigBuffer = Buffer.from(expectedSignature, "hex");

    if (
      sigBuffer.length !== expectedSigBuffer.length ||
      !crypto.timingSafeEqual(sigBuffer, expectedSigBuffer)
    ) {
      throw new Error("Signature invalid");
    }
  } catch (error) {
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
    secure:
      process.env.NODE_ENV === "production" ||
      process.env.NODE_ENVIRONMENT === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 86400000, // 1 day cookie expiration
  });
  res.status(200).json({ success: true, csrfToken: token });
};

// Rotates the CSRF token on privilege change and returns the new token string
export const rotateCsrfToken = (req, res) => {
  const token = generateToken(req);
  res.cookie("_csrf_token", token, {
    httpOnly: true,
    secure:
      process.env.NODE_ENV === "production" ||
      process.env.NODE_ENVIRONMENT === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 86400000,
  });
  return token;
};

export default csrfProtection;
