import crypto from "crypto";
import ApiError from "../utility/ApiError.js";
import requestHandler from "../utility/requestHandeller.js"; // Note: file is requestHandeller.js in starter Kit

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

  next();
});

export const generateCsrfToken = (req, res) => {
  const token = crypto.randomBytes(32).toString("hex");
  res.cookie("_csrf_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" || process.env.NODE_ENVIRONMENT === "production",
    sameSite: "strict", 
    path: "/",
    maxAge: 86400000, // 1 day
  });
  res.status(200).json({ success: true, csrfToken: token });
};

export default csrfProtection;
