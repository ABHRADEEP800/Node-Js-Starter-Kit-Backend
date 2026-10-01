import express from "express";
import rateLimit from "express-rate-limit";
import { baseRateLimitOptions } from "../config/rateLimit.config.js";
import validate from "../middlewares/validate.middleware.js";
import { optionalAuthMiddleware } from "../middlewares/auth.middleware.js";
import { cookieConsentSchema, cookieWithdrawSchema } from "../utility/schemas.js";
import {
  getCookieState,
  postCookieConsent,
  withdrawCookie,
} from "../controllers/cookie.controller.js";

// Domain 8 cookie-consent surfaces. Public — an anonymous visitor can decide
// before signing in. `optionalAuthMiddleware` attaches the user when signed in
// so consent is scoped to the account (never shared across users on one
// browser), without rejecting anonymous visitors. Rate-limited as a public write.
const cookieRouter = express.Router();
const cookieLimiter = rateLimit({ ...baseRateLimitOptions, windowMs: 15 * 60 * 1000, max: 60 });
const maybeAuth = optionalAuthMiddleware();

cookieRouter.route("/").get(cookieLimiter, maybeAuth, getCookieState);
cookieRouter
  .route("/consent")
  .post(cookieLimiter, maybeAuth, validate(cookieConsentSchema), postCookieConsent);
cookieRouter
  .route("/withdraw")
  .post(cookieLimiter, maybeAuth, validate(cookieWithdrawSchema), withdrawCookie);

export default cookieRouter;
