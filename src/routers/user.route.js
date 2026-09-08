import express from "express";
import {
  loginUser,
  logoutUser,
  getUserProfile,
  verify2faToken,
  status2fa,
  generate2faSecret,
  change2faStatus,
  registerUser,
  changeName,
  changePassword,

  // New Imports
  getActiveSessions,
  revokeSession,
  revokeOtherSessions,
  verifyEmail,
  forgotPassword,
  resetPassword,
  checkUsername,
  checkEmail,
} from "../controllers/user.controller.js";
import authMiddleware from "../middlewares/auth.middleware.js";
import rateLimit from "express-rate-limit";
import validate from "../middlewares/validate.middleware.js";
import {
  signupSchema,
  loginSchema,
  changePassSchema,
  changeNameSchema,
  verify2FASchema,
  revokeSessionSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  passkeyRegisterOptionsSchema,
  passkeyRegisterVerifySchema,
  passkeyLoginOptionsSchema,
  passkeyLoginVerifySchema,
} from "../utility/schemas.js";
import {
  getPasskeyLoginOptions,
  verifyPasskeyLogin,
  getPasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  listPasskeys,
  deletePasskey,
} from "../controllers/passkey.controller.js";

const userRouter = express.Router();

// ensureDeviceId is now registered globally in app.js so the device_id cookie
// exists before CSRF tokens are minted.

// Rate Limits
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const twofaLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const passwordResetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
const checkLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 60 });

// Auth Routes
userRouter.route("/check-username").get(checkLimiter, checkUsername);
userRouter.route("/check-email").get(checkLimiter, checkEmail);
userRouter.route("/login").post(loginLimiter, validate(loginSchema), loginUser);
userRouter
  .route("/create")
  .post(loginLimiter, validate(signupSchema), registerUser);
userRouter.route("/verify-email").get(verifyEmail);
userRouter
  .route("/forgot-password")
  .post(passwordResetLimiter, validate(forgotPasswordSchema), forgotPassword);
userRouter
  .route("/reset-password")
  .post(passwordResetLimiter, validate(resetPasswordSchema), resetPassword);
userRouter.route("/logout").post(authMiddleware(), logoutUser);
userRouter.route("/profile").get(authMiddleware(), getUserProfile);

// 2FA Routes
userRouter
  .route("/2fa/verify")
  .post(twofaLimiter, validate(verify2FASchema), verify2faToken);
userRouter.route("/2fa/status").get(authMiddleware(), status2fa);
userRouter.route("/2fa/generate").post(authMiddleware(), generate2faSecret);
userRouter
  .route("/2fa/change")
  .post(authMiddleware(), validate(verify2FASchema), change2faStatus);

// Account Routes
userRouter
  .route("/change-name")
  .post(authMiddleware(), validate(changeNameSchema), changeName);
userRouter
  .route("/change-pass")
  .post(authMiddleware(), validate(changePassSchema), changePassword);

// 📱 NEW: DEVICE MANAGEMENT ROUTES
userRouter.route("/sessions").get(authMiddleware(), getActiveSessions); // List devices
userRouter
  .route("/sessions/revoke")
  .post(authMiddleware(), validate(revokeSessionSchema), revokeSession); // Logout one
userRouter
  .route("/sessions/revoke-all")
  .post(authMiddleware(), revokeOtherSessions); // Logout others

// 🔑 NEW: PASSKEY (WEBAUTHN) ROUTES
// Registration & management require an authenticated session; login is public
// but rate-limited (generating options is where a bot would probe for users).
const passkeyLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

userRouter.route("/passkey/list").get(authMiddleware(), listPasskeys);
userRouter
  .route("/passkey/register/options")
  .post(
    authMiddleware(),
    validate(passkeyRegisterOptionsSchema),
    getPasskeyRegistrationOptions
  );
userRouter
  .route("/passkey/register/verify")
  .post(
    authMiddleware(),
    validate(passkeyRegisterVerifySchema),
    verifyPasskeyRegistration
  );
userRouter
  .route("/passkey/login/options")
  .post(
    passkeyLoginLimiter,
    validate(passkeyLoginOptionsSchema),
    getPasskeyLoginOptions
  );
userRouter
  .route("/passkey/login/verify")
  .post(
    passkeyLoginLimiter,
    validate(passkeyLoginVerifySchema),
    verifyPasskeyLogin
  );
userRouter.route("/passkey/:id").delete(authMiddleware(), deletePasskey);

export default userRouter;
