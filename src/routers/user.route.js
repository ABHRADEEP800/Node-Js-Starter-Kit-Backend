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
} from "../controllers/user.controller.js";
import authMiddleware from "../middlewares/auth.middleware.js";
import ensureDeviceId from "../middlewares/device.middleware.js";
import rateLimit from "express-rate-limit";
import validate from "../middlewares/validate.middleware.js";
import { signupSchema, loginSchema, changePassSchema, changeNameSchema, verify2FASchema, revokeSessionSchema } from "../utility/schemas.js";

const userRouter = express.Router();

userRouter.use(ensureDeviceId);

// Rate Limits
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const twofaLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// Auth Routes
userRouter.route("/login").post(loginLimiter, validate(loginSchema), loginUser);
userRouter.route("/create").post(loginLimiter, validate(signupSchema), registerUser);
userRouter.route("/verify-email").get(verifyEmail);
userRouter.route("/logout").post(authMiddleware(), logoutUser);
userRouter.route("/profile").get(authMiddleware(), getUserProfile);

// 2FA Routes
userRouter.route("/2fa/verify").post(twofaLimiter, validate(verify2FASchema), verify2faToken);
userRouter.route("/2fa/status").get(authMiddleware(), status2fa);
userRouter.route("/2fa/generate").post(authMiddleware(), generate2faSecret);
userRouter.route("/2fa/change").post(authMiddleware(), validate(verify2FASchema), change2faStatus);

// Account Routes
userRouter.route("/change-name").post(authMiddleware(), validate(changeNameSchema), changeName);
userRouter.route("/change-pass").post(authMiddleware(), validate(changePassSchema), changePassword);

// 📱 NEW: DEVICE MANAGEMENT ROUTES
userRouter.route("/sessions").get(authMiddleware(), getActiveSessions); // List devices
userRouter.route("/sessions/revoke").post(authMiddleware(), validate(revokeSessionSchema), revokeSession); // Logout one
userRouter
  .route("/sessions/revoke-all")
  .post(authMiddleware(), revokeOtherSessions); // Logout others

export default userRouter;
