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
} from "../controllers/user.controller.js";
import authMiddleware from "../middlewares/auth.middleware.js";
import ensureDeviceId from "../middlewares/device.middleware.js";
import rateLimit from "express-rate-limit";

const userRouter = express.Router();

userRouter.use(ensureDeviceId);

// Rate Limits
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const twofaLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// Auth Routes
userRouter.route("/login").post(loginLimiter, loginUser);
userRouter.route("/create").post(loginLimiter, registerUser);
userRouter.route("/logout").post(authMiddleware(["user", "admin"]), logoutUser);
userRouter.route("/profile").get(authMiddleware(["user", "admin"]), getUserProfile);

// 2FA Routes
userRouter.route("/2fa/verify").post(twofaLimiter, verify2faToken);
userRouter.route("/2fa/status").get(authMiddleware(["user", "admin"]), status2fa);
userRouter.route("/2fa/generate").post(authMiddleware(["user", "admin"]), generate2faSecret);
userRouter.route("/2fa/change").post(authMiddleware(["user", "admin"]), change2faStatus);

// Account Routes
userRouter.route("/change-name").post(authMiddleware(["user", "admin"]), changeName);
userRouter.route("/change-pass").post(authMiddleware(["user", "admin"]), changePassword);

// 📱 NEW: DEVICE MANAGEMENT ROUTES
userRouter.route("/sessions").get(authMiddleware(["user", "admin"]), getActiveSessions); // List devices
userRouter.route("/sessions/revoke").post(authMiddleware(["user", "admin"]), revokeSession); // Logout one
userRouter
  .route("/sessions/revoke-all")
  .post(authMiddleware(["user", "admin"]), revokeOtherSessions); // Logout others

export default userRouter;
