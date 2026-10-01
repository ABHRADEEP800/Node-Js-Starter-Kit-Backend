import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import ApiResponse from "../utility/ApiResponse.js";
import verifyRecaptcha from "../utility/verifyRecaptcha.js";
import User from "../models/user.model.js";
import Session from "../models/session.model.js";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import crypto from "crypto";
import { UAParser } from "ua-parser-js";
import zxcvbn from "zxcvbn";
import authEmitter from "../events/auth.events.js";
import { audit } from "../events/auditLog.events.js";
import toUserDTO from "../dto/user.dto.js";
import {
  rotateCsrfToken,
  isProd,
} from "../middlewares/csrf.middleware.js";
import { isChildDob, recordGuardianConsent } from "../services/age.service.js";
import { recordSignupConsents } from "../services/consent.service.js";

// ==========================================
// 🛠️ HELPER: CREATE SECURE SESSION
// ==========================================
// Now accepts 'status' to support PENDING_2FA state
const createSession = async (
  res,
  userId,
  req,
  remember = false,
  status = "ACTIVE"
) => {
  const sessionId = crypto.randomBytes(32).toString("hex");
  const userAgent = req.headers["user-agent"] || "";

  // 1. Generate Security Hash
  const uaHash = crypto.createHash("sha256").update(userAgent).digest("hex");

  // 2. Parse User Agent for UI
  const parser = new UAParser(userAgent);
  const browserName = parser.getBrowser().name || "Unknown Browser";
  const osName = parser.getOS().name || "Unknown OS";

  // 3. Create Session in DB
  await Session.create({
    _id: sessionId,
    user_id: userId,
    ua_hash: uaHash,
    device_id: req.cookies.device_id, // From device middleware
    ip: req.ip,
    browser: browserName,
    os: osName,
    remember: remember,
    status: status, // 👈 KEY: Controls if session is usable
    last_seen: new Date(),
    revoked: false,
  });

  // 4. Set Cookie
  const cookieOptions = {
    httpOnly: true,
    secure: isProd(),
    sameSite: "strict",
    path: "/",
  };

  // If "Remember Me": 30 Days. Else: Session Cookie.
  if (remember) {
    res.cookie("session_id", sessionId, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  } else {
    res.cookie("session_id", sessionId, cookieOptions);
  }

  // IMPORTANT: reflect the new session id on the request so a CSRF token minted
  // later in the SAME handler (rotateCsrfToken) is bound to THIS session — not
  // to the pre-login device_id/anon. Without this, the token is bound to the
  // old key while the browser sends the new session_id, and every subsequent
  // write fails with "CSRF validation failed".
  req.cookies.session_id = sessionId;
};

// ==========================================
// 🚀 AUTHENTICATION CONTROLLERS
// ==========================================

const registerUser = requestHandler(async (req, res) => {
  const {
    firstName,
    lastName,
    username,
    email,
    password,
    recaptchaToken,
    dateOfBirth,
    consentAccepted,
    optionalConsent,
    language,
    guardian,
  } = req.body.user;

  // ---- DPDP s. 6: consent must be an explicit, affirmative act. The schema
  // already enforces `true`; this is defence-in-depth.
  if (consentAccepted !== true)
    throw new ApiError(
      400,
      "Consent to the privacy notice is required before we can create your account (s. 6)."
    );

  if (!recaptchaToken) throw new ApiError(400, "reCAPTCHA token is required");

  await verifyRecaptcha(recaptchaToken);

  if (!firstName || !lastName || !username || !email || !password)
    throw new ApiError(400, "All fields are required");

  const pwdCheck = zxcvbn(password);
  if (pwdCheck.score < 3) {
    throw new ApiError(
      400,
      "Password is too weak. " +
        (pwdCheck.feedback.warning || "Please use a stronger password.")
    );
  }

  const existingUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existingUser) throw new ApiError(400, "User already exists");

  // ---- DPDP s. 9: age gate BEFORE any processing. Unknown age ⇒ treated as a
  // child until verified otherwise (deny-by-default).
  const dob = dateOfBirth ? new Date(dateOfBirth) : null;
  if (!dob || Number.isNaN(dob.getTime()))
    throw new ApiError(400, "A valid date of birth is required (s. 9 age gate).");
  // Reject future dates and implausibly old ones — a future DOB would satisfy
  // the age gate as a (negative-age) child while being obviously invalid.
  if (dob.getTime() > Date.now())
    throw new ApiError(400, "Date of birth cannot be in the future.");
  if (dob.getTime() < new Date("1900-01-01").getTime())
    throw new ApiError(400, "Please enter a valid date of birth.");
  const child = isChildDob(dob);

  // A child may not be onboarded without verifiable parental/guardian consent
  // (s. 9(1), Rule 10). We require the guardian details up front.
  if (child && (!guardian || !guardian.name)) {
    throw new ApiError(
      400,
      "Because you are under 18, verifiable parental/guardian consent is required to create an account (s. 9, Rule 10)."
    );
  }

  // Issue 18 + 42: hash the verification token before storing it (same
// approach as password reset), and set an expiry. The raw token is only
// sent via the email link.
const verificationToken = crypto.randomBytes(32).toString("hex");
const hashedVerificationToken = crypto
  .createHash("sha256")
  .update(verificationToken)
  .digest("hex");

const newUser = await User.create({
    firstName,
    lastName,
    username,
    email,
    password,
    isEmailVerified: false,
    emailVerificationToken: hashedVerificationToken,
    emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    // ---- DPDP fields ----
    dateOfBirth: dob,
    isChild: child,
    telemetryDisabled: true, // deny-by-default; enabled only with analytics consent
    purposeId: "account",
    lawfulBasis: "consent",
    accountStatus: "active",
    lastActiveAt: new Date(),
  });

  audit({
    userId: newUser._id,
    action: "SIGNUP",
    category: "auth",
    purposeId: "account",
    lawfulBasis: "consent",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
  });

  // ---- DPDP s. 6(10): persist the provable consent artefact(s) BEFORE we
  // rely on them. Required purposes always recorded; optional only if opted in.
  await recordSignupConsents({
    userId: newUser._id,
    optionalGranted: Array.isArray(optionalConsent) ? optionalConsent : [],
    req,
    language: language || "en",
  });

  // ---- DPDP s. 9: record verifiable guardian consent for a child.
  if (child) {
    await recordGuardianConsent({
      childUserId: newUser._id,
      relationship: guardian.relationship || "parent",
      guardianName: guardian.name,
      guardianEmail: guardian.email,
      guardianPhone: guardian.phone,
      verificationMethod: guardian.verificationMethod || "voluntarily_provided_identity",
      verifier: "signup-self-attested-with-due-diligence",
    });
  }

  // DO NOT AUTO-LOGIN until email is verified
  authEmitter.emit("userRegistered", {
    email: newUser.email,
    firstName: newUser.firstName,
    lastName: newUser.lastName,
    token: verificationToken,
  });

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        "Registration successful. Please check your email to verify your account.",
        { user: toUserDTO(newUser) }
      )
    );
});

const verifyEmail = requestHandler(async (req, res) => {
  const { token } = req.query;
  if (!token) throw new ApiError(400, "Token is required");

  // Issue 18 + 42: hash the incoming token and look up with an unexpired check.
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: { $gt: new Date() },
  });
  if (!user) throw new ApiError(400, "Invalid or expired token");

  user.isEmailVerified = true;
  user.emailVerificationToken = null;
  user.emailVerificationExpires = null;
  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, "Email verified successfully"));
});

const loginUser = requestHandler(async (req, res) => {
  const { username, email, password, rememberMe } = req.body.user;
  const recaptchaToken = req.body.user.recaptchaToken;

  if (!recaptchaToken) throw new ApiError(400, "reCAPTCHA token is required");

  await verifyRecaptcha(recaptchaToken);

  if (!username && !email)
    throw new ApiError(400, "username or email is required");

  const foundUser = await User.findOne(email ? { email } : { username });
  if (!foundUser) {
    audit({
      action: "LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "User not found",
    });
    throw new ApiError(401, "Invalid credentials");
  }

  if (!foundUser.isEmailVerified) {
    throw new ApiError(403, "Please verify your email before logging in.");
  }

// Check Lockout (Issue 12: explicit Date.now() comparison, not object coercion).
  if (
    foundUser.lockUntil &&
    new Date(foundUser.lockUntil).getTime() > Date.now()
  ) {
    audit({
      userId: foundUser._id,
      action: "LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "Account locked",
    });
    throw new ApiError(
      403,
      "Account is temporarily locked due to too many failed attempts. Try again later."
    );
  }

  const isPasswordValid = await foundUser.isPasswordCorrect(password);
  if (!isPasswordValid) {
    foundUser.failedLoginAttempts += 1;
    // Issue 14: exponential lockout. First lock is 15 min; each subsequent
    // re-lock doubles (capped at 24h). Linear "always 15 min" lets an
    // attacker wait out the lock and try again forever.
    if (foundUser.failedLoginAttempts >= 5) {
      const priorLocks = foundUser.lockUntil && foundUser.lockUntil < new Date()
        ? Math.min(24, (foundUser.failedLoginAttempts / 5))
        : 1;
      const lockMinutes = 15 * priorLocks;
      foundUser.lockUntil = new Date(Date.now() + lockMinutes * 60 * 1000);
    }
    await foundUser.save({ validateBeforeSave: false });
    audit({
      userId: foundUser._id,
      action: "LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "Invalid password",
    });
    throw new ApiError(401, "Invalid credentials");
  }

  // Reset Lockout
  foundUser.failedLoginAttempts = 0;
  foundUser.lockUntil = null;
  // Issue 11: a successful password login should also reset passkey counters,
  // since both gates protect the same account.
  foundUser.failedPasskeyAttempts = 0;
  foundUser.passkeyLockUntil = null;
  await foundUser.save({ validateBeforeSave: false });

  audit({
    userId: foundUser._id,
    action: "LOGIN",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
  });

  // 🔒 2FA CHECK
  if (foundUser.twofa === true) {
    // 1. Create a "PENDING" Session
    // Cookie is set, but user cannot access protected routes yet.
    await createSession(res, foundUser._id, req, rememberMe, "PENDING_2FA");

    const csrfToken = rotateCsrfToken(req, res);
    return res.status(200).json(
      new ApiResponse(200, "2FA verification required", {
        twofaEnabled: true,
        csrfToken,
      })
    );
  }

  // ✅ NORMAL LOGIN (ACTIVE)
  await createSession(res, foundUser._id, req, rememberMe, "ACTIVE");

  // `foundUser` is already saved & current in memory — no need to re-fetch.
  const csrfToken = rotateCsrfToken(req, res);

  return res.status(200).json(
    new ApiResponse(200, "Logged in successfully", {
      user: toUserDTO(foundUser),
      csrfToken,
    })
  );
});

const verify2faToken = requestHandler(async (req, res) => {
  const { code } = req.body;

  // 1. Get Session from Cookie
  const sessionId = req.cookies.session_id;
  if (!sessionId)
    throw new ApiError(401, "Session expired, please login again");

  // 2. Find the Pending Session
  const session = await Session.findById(sessionId);
  if (!session || session.revoked) throw new ApiError(401, "Invalid session");

  // 🛑 STRICT 5-MINUTE CHECK FOR PENDING SESSIONS
  const FIVE_MINUTES = 5 * 60 * 1000;
  const isPending = session.status === "PENDING_2FA";
  const timeElapsed = Date.now() - new Date(session.last_seen).getTime();

  if (isPending && timeElapsed > FIVE_MINUTES) {
    // Expired? Kill it immediately.
    await Session.findByIdAndUpdate(sessionId, { revoked: true });
    res.clearCookie("session_id");
    throw new ApiError(401, "Validation time expired. Please login again.");
  }

  // If already active, just return success
  if (session.status === "ACTIVE") {
    const user = await User.findById(session.user_id).select("-password");
    return res
      .status(200)
      .json(
        new ApiResponse(200, "Already logged in", { user: toUserDTO(user) })
      );
  }

  const user = await User.findById(session.user_id);
  if (!user) throw new ApiError(404, "User not found");

  // Issue 25: validate twofaCode exists before invoking speakeasy — otherwise
  // a deleted/disabled-2FA state produces a confusing 500.
  if (!user.twofaCode) {
    throw new ApiError(400, "2FA is not configured for this account");
  }

  // Per-account lockout: the IP limiter alone is bypassable across many IPs, so
  // a stolen password + PENDING_2FA session must not allow unbounded guessing.
  if (user.twofaLockUntil && user.twofaLockUntil > new Date()) {
    throw new ApiError(429, "Too many invalid 2FA attempts. Please try again later.");
  }

  // 3. Verify OTP or Backup Code
  let is2faValid = speakeasy.totp.verify({
    secret: user.twofaCode,
    encoding: "base32",
    token: code,
  });

  if (!is2faValid) {
    // Issue 43: only consume the single backup code, don't drop the rest.
    const backupIndex = user.backupCodes.indexOf(code);
    if (backupIndex !== -1) {
      is2faValid = true;
      // Issue 13: backup-code use MUST NOT disable 2FA. Mark the code used
      // and let the user regenerate new codes from settings if needed.
      user.backupCodes.splice(backupIndex, 1);
      await user.save({ validateBeforeSave: false });
    }
  }

  if (!is2faValid) {
    // Exponential lockout after 5 failures (15 min, doubling — mirrors login).
    user.failed2faAttempts = (user.failed2faAttempts || 0) + 1;
    if (user.failed2faAttempts >= 5) {
      const priorLocks =
        user.twofaLockUntil && user.twofaLockUntil < new Date()
          ? Math.min(24, user.failed2faAttempts / 5)
          : 1;
      user.twofaLockUntil = new Date(Date.now() + 15 * priorLocks * 60 * 1000);
    }
    await user.save({ validateBeforeSave: false });
    audit({
      userId: user._id,
      action: "2FA_VERIFY",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
    });
    throw new ApiError(401, "Invalid 2FA code");
  }

  // Success: reset the counter/lock.
  user.failed2faAttempts = 0;
  user.twofaLockUntil = null;
  await user.save({ validateBeforeSave: false });

  audit({
    userId: user._id,
    action: "2FA_VERIFY",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
  });

  // ✅ 4. UNLOCK SESSION
  session.status = "ACTIVE";
  await session.save();

  // `user` is already loaded & in-memory — no need to re-fetch.
  const csrfToken = rotateCsrfToken(req, res);

  return res.status(200).json(
    new ApiResponse(200, "Logged in successfully", {
      user: toUserDTO(user),
      csrfToken,
    })
  );
});

const logoutUser = requestHandler(async (req, res) => {
  const sessionId = req.cookies.session_id;

  if (sessionId) {
    await Session.findByIdAndUpdate(sessionId, { revoked: true });
  }

  // The session cookie is being cleared, so the NEW CSRF token must bind to
  // the post-logout key (device_id/anon), not the now-revoked session id.
  delete req.cookies.session_id;
  const csrfToken = rotateCsrfToken(req, res);

  return res
    .status(200)
    .clearCookie("session_id")
    .json(new ApiResponse(200, "User logged out successfully", { csrfToken }));
});

// ==========================================
// 📱 DEVICE MANAGEMENT CONTROLLERS
// ==========================================

const getActiveSessions = requestHandler(async (req, res) => {
  // Find all non-revoked sessions
  const sessions = await Session.find({
    user_id: req.user._id,
    revoked: false,
  }).sort({ last_seen: -1 });

  const currentSessionId = req.cookies.session_id;

  const safeSessions = sessions.map((s) => ({
    id: s._id,
    ip: s.ip,
    browser: s.browser,
    os: s.os,
    lastSeen: s.last_seen,
    isCurrent: s._id === currentSessionId,
    remember: s.remember,
    status: s.status,
  }));

  return res.status(200).json(
    new ApiResponse(200, "Active sessions fetched", {
      sessions: safeSessions,
    })
  );
});

const revokeSession = requestHandler(async (req, res) => {
  const { sessionId } = req.body;
  const currentSessionId = req.cookies.session_id;

  if (sessionId === currentSessionId) {
    throw new ApiError(
      400,
      "Cannot revoke current session. Use logout instead."
    );
  }

  const session = await Session.findOne({
    _id: sessionId,
    user_id: req.user._id,
  });
  if (!session) throw new ApiError(404, "Session not found");

  session.revoked = true;
  await session.save();

  return res
    .status(200)
    .json(new ApiResponse(200, "Device logged out successfully"));
});

const revokeOtherSessions = requestHandler(async (req, res) => {
  const currentSessionId = req.cookies.session_id;

  await Session.updateMany(
    {
      user_id: req.user._id,
      _id: { $ne: currentSessionId },
      revoked: false,
    },
    { revoked: true }
  );

  return res
    .status(200)
    .json(new ApiResponse(200, "All other devices logged out"));
});

// ==========================================
// 👤 PROFILE & SETTINGS CONTROLLERS
// ==========================================

const getUserProfile = requestHandler(async (req, res) => {
  // req.user is guaranteed by authMiddleware()
  return res
    .status(200)
    .json(
      new ApiResponse(200, "User profile fetched", {
        user: toUserDTO(req.user),
      })
    );
});

const status2fa = requestHandler(async (req, res) => {
  const foundUser = await User.findById(req.user._id);
  return res.status(200).json(
    new ApiResponse(200, "2FA status fetched", {
      twofaEnabled: foundUser.twofa === true,
    })
  );
});

const generate2faSecret = requestHandler(async (req, res) => {
  const foundUser = await User.findById(req.user._id);

  const secret = speakeasy.generateSecret({
    name: ` ${process.env.PROJECT_NAME} (${foundUser.email || foundUser.username})`,
  });
  foundUser.twofaCode = secret.base32;
  await foundUser.save({ validateBeforeSave: false });

  const qr = await QRCode.toDataURL(secret.otpauth_url);

  // Keep unused existing codes but CAP the list so repeated calls cannot grow
  // the document without bound (the old code appended 10 every call forever).
  const MAX_BACKUP_CODES = 20;
  const newBackupCodes = Array.from({ length: 10 }, () =>
    crypto.randomBytes(8).toString("hex")
  );
  foundUser.backupCodes = [
    ...(foundUser.backupCodes || []),
    ...newBackupCodes,
  ].slice(-MAX_BACKUP_CODES);
  await foundUser.save({ validateBeforeSave: false });

  return res.status(200).json(
    new ApiResponse(200, "2FA secret generated", {
      qrCode: qr,
      secret: secret.base32,
      backupCodes: newBackupCodes,
    })
  );
});

const change2faStatus = requestHandler(async (req, res) => {
  const { code, enable } = req.body;
  const foundUser = await User.findById(req.user._id);

  // Issue 25: validate secret exists.
  if (!foundUser.twofaCode) {
    throw new ApiError(400, "Generate a 2FA secret first");
  }

  const is2faValid = speakeasy.totp.verify({
    secret: foundUser.twofaCode,
    encoding: "base32",
    token: code,
  });

  if (!is2faValid) throw new ApiError(401, "Invalid 2FA code");

  const newStatus = enable !== undefined ? enable : !foundUser.twofa;
  foundUser.twofa = newStatus;
  await foundUser.save({ validateBeforeSave: false });

  return res.status(200).json(
    new ApiResponse(200, "2FA status changed", {
      twofaEnabled: newStatus === true,
    })
  );
});

const changeName = requestHandler(async (req, res) => {
  const { firstName, lastName } = req.body;
  const foundUser = await User.findById(req.user._id);

  foundUser.firstName = firstName || foundUser.firstName;
  foundUser.lastName = lastName || foundUser.lastName;
  await foundUser.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, "Name updated", { user: toUserDTO(foundUser) }));
});

const changePassword = requestHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const foundUser = await User.findById(req.user._id);

  const isPasswordValid = await foundUser.isPasswordCorrect(currentPassword);
  if (!isPasswordValid) throw new ApiError(401, "Old password is incorrect");

  const pwdCheck = zxcvbn(newPassword);
  if (pwdCheck.score < 3) {
    throw new ApiError(
      400,
      "Password is too weak. " +
        (pwdCheck.feedback.warning || "Please use a stronger password.")
    );
  }

  foundUser.password = newPassword;
  await foundUser.save();

  // Revoke every OTHER active session: a credential change must invalidate
  // sessions established with the old password (matches resetPassword). Keep
  // the caller's current session so they are not logged out of this device.
  const currentSessionId = req.cookies.session_id;
  await Session.updateMany(
    { user_id: foundUser._id, revoked: false, _id: { $ne: currentSessionId } },
    { revoked: true }
  );

  audit({
    userId: foundUser._id,
    action: "PASSWORD_CHANGE",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
  });

  return res
    .status(200)
    .json(new ApiResponse(200, "Password changed successfully"));
});

const forgotPassword = requestHandler(async (req, res) => {
  const { email, recaptchaToken } = req.body;

  if (!recaptchaToken) throw new ApiError(400, "reCAPTCHA token is required");

  await verifyRecaptcha(recaptchaToken);

  if (!email) throw new ApiError(400, "Email is required");

  const user = await User.findOne({ email });

  if (user) {
    const token = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    user.passwordResetToken = hashedToken;
    // Issue 4: store as a Date, not a number, to match the schema type.
    user.passwordResetExpires = new Date(Date.now() + 3600000); // 1 hour
    await user.save({ validateBeforeSave: false });

    // Emit event to send email
    authEmitter.emit("passwordResetRequested", {
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      token,
    });

    audit({
      userId: user._id,
      action: "PASSWORD_RESET_REQUESTED",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "SUCCESS",
    });
  } else {
    // Issue 17: do NOT log the raw email on failure. Anyone with audit-log
    // read access would otherwise be able to enumerate attempted addresses.
    audit({
      action: "PASSWORD_RESET_REQUESTED",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "Password reset requested for non-existent email",
    });
  }

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        "If that email is registered, a password reset link has been sent. Please check your inbox."
      )
    );
});

const resetPassword = requestHandler(async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password)
    throw new ApiError(400, "Token and password are required");

  const pwdCheck = zxcvbn(password);
  if (pwdCheck.score < 3) {
    throw new ApiError(
      400,
      "Password is too weak. " +
        (pwdCheck.feedback.warning || "Please use a stronger password.")
    );
  }

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: new Date() },
  });

  if (!user) {
    throw new ApiError(400, "Invalid or expired password reset token.");
  }

  user.password = password;
  user.passwordResetToken = null;
  user.passwordResetExpires = null;
  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  await user.save();

  // Revoke all active sessions for this user
  await Session.updateMany(
    { user_id: user._id, revoked: false },
    { revoked: true }
  );

  // Emit event to send email
  authEmitter.emit("passwordResetSuccess", {
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
  });

  audit({
    userId: user._id,
    action: "PASSWORD_RESET_COMPLETED",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
  });

  res.clearCookie("session_id");

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        "Password reset successful. You can now login with your new password."
      )
    );
});

const checkUsername = requestHandler(async (req, res) => {
  const { username } = req.query;

  if (!username) {
    throw new ApiError(400, "Username query parameter is required");
  }

  const usernameRegex = /^[a-zA-Z0-9_]+$/;
  if (username.length < 3 || !usernameRegex.test(username)) {
    // Issue 77: 400 HTTP status (not 200) to match the body statusCode.
    return res
      .status(400)
      .json(
        new ApiResponse(400, "Invalid username format", { available: false })
      );
  }

  const existingUser = await User.findOne({ username: username.toLowerCase() });

  if (existingUser) {
    return res
      .status(200)
      .json(
        new ApiResponse(200, "Username is already taken", { available: false })
      );
  }

  return res
    .status(200)
    .json(new ApiResponse(200, "Username is available", { available: true }));
});

const checkEmail = requestHandler(async (req, res) => {
  const { email } = req.query;

  if (!email) {
    throw new ApiError(400, "Email query parameter is required");
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res
      .status(400)
      .json(new ApiResponse(400, "Invalid email format", { available: false }));
  }

  const existingUser = await User.findOne({ email: email.toLowerCase() });

  if (existingUser) {
    return res.status(200).json(
      new ApiResponse(200, "Email is already registered", {
        available: false,
      })
    );
  }

  return res
    .status(200)
    .json(new ApiResponse(200, "Email is available", { available: true }));
});

export {
  registerUser,
  loginUser,
  logoutUser,
  verify2faToken,
  getActiveSessions,
  revokeSession,
  revokeOtherSessions,
  verifyEmail,
  getUserProfile,
  status2fa,
  generate2faSecret,
  change2faStatus,
  changeName,
  changePassword,
  forgotPassword,
  resetPassword,
  checkUsername,
  checkEmail,
};
