import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import ApiResponse from "../utility/ApiResponse.js";
import User from "../models/user.model.js";
import Session from "../models/session.model.js";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import crypto from "crypto";
import { UAParser } from "ua-parser-js"; // Fixed Import

// ==========================================
// 🛠️ HELPER: CREATE SECURE SESSION
// ==========================================
// Now accepts 'status' to support PENDING_2FA state
const createSession = async (res, userId, req, remember = false, status = "ACTIVE") => {
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
    revoked: false
  });

  // 4. Set Cookie
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/"
  };

  // If "Remember Me": 30 Days. Else: Session Cookie.
  if (remember) {
    res.cookie("session_id", sessionId, { 
      ...cookieOptions, 
      maxAge: 30 * 24 * 60 * 60 * 1000 
    });
  } else {
    res.cookie("session_id", sessionId, cookieOptions);
  }
};

// ==========================================
// 🚀 AUTHENTICATION CONTROLLERS
// ==========================================

const registerUser = requestHandler(async (req, res) => {
  const { fullName, username, email, password, recaptchaToken } = req.body.user;

  if (!recaptchaToken) throw new ApiError(400, "reCAPTCHA token is required");
  
  const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`;
  const data = await fetch(verifyURL, { method: "POST" }).then((res) => res.json());

  if (!data.success || data.score < 0.5) throw new ApiError(400, "reCAPTCHA verification failed");

  if (!fullName || !username || !email || !password) throw new ApiError(400, "All fields are required");

  const existingUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existingUser) throw new ApiError(400, "User already exists");

  const newUser = await User.create({ fullName, username, email, password });

  // Auto-login (ACTIVE status)
  await createSession(res, newUser._id, req, false, "ACTIVE");

  const createdUser = await User.findById(newUser._id).select("-password -refreshToken");

  return res.status(201).json(
    new ApiResponse(201, "Registered successfully", { user: createdUser })
  );
});

const loginUser = requestHandler(async (req, res) => {
  const { username, email, password, rememberMe } = req.body.user;
  const recaptchaToken = req.body.user.recaptchaToken;

  if (!recaptchaToken) throw new ApiError(400, "reCAPTCHA token is required");
  
  const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`;
  const data = await fetch(verifyURL, { method: "POST" }).then((res) => res.json());

  if (!data.success || data.score < 0.5) throw new ApiError(400, "reCAPTCHA verification failed");

  if (!username && !email) throw new ApiError(400, "username or email is required");

  const foundUser = await User.findOne(email ? { email } : { username });
  if (!foundUser) throw new ApiError(404, "User not found");

  const isPasswordValid = await foundUser.isPasswordCorrect(password);
  if (!isPasswordValid) throw new ApiError(401, "Invalid credentials");

  // 🔒 2FA CHECK
  if (foundUser.twofa === true) {
    // 1. Create a "PENDING" Session
    // Cookie is set, but user cannot access protected routes yet.
    await createSession(res, foundUser._id, req, rememberMe, "PENDING_2FA");

    return res.status(200).json(
      new ApiResponse(200, "2FA verification required", {
        twofaEnabled: true,
        // No temporary token needed! The cookie acts as the handle.
      })
    );
  }

  // ✅ NORMAL LOGIN (ACTIVE)
  await createSession(res, foundUser._id, req, rememberMe, "ACTIVE");

  const loggedInUser = await User.findById(foundUser._id).select("-password -refreshToken");

  return res.status(200).json(
    new ApiResponse(200, "Logged in successfully", { user: loggedInUser })
  );
});

const verify2faToken = requestHandler(async (req, res) => {
  const { code } = req.body;
  
  // 1. Get Session from Cookie
  const sessionId = req.cookies.session_id;
  if (!sessionId) throw new ApiError(401, "Session expired, please login again");

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
    return res.status(200).json(new ApiResponse(200, "Already logged in", { user }));
  }

  const user = await User.findById(session.user_id);
  if (!user) throw new ApiError(404, "User not found");

  // 3. Verify OTP
  const is2faValid = speakeasy.totp.verify({
    secret: user.twofaCode,
    encoding: "base32",
    token: code,
  });

  if (!is2faValid) throw new ApiError(401, "Invalid 2FA code");

  // ✅ 4. UNLOCK SESSION
  session.status = "ACTIVE";
  await session.save();

  const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

  return res.status(200).json(
    new ApiResponse(200, "Logged in successfully", { user: loggedInUser })
  );
});

const logoutUser = requestHandler(async (req, res) => {
  const sessionId = req.cookies.session_id;

  if (sessionId) {
    await Session.findByIdAndUpdate(sessionId, { revoked: true });
  }

  return res
    .status(200)
    .clearCookie("session_id")
    .json(new ApiResponse(200, "User logged out successfully"));
});

// ==========================================
// 📱 DEVICE MANAGEMENT CONTROLLERS
// ==========================================

const getActiveSessions = requestHandler(async (req, res) => {
  // Find all non-revoked sessions
  const sessions = await Session.find({ 
    user_id: req.user._id, 
    revoked: false 
  }).sort({ last_seen: -1 });

  const currentSessionId = req.cookies.session_id;

  const safeSessions = sessions.map(s => ({
    id: s._id,
    ip: s.ip,
    browser: s.browser,
    os: s.os,
    lastSeen: s.last_seen,
    isCurrent: s._id === currentSessionId,
    remember: s.remember,
    status: s.status 
  }));

  return res.status(200).json(
    new ApiResponse(200, "Active sessions fetched", { sessions: safeSessions })
  );
});

const revokeSession = requestHandler(async (req, res) => {
  const { sessionId } = req.body;
  const currentSessionId = req.cookies.session_id;

  if (sessionId === currentSessionId) {
    throw new ApiError(400, "Cannot revoke current session. Use logout instead.");
  }

  const session = await Session.findOne({ _id: sessionId, user_id: req.user._id });
  if (!session) throw new ApiError(404, "Session not found");

  session.revoked = true;
  await session.save();

  return res.status(200).json(new ApiResponse(200, "Device logged out successfully"));
});

const revokeOtherSessions = requestHandler(async (req, res) => {
  const currentSessionId = req.cookies.session_id;

  await Session.updateMany(
    { 
      user_id: req.user._id, 
      _id: { $ne: currentSessionId }, 
      revoked: false 
    },
    { revoked: true }
  );

  return res.status(200).json(new ApiResponse(200, "All other devices logged out"));
});

// ==========================================
// 👤 PROFILE & SETTINGS CONTROLLERS
// ==========================================

const getUserProfile = requestHandler(async (req, res) => {
  const user = req.user || {}; 
  const sanitized = user.toObject ? user.toObject() : user;
  delete sanitized.password;
  delete sanitized.refreshToken;

  return res.status(200).json(
    new ApiResponse(200, "User profile fetched", { user: sanitized })
  );
});

const status2fa = requestHandler(async (req, res) => {
  const foundUser = await User.findById(req.user._id);
  return res.status(200).json(
    new ApiResponse(200, "2FA status fetched", { twofaEnabled: foundUser.twofa === true })
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

  return res.status(200).json(
    new ApiResponse(200, "2FA secret generated", { qrCode: qr, secret: secret.base32 })
  );
});

const change2faStatus = requestHandler(async (req, res) => {
  const code = req.body.code;
  const foundUser = await User.findById(req.user._id);

  const is2faValid = speakeasy.totp.verify({
    secret: foundUser.twofaCode,
    encoding: "base32",
    token: code,
  });

  if (!is2faValid) throw new ApiError(401, "Invalid 2FA code");
  
  const newStatus = !foundUser.twofa;
  foundUser.twofa = newStatus;
  await foundUser.save({ validateBeforeSave: false });

  return res.status(200).json(
    new ApiResponse(200, "2FA status changed", { twofaEnabled: newStatus === true })
  );
});

const changeName = requestHandler(async (req, res) => {
  const { fullName } = req.body;
  const foundUser = await User.findById(req.user._id);
  
  foundUser.fullName = fullName || foundUser.fullName;
  await foundUser.save({ validateBeforeSave: false });
  
  return res.status(200).json(new ApiResponse(200, "Name updated", { user: foundUser }));
});

const changePassword = requestHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const foundUser = await User.findById(req.user._id);

  const isPasswordValid = await foundUser.isPasswordCorrect(currentPassword);
  if (!isPasswordValid) throw new ApiError(401, "Old password is incorrect");
  
  foundUser.password = newPassword;
  await foundUser.save();

  return res.status(200).json(new ApiResponse(200, "Password changed successfully"));
});

export {
  registerUser,
  loginUser,
  logoutUser,
  verify2faToken,
  getActiveSessions,
  revokeSession,
  revokeOtherSessions,
  getUserProfile,
  status2fa,
  generate2faSecret,
  change2faStatus,
  changeName,
  changePassword
};