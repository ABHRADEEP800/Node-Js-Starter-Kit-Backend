import crypto from "crypto";
import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import Session from "../models/session.model.js";
import User from "../models/user.model.js";

// ⏳ SECURITY POLICIES
const IDLE_NORMAL = process.env.IDLE_NORMAL;
const IDLE_REMEMBER = process.env.IDLE_REMEMBER;
const ROTATION_WINDOW = process.env.ROTATION_WINDOW;

const authMiddleware = (roles = []) =>
  requestHandler(async (req, res, next) => {
    const sessionId = req.cookies.session_id;
    const deviceId = req.cookies.device_id;

    // Hash User Agent to prevent spoofing
    const uaHash = crypto
      .createHash("sha256")
      .update(req.headers["user-agent"] || "")
      .digest("hex");

    if (!sessionId) {
      throw new ApiError(401, "Unauthorized request");
    }

    // 1. Validate Session Exists
    const session = await Session.findById(sessionId);
    if (!session || session.revoked) {
      res.clearCookie("session_id");
      throw new ApiError(401, "Session invalid or expired");
    }

    if (session.status === "PENDING_2FA") {
      throw new ApiError(403, "2FA verification incomplete");
    }

    // 2. SECURITY BINDING CHECKS
    if (session.device_id !== deviceId)
      throw new ApiError(401, "Device mismatch - Security Alert");
    if (session.ua_hash !== uaHash)
      throw new ApiError(401, "Browser mismatch - Security Alert");

    // 3. IDLE TIMEOUT CHECK
    const now = Date.now();
    const lastSeen = new Date(session.last_seen).getTime();
    const allowedIdle = session.remember ? IDLE_REMEMBER : IDLE_NORMAL;

    if (now - lastSeen > allowedIdle) {
      await Session.findByIdAndUpdate(sessionId, { revoked: true });
      res.clearCookie("session_id");
      throw new ApiError(401, "Session timed out");
    }

    // 4. SESSION ROTATION (Anti-Hijacking)
    if (now - lastSeen > ROTATION_WINDOW) {
      const newSessionId = crypto.randomBytes(32).toString("hex");

      // Create fresh session inheriting properties
      await Session.create({
        _id: newSessionId,
        user_id: session.user_id,
        ua_hash: uaHash,
        device_id: deviceId,
        remember: session.remember,
        last_seen: new Date(),
        ip: req.ip,
      });

      // Revoke old
      await Session.findByIdAndDelete(sessionId);

      // Issue New Cookie
      res.cookie("session_id", newSessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/",
        maxAge: session.remember ? 30 * 24 * 60 * 60 * 1000 : undefined, // 30 Days or Session
      });

      // Update req for phantom token
      req.sessionId = newSessionId;
    } else {
      // Just Heartbeat
      await Session.findByIdAndUpdate(sessionId, { last_seen: new Date() });
      req.sessionId = sessionId;
    }

    // 5. ATTACH USER (Phantom Token)
    const user = await User.findById(session.user_id).select(
      "-password -refreshToken"
    );
    if (!user) throw new ApiError(401, "User context lost");


    if (roles.length > 0) {
      if (!roles.includes(user.role)) {
        throw new ApiError(403, "Forbidden");
      }
    }

    req.user = user;
    next();
  });

export default authMiddleware;
