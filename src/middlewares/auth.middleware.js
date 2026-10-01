import crypto from "crypto";
import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import Session from "../models/session.model.js";
import User from "../models/user.model.js";
import { isProd, rotateCsrfToken } from "./csrf.middleware.js";

// ⏳ SECURITY POLICIES
const IDLE_NORMAL = process.env.IDLE_NORMAL
  ? parseInt(process.env.IDLE_NORMAL)
  : 1000 * 60 * 15; // 15 mins default
const IDLE_REMEMBER = process.env.IDLE_REMEMBER
  ? parseInt(process.env.IDLE_REMEMBER)
  : 1000 * 60 * 60 * 24 * 30; // 30 days default
const ROTATION_WINDOW = process.env.ROTATION_WINDOW
  ? parseInt(process.env.ROTATION_WINDOW)
  : 1000 * 60 * 60 * 24; // 1 day default

// Authentication Middleware Usage:
// authMiddleware() (no role restriction)
// authMiddleware(['admin']) (role restriction example)
// authMiddleware(['admin', 'user']) (role restriction example)

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
      res.clearCookie("device_id"); // Issue 35: clear stale device too
      throw new ApiError(401, "Session invalid or expired");
    }

    if (session.status === "PENDING_2FA") {
      throw new ApiError(403, "2FA verification incomplete");
    }

    // 2. SECURITY BINDING CHECKS
    // Issue 26: combine device + UA checks (one DB write instead of two).
    if (session.device_id !== deviceId || session.ua_hash !== uaHash) {
      await Session.findByIdAndUpdate(sessionId, { revoked: true });
      res.clearCookie("session_id");
      res.clearCookie("device_id");
      throw new ApiError(
        401,
        session.device_id !== deviceId
          ? "Device mismatch - Security Alert"
          : "Browser mismatch - Security Alert"
      );
    }

    // 3. IDLE TIMEOUT CHECK
    const now = Date.now();
    const lastSeen = new Date(session.last_seen).getTime();
    const allowedIdle = session.remember ? IDLE_REMEMBER : IDLE_NORMAL;

    if (now - lastSeen > allowedIdle) {
      await Session.findByIdAndUpdate(sessionId, { revoked: true });
      res.clearCookie("session_id");
      res.clearCookie("device_id");
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
        // Carry the display metadata across the rotation; otherwise every
        // rotated session shows "Unknown Browser"/"Unknown OS".
        browser: session.browser,
        os: session.os,
        last_seen: new Date(),
        ip: req.ip,
      });

      // Revoke old
      await Session.findByIdAndDelete(sessionId);

      // Issue New Cookie
      res.cookie("session_id", newSessionId, {
        httpOnly: true,
        secure: isProd(),
        sameSite: "strict",
        path: "/",
        // Issue 5: align cookie lifetime with server-side idle timeout.
        maxAge: session.remember ? IDLE_REMEMBER : IDLE_NORMAL,
      });

      // Update req for phantom token
      req.sessionId = newSessionId;
      // The CSRF token is bound to the session id; rotating the session without
      // rotating the token would break every later write. Reflect the new id on
      // the request AND mint a fresh token bound to it (same response).
      req.cookies.session_id = newSessionId;
      rotateCsrfToken(req, res);
    } else {
      // Just Heartbeat
      await Session.findByIdAndUpdate(sessionId, { last_seen: new Date() });
      req.sessionId = sessionId;
    }

    // 5. ATTACH USER (Phantom Token)
    const user = await User.findById(session.user_id).select("-password");
    if (!user) throw new ApiError(401, "User context lost");

    if (roles.length > 0) {
      if (!roles.includes(user.role)) {
        throw new ApiError(403, "Forbidden");
      }
    }

    // s. 14: once a nominee claim is approved (death/incapacity), the Data
    // Principal's own logins are blocked — only the nominee may act. Admins
    // (role-gated routes) still pass so they can service the account.
    if (user.accountLockedForNominee && user.role !== "admin") {
      throw new ApiError(
        403,
        "This account is being serviced by a nominated person (s. 14). Please contact our Data Protection Officer."
      );
    }

    // s. 8(7): once consent withdrawal has scheduled erasure, stop processing
    // immediately — don't let the user keep using an account that is pending
    // deletion (erasure itself runs on the retention pass).
    if (user.accountStatus === "erasure_pending" && user.role !== "admin") {
      throw new ApiError(
        403,
        "This account is scheduled for erasure. Processing has stopped."
      );
    }

    // DPDP s. 8(8) / Rule 8(1): track the last time the Data Principal
    // approached us so the inactivity erasure clock is accurate. Fire-and-
    // forget; never block the request on this write.
    User.updateOne({ _id: user._id }, { $set: { lastActiveAt: new Date() } }).catch(
      () => {}
    );

    req.user = user;
    next();
  });

/**
 * OPTIONAL authentication. Attaches `req.user` when a valid session exists,
 * but NEVER rejects an unauthenticated request — used by public endpoints that
 * behave differently for a signed-in Data Principal (e.g. cookie consent,
 * which must be scoped to the account once signed in). Invalid/expired
 * sessions are treated as anonymous (no error), so a stale cookie can't block
 * a public action.
 */
export const optionalAuthMiddleware = () =>
  requestHandler(async (req, _res, next) => {
    const sessionId = req.cookies?.session_id;
    if (!sessionId) return next();

    // Apply the SAME device/UA binding as authMiddleware: a stolen session_id
    // cookie alone must not be accepted as an authenticated identity on the
    // cookie-consent endpoints (which write account-scoped records). A mismatch
    // is treated as anonymous, never as an error.
    const deviceId = req.cookies?.device_id;
    const uaHash = crypto
      .createHash("sha256")
      .update(req.headers["user-agent"] || "")
      .digest("hex");

    try {
      const session = await Session.findById(sessionId);
      if (!session || session.revoked || session.status !== "ACTIVE") return next();
      if (session.device_id !== deviceId || session.ua_hash !== uaHash) return next();
      const user = await User.findById(session.user_id).select("-password -twofaCode -backupCodes");
      if (user) req.user = user;
    } catch {
      // Treat any lookup failure as anonymous rather than failing the request.
    }
    return next();
  });

export default authMiddleware;
