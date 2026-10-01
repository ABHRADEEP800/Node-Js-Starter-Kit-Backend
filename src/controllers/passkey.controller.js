import crypto from "crypto";
import { UAParser } from "ua-parser-js";
import requestHandler from "../utility/requestHandeller.js";
import ApiError from "../utility/ApiError.js";
import ApiResponse from "../utility/ApiResponse.js";
import verifyRecaptcha from "../utility/verifyRecaptcha.js";
import User from "../models/user.model.js";
import Session from "../models/session.model.js";
import Passkey from "../models/passkey.model.js";
import WebAuthnChallenge from "../models/webauthnChallenge.model.js";
import toPasskeyDTO from "../dto/passkey.dto.js";
import toUserDTO from "../dto/user.dto.js";
import { passkeyConfig } from "../utility/passkey.config.js";
import { audit } from "../events/auditLog.events.js";
import { rotateCsrfToken } from "../middlewares/csrf.middleware.js";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import {
  isoBase64URL,
  decodeClientDataJSON,
} from "@simplewebauthn/server/helpers";
import { passkeyDeleteSchema } from "../utility/schemas.js";
import { isProd } from "../middlewares/csrf.middleware.js";

const { rpID, rpName, origin, challengeTtlMs } = passkeyConfig;

const isSecureContext = isProd;

// ==========================================
// 🤖 HELPERS
// ==========================================

// Writes a fresh, single-use, expiring challenge bound to user/session/RP.
const storeChallenge = async (type, challenge, { userId, sessionId }) => {
  if (!challenge) throw new ApiError(500, "Failed to generate challenge");
  await WebAuthnChallenge.create({
    challenge,
    type,
    userId: userId || null,
    sessionId: sessionId || null,
    expectedRPID: rpID,
    expectedOrigin: origin,
    expiresAt: new Date(Date.now() + challengeTtlMs),
  });
};

// Mirrors user.controller.js createSession so passkey logins get the exact
// same hardened session cookie (httpOnly, sameSite=strict, device+UA bound).
const createSession = async (
  res,
  userId,
  req,
  remember = false,
  status = "ACTIVE"
) => {
  const sessionId = crypto.randomBytes(32).toString("hex");
  const userAgent = req.headers["user-agent"] || "";
  const uaHash = crypto.createHash("sha256").update(userAgent).digest("hex");

  // Parse the real User-Agent so active-session listings show the actual
  // browser/OS (same as user.controller.createSession), not a placeholder.
  const parser = new UAParser(userAgent);
  const browserName = parser.getBrowser().name || "Unknown Browser";
  const osName = parser.getOS().name || "Unknown OS";

  await Session.create({
    _id: sessionId,
    user_id: userId,
    ua_hash: uaHash,
    device_id: req.cookies.device_id,
    ip: req.ip,
    browser: browserName,
    os: osName,
    remember,
    status,
    last_seen: new Date(),
    revoked: false,
  });

  const cookieOptions = {
    httpOnly: true,
    secure: isSecureContext(),
    sameSite: "strict",
    path: "/",
  };
  if (remember) {
    res.cookie("session_id", sessionId, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });
  } else {
    res.cookie("session_id", sessionId, cookieOptions);
  }

  // Reflect the new session id on the request so a CSRF token minted later in
  // the same handler binds to THIS session (see user.controller.createSession).
  req.cookies.session_id = sessionId;
};

// ==========================================
// 🚀 PASSKEY LOGIN (authentication) CONTROLLERS
// ==========================================

const getPasskeyLoginOptions = requestHandler(async (req, res) => {
  const { identifier, recaptchaToken } = req.body;

  // Issue 31/32: AWAIT reCAPTCHA before minting the challenge. The previous
  // fire-and-forget pattern let bots bypass reCAPTCHA entirely — the login
  // still worked if the user had a real passkey. Now we block the request
  // until reCAPTCHA confirms.
  try {
    await verifyRecaptcha(recaptchaToken);
  } catch {
    audit({
      action: "PASSKEY_LOGIN_OPTIONS_RECAPTCHA_FAILED",
      status: "FAILED",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });
    throw new ApiError(400, "reCAPTCHA verification failed");
  }

  // Never reveal whether the identifier maps to an account: a missing/wrong
  // user simply yields an empty allow-list, so the browser shows no passkeys.
  let user = null;
  if (identifier) {
    const term = identifier.toLowerCase();
    user = await User.findOne({
      $or: [{ username: term }, { email: term }],
    });
  }

  let allowCredentials = [];
  if (user) {
    const passkeys = await Passkey.find({ user_id: user._id });
    allowCredentials = passkeys.map((pk) => ({
      id: pk.credential_id,
      transports: pk.transports,
    }));
  }

  const options = await generateAuthenticationOptions({
    rpID,
    timeout: 120000,
    allowCredentials,
    userVerification: "preferred",
  });

  await storeChallenge("login", options.challenge, {
    userId: user?._id,
    sessionId: req.cookies.session_id || null,
  });

  return res
    .status(200)
    .json(new ApiResponse(200, "Passkey login options generated", options));
});

const verifyPasskeyLogin = requestHandler(async (req, res) => {
  const { response } = req.body;

  // 1. Pull the challenge out of the signed data we actually received.
  let clientData;
  try {
    clientData = decodeClientDataJSON(response?.response?.clientDataJSON);
  } catch {
    throw new ApiError(400, "Invalid authentication response");
  }

  // 2. Single-use challenge lookup + consume atomically.
  const stored = await WebAuthnChallenge.findOneAndDelete({
    challenge: clientData.challenge,
    type: "login",
  });
  if (!stored) {
    audit({
      action: "PASSKEY_LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "Unknown or replayed challenge",
    });
    throw new ApiError(400, "Authentication challenge invalid or expired");
  }

  // 3. Resolve the credential to its user.
  const passkey = await Passkey.findOne({ credential_id: response.id });
  if (!passkey) {
    audit({
      action: "PASSKEY_LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "Credential not registered",
    });
    throw new ApiError(400, "This passkey is not registered");
  }

  const user = await User.findById(passkey.user_id);
  if (!user) throw new ApiError(401, "User account not found");

  // Issue 11: per-user passkey lockout. The IP-based limiter alone is
  // bypassable across many IPs; this caps attempts against the account itself.
  if (user.passkeyLockUntil && user.passkeyLockUntil > new Date()) {
    audit({
      userId: user._id,
      action: "PASSKEY_LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "Account passkey-locked",
    });
    throw new ApiError(
      403,
      "Account temporarily locked due to too many failed passkey attempts."
    );
  }

  // 4. Strict origin/RP verification (replay of a cross-origin assertion fails).
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: stored.challenge,
    expectedOrigin: stored.expectedOrigin,
    expectedRPID: stored.expectedRPID,
    // Options are generated with `userVerification: "preferred"`, so the
    // assertion may legitimately carry UV=0 (the user/authenticator chose not
    // to prompt). Requiring UV here would throw "User verification required"
    // for valid credentials, so keep verification aligned with that preference.
    requireUserVerification: false,
    credential: {
      id: passkey.credential_id,
      publicKey: isoBase64URL.toBuffer(passkey.public_key),
      counter: passkey.counter,
      transports: passkey.transports,
    },
  });

  if (!verification.verified) {
    // Issue 11: increment per-user passkey failure counter.
    user.failedPasskeyAttempts = (user.failedPasskeyAttempts || 0) + 1;
    if (user.failedPasskeyAttempts >= 5) {
      user.passkeyLockUntil = new Date(Date.now() + 15 * 60 * 1000);
      user.failedPasskeyAttempts = 0; // reset after lock triggers
    }
    await user.save({ validateBeforeSave: false });
    audit({
      userId: user._id,
      action: "PASSKEY_LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
    });
    throw new ApiError(401, "Passkey authentication failed");
  }

  const { authenticationInfo } = verification;

  // Issue 7: a multi-device (synced) passkey's counter can legitimately reset.
  // Pick the device-type for the counter check from the latest assertion, not
  // the stored value, so a single→multi upgrade doesn't apply the wrong rule.
  const effectiveDeviceType =
    authenticationInfo.credentialDeviceType || passkey.credential_device_type;

  // 5. Clone/replay detection: a single-device passkey's usage counter must
  //    strictly increase. A stall/drop signals the key may have been copied.
  if (
    effectiveDeviceType === "singleDevice" &&
    authenticationInfo.newCounter <= passkey.counter
  ) {
    audit({
      userId: user._id,
      action: "PASSKEY_LOGIN",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
      details: "Possible cloned credential (counter did not advance)",
    });
    throw new ApiError(
      403,
      "This passkey may have been cloned. Please re-register it."
    );
  }

  passkey.counter = authenticationInfo.newCounter;
  passkey.credential_device_type =
    authenticationInfo.credentialDeviceType || passkey.credential_device_type;
  passkey.last_used_at = new Date();
  await passkey.save({ validateBeforeSave: false });

  audit({
    userId: user._id,
    action: "PASSKEY_LOGIN",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
  });

  // Issue 11: reset passkey failure counter on successful login.
  user.failedPasskeyAttempts = 0;
  user.passkeyLockUntil = null;
  await user.save({ validateBeforeSave: false });

  // 6. Enforce 2FA the same way password login does.
  if (user.twofa === true) {
    await createSession(res, user._id, req, false, "PENDING_2FA");
    const csrfToken = rotateCsrfToken(req, res);
    return res.status(200).json(
      new ApiResponse(200, "2FA verification required", {
        twofaEnabled: true,
        csrfToken,
      })
    );
  }

  await createSession(res, user._id, req, req.body.rememberMe || false);

  const csrfToken = rotateCsrfToken(req, res);

  return res.status(200).json(
    new ApiResponse(200, "Logged in with passkey successfully", {
      user: toUserDTO(user),
      csrfToken,
    })
  );
});

// ==========================================
// 🔑 PASSKEY REGISTRATION CONTROLLERS (auth)
// ==========================================

const getPasskeyRegistrationOptions = requestHandler(async (req, res) => {
  const { name } = req.body;

  const existing = await Passkey.find({ user_id: req.user._id });
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: req.user.username,
    userDisplayName: `${req.user.firstName} ${req.user.lastName}`.trim(),
    timeout: 120000,
    attestationType: "none",
    excludeCredentials: existing.map((pk) => ({
      id: pk.credential_id,
      transports: pk.transports,
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  await storeChallenge("register", options.challenge, {
    userId: req.user._id,
    sessionId: req.cookies.session_id,
  });

  // Send the name back so the client uses it in the verify step. The real
  // verification still reads `name` from the (authenticated) verify body.
  return res.status(200).json(
    new ApiResponse(200, "Passkey registration options generated", {
      ...options,
      passkeyName: name,
    })
  );
});

const verifyPasskeyRegistration = requestHandler(async (req, res) => {
  const { name, response } = req.body;

  if (!name || !name.trim())
    throw new ApiError(400, "Passkey name is required");

  let clientData;
  try {
    clientData = decodeClientDataJSON(response?.response?.clientDataJSON);
  } catch {
    throw new ApiError(400, "Invalid registration response");
  }

  const stored = await WebAuthnChallenge.findOneAndDelete({
    challenge: clientData.challenge,
    type: "register",
    userId: req.user._id,
    sessionId: req.cookies.session_id,
  });
  if (!stored) {
    throw new ApiError(400, "Registration challenge invalid or expired");
  }

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: stored.challenge,
    expectedOrigin: stored.expectedOrigin,
    expectedRPID: stored.expectedRPID,
    requireUserVerification: false,
  });

  if (!verification.verified || !verification.registrationInfo) {
    audit({
      userId: req.user._id,
      action: "PASSKEY_REGISTER",
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      status: "FAILED",
    });
    throw new ApiError(400, "Passkey registration failed");
  }

  const { credentialDeviceType, credential } = verification.registrationInfo;

  const credentialIdB64 = credential.id;
  const credentialPublicKey = credential.publicKey;
  const counter = credential.counter;

  const duplicate = await Passkey.findOne({ credential_id: credentialIdB64 });
  if (duplicate) throw new ApiError(400, "This passkey is already registered");

  const passkey = await Passkey.create({
    user_id: req.user._id,
    name: name.trim(),
    credential_id: credentialIdB64,
    public_key: isoBase64URL.fromBuffer(credentialPublicKey),
    counter,
    transports: response?.response?.transports || [],
    credential_device_type: credentialDeviceType || "singleDevice",
    last_used_at: null,
  });

  audit({
    userId: req.user._id,
    action: "PASSKEY_REGISTER",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
    details: `Registered "${passkey.name}"`,
  });

  return res.status(201).json(
    new ApiResponse(201, "Passkey registered successfully", {
      passkey: toPasskeyDTO(passkey),
    })
  );
});

// ==========================================
// 🗂️ PASSKEY MANAGEMENT CONTROLLERS (auth)
// ==========================================

const listPasskeys = requestHandler(async (req, res) => {
  const passkeys = await Passkey.find({ user_id: req.user._id }).sort({
    createdAt: -1,
  });
  return res.status(200).json(
    new ApiResponse(200, "Passkeys fetched", {
      passkeys: passkeys.map(toPasskeyDTO),
    })
  );
});

const deletePasskey = requestHandler(async (req, res) => {
  const { id } = passkeyDeleteSchema.parse(req.params);

  // Scoped by owner to harden against IDOR.
  const passkey = await Passkey.findOneAndDelete({
    _id: id,
    user_id: req.user._id,
  });
  if (!passkey) throw new ApiError(404, "Passkey not found");

  audit({
    userId: req.user._id,
    action: "PASSKEY_DELETE",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    status: "SUCCESS",
    details: `Removed "${passkey.name}"`,
  });

  return res
    .status(200)
    .json(new ApiResponse(200, "Passkey removed successfully"));
});

export {
  getPasskeyLoginOptions,
  verifyPasskeyLogin,
  getPasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  listPasskeys,
  deletePasskey,
};
