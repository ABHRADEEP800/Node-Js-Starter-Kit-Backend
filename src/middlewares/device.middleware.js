import crypto from "crypto";

const ensureDeviceId = (req, res, next) => {
  const COOKIE_OPTS = {
    httpOnly: true,
    secure: process.env.NODE_ENVIRONMENT === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 31536000000, // 1 Year
  };

  let deviceId = req.cookies.device_id;

  if (!deviceId) {
    deviceId = crypto.randomBytes(32).toString("hex");
    res.cookie("device_id", deviceId, COOKIE_OPTS);
  }

  // Attach to request for use in auth logic
  req.deviceId = deviceId;
  next();
};

export default ensureDeviceId;
