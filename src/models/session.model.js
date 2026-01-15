import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    _id: { type: String, required: true }, // Secure ID
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    ua_hash: { type: String, required: true },
    device_id: { type: String, required: true },
    ip: { type: String },
    browser: { type: String },
    os: { type: String },
    remember: { type: Boolean, default: false },
    status: { 
      type: String, 
      enum: ["PENDING_2FA", "ACTIVE"], 
      default: "ACTIVE" 
    },
    last_seen: { type: Date, default: Date.now },
    revoked: { type: Boolean, default: false },
  },
  { _id: false, timestamps: true }
);

sessionSchema.index(
  { last_seen: 1 },
  { expireAfterSeconds: 30 * 24 * 60 * 60 }
);

const Session =
  mongoose.models.Session || mongoose.model("Session", sessionSchema);
export default Session;
