import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    _id: { type: String, required: true }, // Secure ID
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // Security fields
    ua_hash: { type: String, required: true },
    device_id: { type: String, required: true },

    // UI Display fields (New)
    ip: { type: String },
    browser: { type: String },
    os: { type: String },

    remember: { type: Boolean, default: false },
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
