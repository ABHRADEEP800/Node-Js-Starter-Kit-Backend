import mongoose from "mongoose";

// ==========================================
// 🔑 PASSKEY (WEBAUTHN CREDENTIAL) MODEL
// ==========================================
// Only the public key + credential ID are ever stored here. The private key
// never leaves the user's authenticator, so a DB leak exposes nothing usable.
const passkeySchema = new mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 64,
    },
    credential_id: {
      type: String,
      required: true,
      unique: true,
    },
    public_key: {
      type: String,
      required: true,
    },
    counter: {
      type: Number,
      required: true,
      default: 0,
    },
    transports: {
      type: [String],
      default: [],
    },
    // Single-device passkeys rely on a monotonically increasing counter to
    // detect cloned authenticators; synced (multi-device) passkeys reset it.
    credential_device_type: {
      type: String,
      enum: ["singleDevice", "multiDevice"],
      default: "singleDevice",
    },
    last_used_at: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

passkeySchema.index({ user_id: 1, createdAt: -1 });

const Passkey =
  mongoose.models.Passkey || mongoose.model("Passkey", passkeySchema);
export default Passkey;
