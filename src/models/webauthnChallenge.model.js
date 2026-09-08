import mongoose from "mongoose";

// ==========================================
// 🎯 WEBAUTHN CHALLENGE STORE (server-side)
// ==========================================
// Challenges are random, single-use, short-lived and bound to the issuing
// browser (via session) and Relying Party. TTL index garbage-collects old
// entries so an attacker can never mount a long-lived replay attack.
const webauthnChallengeSchema = new mongoose.Schema(
  {
    challenge: {
      type: String,
      required: true,
      unique: true,
    },
    type: {
      type: String,
      enum: ["register", "login"],
      required: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    sessionId: {
      type: String,
      default: null,
    },
    expectedRPID: {
      type: String,
      required: true,
    },
    expectedOrigin: {
      type: String,
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expireAfterSeconds: 0 },
    },
  },
  { timestamps: true }
);

const WebAuthnChallenge =
  mongoose.models.WebAuthnChallenge ||
  mongoose.model("WebAuthnChallenge", webauthnChallengeSchema);
export default WebAuthnChallenge;
