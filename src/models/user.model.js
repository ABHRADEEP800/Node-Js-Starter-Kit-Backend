import mongoose from "mongoose";
import bcrypt from "bcrypt";
import crypto from "crypto";

// ==========================================
// 🔐 SALT + PEPPER PASSWORD HASHING
// ==========================================
// Salt is provided by bcrypt: a unique random salt is generated and embedded
// in every hash. The pepper is a secret known only to the server and is never
// stored in the database, so a leaked DB dump alone cannot be used to crack
// passwords. The pepper is mixed in via HMAC-SHA256 (pepper as key) rather
// than plain concatenation, which avoids exposing the pepper in the value.
const BCRYPT_ROUNDS = 10;
const PEPPER = process.env.PASSWORD_PEPPER;

if (!PEPPER) {
  throw new Error(
    "PASSWORD_PEPPER environment variable is required for secure password hashing. Add it to your .env file."
  );
}

/** True when the value is already a bcrypt hash (prevents double hashing). */
const isBcryptHash = (value) => /^\$2[aby]\$/.test(value);

/** Mix the plaintext password with the server-side pepper. */
const applyPepper = (password) =>
  crypto.createHmac("sha256", PEPPER).update(password).digest("base64");

const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
    },
    username: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      lowercase: true,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      lowercase: true,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    twofa: {
      type: Boolean,
      default: false,
    },
    twofaCode: {
      type: String,
      default: null,
    },
    password: {
      type: String,
      required: true,
      trim: true,
    },

    // Issue 6: removed dead `refreshToken` field. This app uses cookie sessions,
    // not JWT refresh tokens. The field was never written or read.
    backupCodes: {
      type: [String],
      default: [],
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
      default: null,
    },
    // Issue 11: per-user passkey attempt counter / lockout. The IP-based
    // passkeyLoginLimiter alone is bypassable across many IPs.
    failedPasskeyAttempts: {
      type: Number,
      default: 0,
    },
    passkeyLockUntil: {
      type: Date,
      default: null,
    },
    // Issue: per-user 2FA attempt counter / lockout. The IP-based twofaLimiter
    // alone can be bypassed across many IPs, so a stolen password + PENDING_2FA
    // session must not permit unbounded TOTP guessing.
    failed2faAttempts: {
      type: Number,
      default: 0,
    },
    twofaLockUntil: {
      type: Date,
      default: null,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: {
      type: String,
      default: null,
    },
    // Issue 42: verification tokens expire (default 24h).
    emailVerificationExpires: {
      type: Date,
      default: null,
    },
    passwordResetToken: {
      type: String,
      default: null,
    },
    passwordResetExpires: {
      type: Date,
      default: null,
    },

    // ==========================================
    // 🇮🇳 DPDP COMPLIANCE FIELDS
    // ==========================================
    // Age gate (s. 9, s. 2(f)). `dateOfBirth` is required at signup and NEVER
    // exposed by the output DTO. A child is anyone under 18; `isChild` is the
    // coarse flag used by access-control checks. If age is unknown we treat
    // the user as a child until verified otherwise.
    dateOfBirth: {
      type: Date,
      default: null,
    },
    isChild: {
      type: Boolean,
      default: true, // deny-by-default: unknown age ⇒ treat as child
    },
    // Verifiable parental / guardian consent (s. 9, Rule 10/11).
    guardianVerified: {
      type: Boolean,
      default: false,
    },
    guardianConsentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "GuardianConsent",
      default: null,
    },
    // Children's data: telemetry, tracking and targeted ads are disabled
    // (s. 9(3)). Adults default to false (telemetry off unless they opt in).
    telemetryDisabled: {
      type: Boolean,
      default: true,
    },
    // Whether the Data Principal has affirmed the s. 15 duties in the UI.
    dutiesAcknowledgedAt: {
      type: Date,
      default: null,
    },
    // Registered lawful purpose for the account record (s. 4(1)).
    purposeId: {
      type: String,
      default: "account",
    },
    lawfulBasis: {
      type: String,
      default: "consent",
    },

    // ---- Retention / erasure lifecycle (s. 8(7)/(8), Rule 8) ----
    lastActiveAt: { type: Date, default: Date.now },
    accountStatus: {
      type: String,
      enum: ["active", "erasure_pending", "erased"],
      default: "active",
    },
    erasureDueAt: { type: Date, default: null },
    erasureWarnedAt: { type: Date, default: null },
    deletionRequestedAt: { type: Date, default: null },
    legalHold: { type: Boolean, default: false },
    legalHoldCitation: { type: String, default: null },
    // Set when the Third Schedule inactivity trim has already run, so an
    // inactive account is not re-trimmed on every retention pass. Cleared
    // implicitly by a fresh sign-in advancing `lastActiveAt`.
    retentionTrimmedAt: { type: Date, default: null },

    // s. 14 — nominees who may exercise the Data Principal's rights on death
    // or incapacity. Name/contact are ENCRYPTED at rest (Rule 6(a)); the
    // relationship and status are not secret.
    nominees: {
      type: [
        {
          name: String, // encrypted (v1 envelope)
          relationship: String,
          contact: String, // encrypted email/phone
          // Optional share of the estate's data claim (e.g. "50%"); free text.
          share: { type: String, default: null },
          // Lifecycle of this nomination.
          status: {
            type: String,
            enum: ["active", "revoked", "claimed"],
            default: "active",
          },
          addedAt: { type: Date, default: Date.now },
          revokedAt: { type: Date, default: null },
        },
      ],
      default: [],
    },
    // Set when a nominee claim is substantiated (death/incapacity proven): the
    // account is locked and the nominee may exercise the DP's rights (s. 14).
    nomineeClaim: {
      status: {
        type: String,
        enum: ["none", "pending", "approved", "rejected"],
        default: "none",
      },
      claimId: { type: mongoose.Schema.Types.ObjectId, ref: "NomineeClaim", default: null },
      approvedAt: { type: Date, default: null },
    },
    // When the DP is deceased/incapacitated and a claim is approved, no further
    // processing happens except servicing the nominee.
    accountLockedForNominee: { type: Boolean, default: false },
  },
  {
    timestamps: true,
  }
);

// Hash the password before saving the user.
// The `isBcryptHash` guard makes hashing idempotent: re-saving an already
// hashed value (e.g. the login migration below) won't double-hash it.
userSchema.pre("save", async function () {
  if (this.isModified("password") && !isBcryptHash(this.password)) {
    this.password = await bcrypt.hash(applyPepper(this.password), BCRYPT_ROUNDS);
  }
});

userSchema.methods.isPasswordCorrect = async function (password) {
  // 1. Current scheme: peppered hash.
  if (await bcrypt.compare(applyPepper(password), this.password)) return true;

  // 2. Fallback for accounts hashed before the pepper was introduced — on a
  //    successful login the password is re-hashed with the pepper, migrating
  //    the account to the new scheme transparently.
  if (await bcrypt.compare(password, this.password)) {
    this.password = await bcrypt.hash(applyPepper(password), BCRYPT_ROUNDS);
    await this.save({ validateBeforeSave: false });
    return true;
  }

  return false;
};

const User = mongoose.models.User || mongoose.model("User", userSchema);
export default User;
