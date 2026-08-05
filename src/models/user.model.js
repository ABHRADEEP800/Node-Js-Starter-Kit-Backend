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

    refreshToken: {
      type: String,
      default: null,
    },
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
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: {
      type: String,
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
