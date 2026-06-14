import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: false, // Optional for failed logins where user doesn't exist
    },
    action: {
      type: String,
      required: true,
    },
    details: {
      type: String,
      required: false,
    },
    ip: {
      type: String,
      required: true,
    },
    userAgent: {
      type: String,
      required: false,
    },
    status: {
      type: String,
      enum: ["SUCCESS", "FAILED"],
      required: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model("AuditLog", auditLogSchema);
