import express from "express";
import authMiddleware from "../middlewares/auth.middleware.js";
import User from "../models/user.model.js";
import ApiError from "../utility/ApiError.js";
import requestHandler from "../utility/requestHandeller.js";
import ApiResponse from "../utility/ApiResponse.js";
import toUserDTO from "../dto/user.dto.js";

const adminRouter = express.Router();

// ==========================================
// 🛡️ STRICT RBAC & IDOR PREVENTION DEMO
// ==========================================

// This route uses Strict RBAC: Only "admin" can even access this router.
// authMiddleware(["admin"]) ensures only users with the 'admin' role pass.
adminRouter.use(authMiddleware(["admin"]));

// Fetch any user profile by ID
adminRouter.route("/users/:id").get(
  requestHandler(async (req, res) => {
    const targetUserId = req.params.id;

    // IDOR Check (Insecure Direct Object Reference)
    // Even though this is an admin route, let's explicitly document how IDOR is prevented.
    // If a normal user somehow bypassed the RBAC, we double-check ownership vs privilege.
    if (req.user.role !== "admin" && req.user._id.toString() !== targetUserId) {
      throw new ApiError(
        403,
        "Access Denied: You do not have permission to view this resource."
      );
    }

    const user = await User.findById(targetUserId).select(
      "-password -refreshToken -twofaCode -backupCodes"
    );
    if (!user) throw new ApiError(404, "User not found");

    return res
      .status(200)
      .json(new ApiResponse(200, "User fetched successfully", { user: toUserDTO(user) }));
  })
);

export default adminRouter;
