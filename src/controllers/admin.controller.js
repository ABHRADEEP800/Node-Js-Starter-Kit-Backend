// ===========================================================
// 🛡️ ADMIN CONTROLLER — strict RBAC + explicit IDOR prevention
// ===========================================================
// The whole admin router is gated by authMiddleware(["admin"]), so by the time
// these handlers run req.user.role is guaranteed to be "admin". The explicit
// ownership check is kept as documented defence-in-depth (IDOR).
import User from "../models/user.model.js";
import ApiError from "../utility/ApiError.js";
import requestHandler from "../utility/requestHandeller.js";
import ApiResponse from "../utility/ApiResponse.js";
import toUserDTO from "../dto/user.dto.js";

// Fetch any user profile by ID.
const getAdminUser = requestHandler(async (req, res) => {
  const targetUserId = req.params.id;

  // IDOR check: even behind RBAC, explicitly verify ownership vs privilege.
  if (req.user.role !== "admin" && req.user._id.toString() !== targetUserId) {
    throw new ApiError(
      403,
      "Access Denied: You do not have permission to view this resource."
    );
  }

  const user = await User.findById(targetUserId).select(
    "-password -twofaCode -backupCodes"
  );
  if (!user) throw new ApiError(404, "User not found");

  return res
    .status(200)
    .json(new ApiResponse(200, "User fetched successfully", { user: toUserDTO(user) }));
});

export { getAdminUser };
