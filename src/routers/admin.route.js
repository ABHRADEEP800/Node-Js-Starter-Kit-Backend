import express from "express";
import authMiddleware from "../middlewares/auth.middleware.js";
import { getAdminUser } from "../controllers/admin.controller.js";

const adminRouter = express.Router();

// ==========================================
// 🛡️ STRICT RBAC & IDOR PREVENTION
// ==========================================
// This route uses Strict RBAC: only "admin" can even access this router.
// authMiddleware(["admin"]) ensures only users with the 'admin' role pass.
adminRouter.use(authMiddleware(["admin"]));

// Fetch any user profile by ID (controller documents the explicit IDOR check).
adminRouter.route("/users/:id").get(getAdminUser);

export default adminRouter;
