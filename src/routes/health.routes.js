import { Router } from "express";
import { ApiResponse } from "../utils/apiResponse.js";
import { requireAuth } from "../middlewares/auth.middleware.js";
import { requireRole } from "../middlewares/rbac.middleware.js";
import { ROLES } from "../utils/constants.js";

const router = Router();

router.get("/", (req, res) => {
  res.json(
    new ApiResponse(200, "API is healthy", { time: new Date().toISOString() }),
  );
});

// Protected test route
router.get("/me", requireAuth, (req, res) => {
  res.json(new ApiResponse(200, "Authorized", { user: req.user }));
});

// Role test route
router.get(
  "/super-only",
  requireAuth,
  requireRole(ROLES.SUPER_ADMIN),
  (req, res) => {
    res.json(
      new ApiResponse(200, "Welcome Super Admin", { userId: req.user._id }),
    );
  },
);

export default router;
