import { Router } from "express";
import {
  register,
  login,
  validateOtp,
  signOut,
} from "../controllers/auth.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/verify-otp", validateOtp);
router.get("/signout", requireAuth, signOut);

export default router;
