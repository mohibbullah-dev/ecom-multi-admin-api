import { Router } from "express";
import {
  register,
  login,
  validateOtp,
} from "../controllers/auth.controller.js";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/verify-otp", validateOtp);

export default router;
