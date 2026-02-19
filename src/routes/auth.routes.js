import { Router } from "express";
import {
  register,
  login,
  validateEmailVerifyOtp,
  signOut,
  updateUser,
  userPasswordUpdate,
  forgotPassword,
  ResetPasswordOtpValidate,
  resetPassword,
} from "../controllers/auth.controller.js";
import { requireAuth } from "../middlewares/auth.middleware.js";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/emailVerify-otp", validateEmailVerifyOtp);
router.get("/signout", requireAuth, signOut);
router.patch("/update-user", requireAuth, updateUser);
router.patch("/userPasswordUpdate", requireAuth, userPasswordUpdate);
router.post("/forgot-password", requireAuth, forgotPassword);
router.post("/passwordReset-Otp", requireAuth, ResetPasswordOtpValidate);
router.post("/passwordReset", requireAuth, resetPassword);

export default router;
