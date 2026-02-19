import { z } from "zod";
import { ROLES } from "../utils/constants.js";

export const registerSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(6),
  role: z.enum([
    ROLES.SUPER_ADMIN,
    ROLES.MERCHANT_ADMIN,
    ROLES.DISPATCH_ADMIN,
    ROLES.STORE_OWNER,
  ]),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export const updateUserSchema = z.object({
  name: z.string().min(2).max(60),
});

export const updatePasswordSchema = z.object({
  currentPassword: z.string().min(6),
  newPassword: z.string().min(6),
});

export const forgotSchema = z.object({
  email: z.string().email(),
});

export const resetPasswordSchema = z.object({
  confirmPassword: z.string().min(6),
  newPassword: z.string().min(6),
});
