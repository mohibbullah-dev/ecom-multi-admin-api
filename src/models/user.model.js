import mongoose from "mongoose";
import { ROLES } from "../utils/constants.js";

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    passwordHash: { type: String, required: true },
    passwordResetOtp: { type: String, default: null },
    passwordResetOtpExpiresAt: { type: Date, default: null },

    role: { type: String, enum: Object.values(ROLES), required: true },

    isActive: { type: Boolean, default: true },

    // ✅ Email verification
    isEmailVerified: { type: Boolean, default: false },
    emailVerifyOtpHash: { type: String, default: null },
    emailVerifyOtpExpiresAt: { type: Date, default: null },

    // ✅ Avatar
    avatar: {
      url: { type: String, default: null },
      publicId: { type: String, default: null },
    },

    // (Later for refresh tokens)
    refreshTokenHash: { type: String, default: null },
  },
  { timestamps: true },
);

export const User = mongoose.model("User", userSchema);
