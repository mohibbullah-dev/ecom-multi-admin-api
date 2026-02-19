import { User } from "../models/user.model.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import {
  hashToken,
  signAccessToken,
  signRefreshToken,
} from "../utils/token.util.js";
import bcrypt from "bcryptjs";
import {
  forgotSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
  updatePasswordSchema,
  updateUserSchema,
} from "../validators/auth.validator.js";
import { generateOtp6, hashOtp } from "../utils/otp.js";
import { sendOtpEmail } from "../services/email.service.js";
import { env } from "../config/env.js";

export const register = asyncHandler(async (req, res) => {
  const data = registerSchema.parse(req.body);

  const exists = await User.findOne({ email: data.email }).lean();
  if (exists) throw new ApiError(409, "Email already registered");

  const passwordHash = await bcrypt.hash(data.password, 10);

  // OTP generate + hash + expiry
  const otp = generateOtp6();
  //   const otpHash = hashOtp(otp);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000); // 10 minutes

  const user = await User.create({
    name: data.name,
    email: data.email,
    passwordHash,
    role: data.role,

    isEmailVerified: false,
    emailVerifyOtpHash: otp,
    emailVerifyOtpExpiresAt: expiresAt,
  });
  // otp send
  await sendOtpEmail({ to: user.email, otp, minutes: env.OTP_EXPIRES_MINUTES });

  // We don't sign-in user until verified (your choice).
  // We'll do "verify first, then login".
  const payload = {
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    message: "Signup successful. OTP sent to your email.",
  };

  // ✅ For development/testing only: return OTP
  if (process.env.NODE_ENV !== "production") {
    payload.devOtp = otp;
    payload.otpExpiresAt = expiresAt;
  }

  res.status(201).json(new ApiResponse(201, "Signup created", payload));
});

// otpverify
export const validateEmailVerifyOtp = asyncHandler(async (req, res) => {
  const { otp } = req.body;
  const user = await User.findOne({ emailVerifyOtpHash: otp });
  if (!user) throw ApiError.notFound("invalid otp.");
  if (user?.emailVerifyOtpExpiresAt < Date.now())
    throw new ApiError(401, "otp expired");
  user.isEmailVerified = true;
  await user.save();
  return res.status(200).json(new ApiResponse(200, "otp verified."));
});

// login
export const login = asyncHandler(async (req, res) => {
  const data = loginSchema.parse(req.body);

  const user = await User.findOne({ email: data.email });
  if (!user) throw new ApiError(401, "Invalid credentials");

  const ok = await bcrypt.compare(data.password, user.passwordHash);
  if (!ok) throw new ApiError(401, "Invalid credentials");

  if (!user.isActive) throw new ApiError(403, "User is inactive");
  if (!user.isEmailVerified) throw new ApiError(403, "Email not verified");

  //   const token = signAccessToken(user._id.toString());
  const accessToken = signAccessToken(user._id.toString());
  const refreshToken = signRefreshToken(user._id.toString());
  user.refreshTokenHash = hashToken(refreshToken);
  await user.save();

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.json(
    new ApiResponse(200, "Logged in", {
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    }),
  );
});

// signOut
export const signOut = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;

  // Clear cookie always (even if no cookie)
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });

  if (!refreshToken) {
    return res.json(new ApiResponse(200, "Signed out", { done: true }));
  }

  const refreshHash = hashToken(refreshToken);

  // Remove stored session
  await User.updateOne(
    { _id: req.user._id },
    { $set: { refreshTokenHash: null } },
  );

  res.json(new ApiResponse(200, "Signed out", { done: true }));
});

// updateUser

export const updateUser = asyncHandler(async (req, res) => {
  const { name } = updateUserSchema.parse(req.body);

  const updated = await User.findByIdAndUpdate(
    req.user._id,
    { $set: { name } },
    {
      new: true,
      runValidators: true,
      select:
        "_id name email role isEmailVerified isActive avatar createdAt updatedAt",
    },
  ).lean();

  if (!updated) throw new ApiError(404, "User not found");

  res.json(new ApiResponse(200, "User updated", { user: updated }));
});

// userPasswordUpdate
export const userPasswordUpdate = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = updatePasswordSchema.parse(req.body);

  if (currentPassword === newPassword) {
    throw new ApiError(
      400,
      "New password must be different from current password",
    );
  }

  const user = await User.findById(req.user._id);
  if (!user) throw new ApiError(404, "User not found");

  const ok = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!ok) throw new ApiError(400, "Current password is incorrect");

  user.passwordHash = await bcrypt.hash(newPassword, 10);

  // ✅ Invalidate refresh token (force logout)
  user.refreshTokenHash = null;

  await user.save();

  // clear refresh cookie too
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });

  res.json(
    new ApiResponse(200, "Password updated. Please sign in again.", {
      done: true,
    }),
  );
});

// forgotPassword
export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = forgotSchema.parse(req.body);

  const user = await User.findOne({ email });

  // ✅ Always return same response (security)
  const safeResponse = new ApiResponse(
    200,
    "If the email exists, an OTP has been sent.",
    {
      sent: true,
    },
  );

  if (!user) return res.json(safeResponse);

  const otp = generateOtp6();
  //   const otpHash = hashOtp(otp);
  const expiresAt = new Date(Date.now() + env.OTP_EXPIRES_MINUTES * 60 * 1000);

  user.passwordResetOtp = otp;
  user.passwordResetOtpExpiresAt = expiresAt;

  await user.save();

  await sendOtpEmail({
    to: user.email,
    otp,
    minutes: env.OTP_EXPIRES_MINUTES,
  });

  // ✅ dev helper
  if (process.env.NODE_ENV !== "production") {
    safeResponse.data.devOtp = otp;
    safeResponse.data.otpExpiresAt = expiresAt;
  }

  return res.json(safeResponse);
});

// ResetPasswordOtpValidate
export const ResetPasswordOtpValidate = asyncHandler(async (req, res) => {
  const { otp } = req.body;
  const user = await User.findOne({ passwordResetOtp: otp });
  if (!user) throw ApiError.notFound("invalid otp.");
  if (user?.passwordResetOtpExpiresAt < Date.now())
    throw new ApiError(401, "otp expired");
  await user.save();
  return res.status(200).json(new ApiResponse(200, "otp verified."));
});

export const resetPassword = asyncHandler(async (req, res) => {
  const { confirmPassword, newPassword } = resetPasswordSchema.parse(req.body);

  if (confirmPassword !== newPassword) {
    throw new ApiError(400, "confirm password is incurrect");
  }

  const user = await User.findById(req.user._id);
  if (!user) throw new ApiError(404, "User not found");

  user.passwordHash = await bcrypt.hash(newPassword, 10);

  // ✅ Invalidate refresh token (force logout)
  user.refreshTokenHash = null;

  await user.save();

  // clear refresh cookie too
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });

  res.json(
    new ApiResponse(200, "Password reseted. Please sign in again.", {
      done: true,
    }),
  );
});
