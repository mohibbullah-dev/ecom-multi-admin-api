import { User } from "../models/user.model.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { signAccessToken } from "../utils/token.util.js";
import bcrypt from "bcryptjs";
import { loginSchema, registerSchema } from "../validators/auth.validator.js";
import { generateOtp6, hashOtp } from "../utils/otp.js";
import { sendOtpEmail } from "../services/email.service.js";
import { env } from "../config/env.js";

// export const register = asyncHandler(async (req, res) => {
//   const data = registerSchema.parse(req.body);

//   const exists = await User.findOne({ email: data.email }).lean();
//   if (exists) throw new ApiError(409, "Email already registered");

//   const passwordHash = await bcrypt.hash(data.password, 10);

//   const user = await User.create({
//     name: data.name,
//     email: data.email,
//     passwordHash,
//     role: data.role,
//   });

//   const token = signAccessToken(user._id.toString());

//   res.status(201).json(
//     new ApiResponse(201, "Registered", {
//       token,
//       user: {
//         id: user._id,
//         name: user.name,
//         email: user.email,
//         role: user.role,
//       },
//     }),
//   );
// });

export const register = asyncHandler(async (req, res) => {
  const data = registerSchema.parse(req.body);

  const exists = await User.findOne({ email: data.email }).lean();
  if (exists) throw new ApiError(409, "Email already registered");

  const passwordHash = await bcrypt.hash(data.password, 10);

  // OTP generate + hash + expiry
  const otp = generateOtp6();
  //   const otpHash = hashOtp(otp);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

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
export const validateOtp = asyncHandler(async (req, res) => {
  const { otp } = req.body;
  const user = await User.findOne({ emailVerifyOtpHash: otp });
  if (!user) throw ApiError.notFound("invalid otp.");
  if (user.passwordResetExpires < Date.now())
    throw ApiError(401, "otp expired");
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

  const token = signAccessToken(user._id.toString());

  res.json(
    new ApiResponse(200, "Logged in", {
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    }),
  );
});
