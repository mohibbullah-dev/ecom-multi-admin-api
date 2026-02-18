import { User } from "../models/user.model.js";
import { ApiError } from "../utils/apiError.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { signAccessToken } from "../utils/token.util.js";
import bcrypt from "bcryptjs";
import { loginSchema, registerSchema } from "../validators/auth.validator.js";
import { generateOtp6, hashOtp } from "../utils/otp.js";

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
  const otpHash = hashOtp(otp);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  const user = await User.create({
    name: data.name,
    email: data.email,
    passwordHash,
    role: data.role,

    isEmailVerified: false,
    emailVerifyOtpHash: otpHash,
    emailVerifyOtpExpiresAt: expiresAt,
  });

  // We don't sign-in user until verified (your choice).
  // We'll do "verify first, then login".
  const payload = {
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    message: "Signup successful. Please verify your email with OTP.",
  };

  // ✅ For development/testing only: return OTP
  if (process.env.NODE_ENV !== "production") {
    payload.devOtp = otp;
    payload.otpExpiresAt = expiresAt;
  }

  res.status(201).json(new ApiResponse(201, "Signup created", payload));
});

export const login = asyncHandler(async (req, res) => {
  const data = loginSchema.parse(req.body);

  const user = await User.findOne({ email: data.email });
  if (!user) throw new ApiError(401, "Invalid credentials");

  const ok = await bcrypt.compare(data.password, user.passwordHash);
  if (!ok) throw new ApiError(401, "Invalid credentials");

  if (!user.isActive) throw new ApiError(403, "User is inactive");

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
