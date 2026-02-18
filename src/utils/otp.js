import crypto from "crypto";

export function generateOtp6() {
  // 6-digit numeric OTP (100000 to 999999)
  return String(Math.floor(100000 + Math.random() * 900000));
}

export function hashOtp(otp) {
  // Hash so OTP isn't stored as plain text
  return crypto.createHash("sha256").update(otp).digest("hex");
}
