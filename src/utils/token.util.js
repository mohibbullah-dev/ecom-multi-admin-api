import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import crypto from "crypto";

export const signAccessToken = (userId) => {
  return jwt.sign({ sub: userId }, env.JWT_ACCESS_SECRET, {
    expiresIn: env.JWT_ACCESS_EXPIRES_IN,
  });
};

export function signRefreshToken(userId) {
  return jwt.sign({ sub: userId }, env.JWT_REFRESH_SECRET, {
    expiresIn: env.JWT_REFRESH_EXPIRES_IN,
  });
}

export function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
