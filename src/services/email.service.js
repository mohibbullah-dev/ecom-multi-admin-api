import nodemailer from "nodemailer";
import { env } from "../config/env.js";

export const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export async function sendOtpEmail({ to, otp, minutes }) {
  const fromName = process.env.SMTP_FROM_NAME || "ecom-multi-admin-api";
  const fromEmail = process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER;

  const subject = "Verify your email (OTP)";
  const text = `Your OTP is: ${otp}\nIt will expire in ${minutes} minutes.\nIf you didn't request this, ignore this email.`;

  await mailer.sendMail({
    from: `${fromName} <${fromEmail}>`,
    to,
    subject,
    text,
  });
}
