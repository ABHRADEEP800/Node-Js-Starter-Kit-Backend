import { EventEmitter } from "events";
import { sendEmail } from "../utility/email.js";

class AuthEmitter extends EventEmitter {}
const authEmitter = new AuthEmitter();

authEmitter.on("userRegistered", async ({ email, fullName, token }) => {
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : ["http://localhost:5173"];
  const frontendUrl = allowedOrigins[0];
  const verificationLink = `${frontendUrl}/verify-email?token=${token}`;

  const subject = "Verify Your Email - Starter Kit";
  const text = `Hi ${fullName},\n\nPlease verify your email by opening the link: ${verificationLink}`;
  const html = `<p>Hi ${fullName},</p>
  <p>Please verify your email by clicking the link below:</p>
  <p><a href="${verificationLink}">Verify Email</a></p>`;

  await sendEmail(email, subject, text, html);
});

authEmitter.on("passwordResetRequested", async ({ email, fullName, token }) => {
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : ["http://localhost:5173"];
  const frontendUrl = allowedOrigins[0];
  const resetLink = `${frontendUrl}/reset-password?token=${token}`;

  const subject = "Reset Your Password - Starter Kit";
  const text = `Hi ${fullName},\n\nYou have requested a password reset. Please click on the link to reset your password: ${resetLink}\n\nThis link will expire in 1 hour. If you did not make this request, please ignore this email.`;
  const html = `<p>Hi ${fullName},</p>
  <p>You have requested a password reset. Please click the link below to reset your password:</p>
  <p><a href="${resetLink}">Reset Password</a></p>
  <p>This link will expire in 1 hour. If you did not make this request, please ignore this email.</p>`;

  await sendEmail(email, subject, text, html);
});

authEmitter.on("passwordResetSuccess", async ({ email, fullName }) => {
  const subject = "Your Password Has Been Reset - Starter Kit";
  const text = `Hi ${fullName},\n\nYour password has been successfully reset. If you did not perform this action, please contact our support immediately.`;
  const html = `<p>Hi ${fullName},</p>
  <p>Your password has been successfully reset. If you did not perform this action, please contact our support immediately.</p>`;

  await sendEmail(email, subject, text, html);
});

export default authEmitter;
