import { EventEmitter } from "events";
import { sendEmail } from "../utility/email.js";

class AuthEmitter extends EventEmitter {}
const authEmitter = new AuthEmitter();

authEmitter.on("userRegistered", async ({ email, fullName, token }) => {
  const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : ["http://localhost:5173"];
  const frontendUrl = allowedOrigins[0];
  const verificationLink = `${frontendUrl}/verify-email?token=${token}`;
  
  const subject = "Verify Your Email - Starter Kit";
  const text = `Hi ${fullName},\n\nPlease verify your email by opening the link: ${verificationLink}`;
  const html = `<p>Hi ${fullName},</p>
  <p>Please verify your email by clicking the link below:</p>
  <p><a href="${verificationLink}">Verify Email</a></p>`;
  
  await sendEmail(email, subject, text, html);
});

export default authEmitter;
