import { z } from "zod";

export const signupSchema = z.object({
  user: z.object({
    firstName: z.string().min(1),
    lastName: z.string().min(1),
    username: z
      .string()
      .min(3)
      .regex(/^[a-zA-Z0-9_]+$/),
    email: z.string().email(),
    password: z.string().min(8),
    recaptchaToken: z.string().min(1),
  }),
});

export const loginSchema = z.object({
  user: z.object({
    username: z.string().optional(),
    email: z.string().email().optional(),
    password: z.string().min(1),
    rememberMe: z.boolean().optional(),
    recaptchaToken: z.string().min(1),
  }),
});

export const changePassSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8),
});

export const changeNameSchema = z.object({
  firstName: z.string().min(1),
  lastName: z.string().min(1),
});

export const verify2FASchema = z.object({
  code: z.string().min(6), // 6 digit OTP or 8 hex backup code
  enable: z.boolean().optional(),
});

export const revokeSessionSchema = z.object({
  sessionId: z.string().min(1),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email(),
  recaptchaToken: z.string().min(1),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(8),
});

// ==========================================
// 🔑 PASSKEY (WEBAUTHN) SCHEMAS
// ==========================================

export const passkeyRegisterOptionsSchema = z.object({
  name: z.string().min(1).max(64),
});

export const passkeyRegisterVerifySchema = z.object({
  name: z.string().min(1).max(64),
  response: z.any(),
});

export const passkeyLoginOptionsSchema = z.object({
  // Empty string is treated as "no identifier" (empty allow-list) by the
  // handler, so the field must accept "" as well as undefined.
  identifier: z
    .string()
    .trim()
    .max(320)
    .optional()
    .transform((v) => v || ""),
  recaptchaToken: z.string().min(1),
});

export const passkeyLoginVerifySchema = z.object({
  response: z.any(),
});

export const passkeyDeleteSchema = z.object({
  id: z.string().min(1),
});
