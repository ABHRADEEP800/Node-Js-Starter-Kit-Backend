import { z } from "zod";

export const signupSchema = z.object({
  user: z.object({
    fullName: z.string().min(2),
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
  fullName: z.string().min(2),
});

export const verify2FASchema = z.object({
  code: z.string().min(6), // 6 digit OTP or 10 digit backup code
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
