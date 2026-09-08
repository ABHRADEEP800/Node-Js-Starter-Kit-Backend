import ApiError from "./ApiError.js";

// Google's siteverify can be slow or temporarily unreachable. Without a
// timeout, `await fetch(...)` could hang an auth request indefinitely, which
// makes login look "stuck". Abort after a few seconds and fail fast.
const RECAPTCHA_TIMEOUT_MS = Number(process.env.RECAPTCHA_TIMEOUT_MS) || 4000;

const verifyRecaptcha = async (token) => {
  if (!token) throw new ApiError(400, "reCAPTCHA token is required");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RECAPTCHA_TIMEOUT_MS);

  try {
    const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`;
    const data = await fetch(verifyURL, {
      method: "POST",
      signal: controller.signal,
    }).then((res) => res.json());

    if (!data.success || data.score < 0.5) {
      throw new ApiError(400, "reCAPTCHA verification failed");
    }
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(502, "reCAPTCHA service unreachable, please try again");
  } finally {
    clearTimeout(timer);
  }
};

export default verifyRecaptcha;
