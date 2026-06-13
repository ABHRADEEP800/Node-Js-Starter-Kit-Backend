import ApiError from "../utility/ApiError.js";

const csrfMiddleware = (req, res, next) => {
  // Allow safe methods
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  // Check for standard anti-CSRF custom header
  // Simple SPA approach: SPA must send this header
  const csrfHeader = req.headers["x-csrf-token"];
  if (!csrfHeader || csrfHeader !== "strict") {
    throw new ApiError(403, "CSRF token missing or invalid");
  }

  next();
};

export default csrfMiddleware;
