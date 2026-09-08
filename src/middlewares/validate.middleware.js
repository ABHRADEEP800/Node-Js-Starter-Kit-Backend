import ApiError from "../utility/ApiError.js";

const validate = (schema) => (req, res, next) => {
  try {
    req.body = schema.parse(req.body);
    next();
  } catch (err) {
    // zod v4 exposes issues on `err.issues`; older versions used `err.errors`.
    const issues = err?.issues || err?.errors || [];
    const errors = issues.map((e) => ({
      path: Array.isArray(e.path) ? e.path.join(".") : String(e.path ?? ""),
      message: e.message,
    }));
    next(new ApiError(400, "Validation Error", errors));
  }
};

export default validate;
