import ApiError from "../utility/ApiError.js";

const validate = (schema) => (req, res, next) => {
  try {
    req.body = schema.parse(req.body);
    next();
  } catch (err) {
    const errors = err.errors.map((e) => ({
      path: e.path.join("."),
      message: e.message,
    }));
    next(new ApiError(400, "Validation Error", errors));
  }
};

export default validate;
