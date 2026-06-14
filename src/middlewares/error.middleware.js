import ApiError from "../utility/ApiError.js";

const errorHandler = (err, req, res, next) => {
  let error = err;

  if (!(error instanceof ApiError)) {
    const statusCode = error.statusCode || 500;
    const message = error.message || "Something went wrong";
    error = new ApiError(statusCode, message, error?.errors || [], err.stack);
  }

  const response = {
    ...error,
    message: error.message,
    ...(process.env.NODE_ENV === "development" ||
    process.env.NODE_ENVIRONMENT === "development"
      ? { stack: error.stack }
      : {}),
  };

  return res.status(error.statusCode).json(response);
};

export default errorHandler;
