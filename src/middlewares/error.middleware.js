import ApiError from "../utility/ApiError.js";
import { systemLog } from "../events/systemLog.events.js";
import { isProd } from "./csrf.middleware.js";

const errorHandler = (err, req, res, _next) => {
  let error = err;

  if (!(error instanceof ApiError)) {
    const statusCode = error.statusCode || 500;
    const message = error.message || "Something went wrong";
    error = new ApiError(statusCode, message, error?.errors || [], err.stack);
  }

  systemLog({
    level: error.statusCode >= 500 ? "ERROR" : "WARN",
    event: "HTTP_ERROR",
    message: error.message,
    meta: {
      statusCode: error.statusCode,
      method: req.method,
      path: req.originalUrl,
      ip: req.ip,
    },
  });

  const response = {
    ...error,
    message: error.message,
    ...(isProd()
      ? {}
      : { stack: error.stack }),
  };

  return res.status(error.statusCode).json(response);
};

export default errorHandler;
