import ApiError from "../utility/ApiError.js";
import { systemLog } from "../events/systemLog.events.js";
import { isProd } from "./csrf.middleware.js";
import { maskPII } from "../utility/piiMask.js";

const errorHandler = (err, req, res, _next) => {
  // A response may already have been sent (e.g. a controller threw AFTER
  // writing). Express would otherwise throw "headers already sent".
  if (res.headersSent) {
    return _next(err);
  }

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
      // Strip the query string: it can carry one-time tokens (e.g.
      // /verify-email?token=…) that must never reach a log sink (Rule 6(a)).
      path: req.originalUrl?.split("?")[0],
      // Never write a raw IP to a log sink (Rule 6(a), s. 8(5)).
      ip: maskPII(req.ip, "ip"),
    },
  });

  // Emit only the documented contract fields — never spread arbitrary error
  // properties (e.g. Mongoose CastError's stringValue/path) to the client.
  const response = {
    statusCode: error.statusCode,
    success: false,
    message: error.message,
    errors: error.errors ?? [],
    data: null,
    ...(isProd() ? {} : { stack: error.stack }),
  };

  return res.status(error.statusCode).json(response);
};

export default errorHandler;
