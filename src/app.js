import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import userRouter from "./routers/user.route.js";
import adminRouter from "./routers/admin.route.js";
import helmet from "helmet";
import compression from "compression";
import mongoSanitize from "express-mongo-sanitize";
import rateLimit from "express-rate-limit";
import errorHandler from "./middlewares/error.middleware.js";
import csrfMiddleware from "./middlewares/csrf.middleware.js";

const app = express();

app.set("trust proxy", 1); 

// 🚨 ALWAYS PUT CORS AT THE VERY TOP
app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, curl, or server-to-server)
      if (!origin) return callback(null, true);
      const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : [];
      // Allow if origin is in list, or if it's localhost in development
      if (allowedOrigins.includes(origin) || origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:")) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "Accept", "Origin", "X-Requested-With"],
  })
);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/"],
      frameSrc: ["https://www.google.com/recaptcha/"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://www.google.com/recaptcha/api/siteverify"],
    },
  },
}));
app.use(compression());

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again after 15 minutes",
});
app.use(globalLimiter);

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// Sanitize data against NoSQL Query Injection (Safe execution avoiding req.query assignment crash)
app.use((req, res, next) => {
  if (req.body) mongoSanitize.sanitize(req.body);
  if (req.query) mongoSanitize.sanitize(req.query);
  if (req.params) mongoSanitize.sanitize(req.params);
  next();
});

app.use(express.static("public"));
app.use(cookieParser());
app.use(csrfMiddleware);

//health check
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "success",
    message: "Server is healthy",
    uptime: process.uptime().toFixed(2) + " seconds",
    timestamp: new Date().toISOString(),
  });
});
//routers
app.use("/api/v1/user", userRouter);
app.use("/api/v1/admin", adminRouter);

// Global Error Handler
app.use(errorHandler);

export default app;
