import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import userRouter from "./routers/user.route.js";
import helmet from "helmet";
const app = express();

app.set("trust proxy", 1); 

app.use(helmet());
app.use(
  express.json({
    limit: "10kb",
  })
);
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS.split(","),
    credentials: true,
  })
);
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(express.static("public"));
app.use(
  cookieParser({
    httpOnly: true,
    secure: process.env.NODE_ENVIRONMENT === "production",
    sameSite: process.env.NODE_ENVIRONMENT === "production" ? "none" : "strict",
  })
);

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

export default app;
