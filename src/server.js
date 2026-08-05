import "dotenv/config";
import app from "./app.js";
import connectDB from "./db/db.js";
import { systemLog } from "./events/systemLog.events.js";
const port = process.env.NODE_SERVER_PORT || 4000;

connectDB()
  .then(() => {
    const server = app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
      systemLog({
        level: "INFO",
        event: "SERVER_START",
        message: `Server is running on port ${port}`,
        meta: { env: process.env.NODE_ENV || "development" },
      });
    });

    process.on("unhandledRejection", (err) => {
      console.error("UNHANDLED REJECTION! 💥 Shutting down...");
      console.error(err.name, err.message);
      systemLog({
        level: "ERROR",
        event: "UNHANDLED_REJECTION",
        message: `${err.name}: ${err.message}`,
      });
      server.close(() => {
        process.exit(1);
      });
    });

    process.on("uncaughtException", (err) => {
      console.error("UNCAUGHT EXCEPTION! 💥 Shutting down...");
      console.error(err.name, err.message);
      systemLog({
        level: "ERROR",
        event: "UNCAUGHT_EXCEPTION",
        message: `${err.name}: ${err.message}`,
      });
      process.exit(1);
    });
  })
  .catch((error) => {
    console.error("Error connecting to the database:", error);
    systemLog({
      level: "ERROR",
      event: "BOOT_FAILED",
      message: error.message,
    });
  });
