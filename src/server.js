import "dotenv/config";
import app from "./app.js";
import connectDB from "./db/db.js";
import { systemLog } from "./events/systemLog.events.js";
import { runRetentionPass } from "./services/retention.service.js";
const port = process.env.NODE_SERVER_PORT || 4000;

// DPDP (s. 8(7)/(8), Rule 8): optional in-process retention scheduler. Disabled
// by default — prefer the standalone `npm run retention` cron script. Set
// DPDP_RETENTION_INTERVAL_MS to a positive number to enable (not for
// multi-instance deploys; use the script + a single scheduler there).
const retentionInterval = parseInt(process.env.DPDP_RETENTION_INTERVAL_MS || "0", 10);
if (retentionInterval > 0) {
  setInterval(
    () =>
      runRetentionPass({ dryRun: false }).catch((err) =>
        systemLog({ level: "ERROR", event: "RETENTION_FAILED", message: err.message })
      ),
    retentionInterval
  );
}

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
