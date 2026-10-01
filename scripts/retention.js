// ===========================================================
// ⏳ RETENTION RUNNER — s. 8(7)/(8), Rule 8
// ===========================================================
// Standalone entry point for the automated cleanup / cascade erasure routine.
// Wire to cron in production, e.g.:
//   0 2 * * *  node -r dotenv/config scripts/retention.js
// Pass `--dry-run` to report what WOULD be erased without erasing anything.
// Pass `--once` (default) for a single pass; `--interval=<ms>` to loop.

import "dotenv/config";
import mongoose from "mongoose";
import connectDB from "../src/db/db.js";
import { runRetentionPass } from "../src/services/retention.service.js";
import { systemLog } from "../src/events/systemLog.events.js";

const args = new Set(process.argv.slice(2));
const dryRun = args.has("--dry-run");
const intervalArg = [...args].find((a) => a.startsWith("--interval="));
const interval = intervalArg ? parseInt(intervalArg.split("=")[1], 10) : 0;

const main = async () => {
  await connectDB();

  const pass = async () => {
    const summary = await runRetentionPass({ dryRun });
    console.log("[DPDP retention]", JSON.stringify(summary));
    systemLog({
      level: "INFO",
      event: "RETENTION_PASS",
      message: dryRun ? "dry-run complete" : "retention pass complete",
      meta: summary,
    });
  };

  await pass();

  if (interval > 0) {
    setInterval(pass, interval);
    console.log(`[DPDP retention] scheduled every ${interval}ms`);
  } else {
    await mongoose.connection.close();
    process.exit(0);
  }
};

main().catch((err) => {
  console.error("[DPDP retention] failed:", err);
  systemLog({ level: "ERROR", event: "RETENTION_FAILED", message: err.message });
  process.exit(1);
});
