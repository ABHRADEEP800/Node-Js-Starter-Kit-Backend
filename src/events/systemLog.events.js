import { EventEmitter } from "events";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// System (operational) logs are appended to a CSV file, one row per event.
// Kept out of the repo via the existing `logs` entry in .gitignore.
const LOG_DIR = path.resolve(__dirname, "../../logs");
const LOG_FILE = path.join(LOG_DIR, "system-log.csv");
// HEADERS array (the CSV header row) is no longer written at startup; the
// async handler appends the header on first write if the file is empty.

class SystemLogEmitter extends EventEmitter {}
const systemLogEmitter = new SystemLogEmitter();

/** Escape a value for safe CSV output (quotes + commas + newlines). */
const csvEscape = (value) => {
  const str = value === undefined || value === null ? "" : String(value);
  return /[",\n\r]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
};

// ensureFile inlined into the async handler below (Issue 108 rewrite).

// Issue 108: async writes so the event loop isn't blocked on disk I/O.
const pendingWrites = [];

systemLogEmitter.on(
  "log",
  ({ level = "INFO", event, message, meta = {} }) => {
    const write = (async () => {
      try {
        await fs.promises.mkdir(LOG_DIR, { recursive: true });
        const row = [
          new Date().toISOString(),
          level,
          event,
          message,
          JSON.stringify(meta),
        ];
        await fs.promises.appendFile(
          LOG_FILE,
          row.map(csvEscape).join(",") + "\n",
          "utf8"
        );
      } catch (err) {
        console.error("Failed to write system log:", err);
      }
    })();
    pendingWrites.push(write);
  }
);

process.on("beforeExit", async () => {
  await Promise.allSettled(pendingWrites);
});

/** Emit a system log entry (fire-and-forget). */
export const systemLog = ({ level, event, message, meta }) =>
  systemLogEmitter.emit("log", { level, event, message, meta });

export default systemLogEmitter;
