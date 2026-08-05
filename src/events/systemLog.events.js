import { EventEmitter } from "events";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// System (operational) logs are appended to a CSV file, one row per event.
// Kept out of the repo via the existing `logs` entry in .gitignore.
const LOG_DIR = path.resolve(__dirname, "../../logs");
const LOG_FILE = path.join(LOG_DIR, "system-log.csv");
const HEADERS = ["timestamp", "level", "event", "message", "meta"];

class SystemLogEmitter extends EventEmitter {}
const systemLogEmitter = new SystemLogEmitter();

/** Escape a value for safe CSV output (quotes + commas + newlines). */
const csvEscape = (value) => {
  const str = value === undefined || value === null ? "" : String(value);
  return /[",\n\r]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
};

/** Create the logs dir and write the header row on first use. */
const ensureFile = () => {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  if (!fs.existsSync(LOG_FILE) || fs.statSync(LOG_FILE).size === 0) {
    fs.writeFileSync(LOG_FILE, HEADERS.join(",") + "\n", "utf8");
  }
};

systemLogEmitter.on(
  "log",
  ({ level = "INFO", event, message, meta = {} }) => {
    try {
      ensureFile();
      const row = [
        new Date().toISOString(),
        level,
        event,
        message,
        JSON.stringify(meta),
      ];
      fs.appendFileSync(LOG_FILE, row.map(csvEscape).join(",") + "\n", "utf8");
    } catch (err) {
      // Never let logging take the app down.
      console.error("Failed to write system log:", err);
    }
  }
);

/** Emit a system log entry (fire-and-forget). */
export const systemLog = ({ level, event, message, meta }) =>
  systemLogEmitter.emit("log", { level, event, message, meta });

export default systemLogEmitter;
