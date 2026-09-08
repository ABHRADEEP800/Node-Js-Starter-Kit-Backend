// Dev-only: start an in-memory MongoDB, then run the real server.
// Use: `node scripts/dev-mongo.js` (or wire into npm run dev).
import("mongodb-memory-server").then(async ({ MongoMemoryServer }) => {
  const mongod = await MongoMemoryServer.create();
  const uri = mongod.getUri();
  process.env.MONGODB_URL = uri;
  console.log("[dev-mongo] in-memory MongoDB at", uri);
  // Import server AFTER setting env so dotenv inside server.js sees it
  await import("../src/server.js");
  // Stash so a Ctrl-C cleans up.
  process.on("SIGINT", async () => {
    await mongod.stop();
    process.exit(0);
  });
  process.on("SIGTERM", async () => {
    await mongod.stop();
    process.exit(0);
  });
});
