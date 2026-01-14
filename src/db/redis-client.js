// redis-client.js
import Redis from "redis";

class RedisClient {
  constructor() {
    this.client = null;
    this.isConnected = false;
  }

  async connect() {
    if (this.client) return this.client;

    try {
      this.client = Redis.createClient({
        url: process.env.REDIS_URL,
        socket: {
          connectTimeout: 60000,
          reconnectStrategy: (retries) => {
            if (retries > 10) {
              console.log("Too many retries on Redis. Giving up.");
              return new Error("Too many retries");
            }
            return Math.min(retries * 100, 3000);
          },
        },
      });

      this.client.on("error", (err) => {
        console.error("Redis Client Error:", err);
        this.isConnected = false;
      });

      this.client.on("connect", () => {
        console.log("✅ Redis Client Connected");
        this.isConnected = true;
      });

      this.client.on("disconnect", () => {
        console.log("❌ Redis Client Disconnected");
        this.isConnected = false;
      });

      await this.client.connect();
      return this.client;
    } catch (error) {
      console.error("Failed to connect to Redis:", error);
      this.isConnected = false;
      return null;
    }
  }

  async get(key) {
    if (!this.isConnected) return null;
    try {
      const data = await this.client.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error("Redis get error:", error);
      return null;
    }
  }

  async set(key, data, ttlSeconds = 300) {
    if (!this.isConnected) return false;
    try {
      await this.client.setEx(key, ttlSeconds, JSON.stringify(data));
      return true;
    } catch (error) {
      console.error("Redis set error:", error);
      return false;
    }
  }

  async del(key) {
    if (!this.isConnected) return false;
    try {
      await this.client.del(key);
      return true;
    } catch (error) {
      console.error("Redis delete error:", error);
      return false;
    }
  }

  async keys(pattern) {
    if (!this.isConnected) return [];
    try {
      return await this.client.keys(pattern);
    } catch (error) {
      console.error("Redis keys error:", error);
      return [];
    }
  }

  async flushPattern(pattern) {
    if (!this.isConnected) return false;
    try {
      const keysToDelete = await this.keys(pattern);
      if (keysToDelete.length > 0) {
        await this.client.del(keysToDelete);
        console.log(
          `🗑️  Cleared ${keysToDelete.length} keys with pattern: ${pattern}`
        );
      }
      return true;
    } catch (error) {
      console.error("Redis flushPattern error:", error);
      return false;
    }
  }

  async healthCheck() {
    if (!this.isConnected) return false;
    try {
      await this.client.ping();
      return true;
    } catch (error) {
      console.error("Redis health check failed:", error);
      return false;
    }
  }
}

// Singleton instance
const redisClient = new RedisClient();
export default redisClient;
