import mongoose from "mongoose";
import redisClient from "../db/redis-client.js";
import { systemLog } from "../events/systemLog.events.js";

const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URL}`
    );
    console.log(
      `\nMongoDB connected !! DB HOST: ${connectionInstance.connection.host}, DB NAME: ${connectionInstance.connection.name}`
    );
    systemLog({
      level: "INFO",
      event: "DB_CONNECTED",
      message: "MongoDB connection established",
      meta: {
        host: connectionInstance.connection.host,
        name: connectionInstance.connection.name,
      },
    });
    redisClient.connect(); // Connect to Redis after MongoDB is connected
  } catch (error) {
    console.error("MongoDB connection failed:", error);
    systemLog({
      level: "ERROR",
      event: "DB_CONNECTION_FAILED",
      message: error.message,
    });
    process.exit(1); // Exit the process with failure
  }
};

export default connectDB;
