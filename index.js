import express from "express";
import { MongoClient } from "mongodb";
import userRoutes from "./src/routes/user.js";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import morgan from "morgan";

const app = express();
const port = 8080; // Directly using the port number

let db;

// Replace with your actual MongoDB connection string
const mongoUri = "mongodb+srv://nayakswadhin25:1111111q@cluster0.3q077.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"; // e.g., "mongodb://localhost:27017/mydatabase"
const corsOrigin = "http://localhost:5173"; // e.g., "http://localhost:3000"

async function startApp() {
  try {
    app.use(helmet()); // Protect with Helmet
    app.use(morgan('dev')); // Logging middleware
    app.use(cors({ origin: corsOrigin, credentials: true })); // Using direct value for CORS
    app.use(express.json());

    // Rate limiting
    const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
    app.use(limiter);

    // MongoDB Connection
    const mongo = await MongoClient.connect(mongoUri, {
    });

    db = mongo.db();
    app.set("db", db);

    app.get("/health", (req, res) => {
      res.status(200).json({ message: "The health is Good." });
    });

    app.use("/user", userRoutes);

    // Error Handling Middleware
    app.use((err, req, res, next) => {
      console.error(err.stack);
      res.status(500).json({ message: "Something went wrong!" });
    });

    app.listen(port, () => {
      console.log(`APP is listening at http://localhost:${port}/`);
    });
  } catch (error) {
    console.error("MongoDB Connection Error:", error);
  }
}

startApp();
