import express from "express";
import { MongoClient } from "mongodb";
import userRoutes from "./src/routes/user.js";
import cors from "cors";
import "dotenv/config";

const app = express();
const port = 8080;

async function startApp() {
  try {
    app.use(
      cors({
        origin: "http://localhost:5173",
        optionsSuccessStatus: 200,
        credentials: true,
      })
    );
    app.use(express.json());
    const mongo = await MongoClient.connect(
      "mongodb+srv://nayakswadhin25:1111111q@cluster0.pbbcb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    );

    app.set("db", mongo.db());

    app.get("/health", (req, res) => {
      res.status(200).json({ message: "The health is Good." });
    });

    app.use("/user", userRoutes);

    app.listen(port, () => {
      console.log(`APP is listening at http://localhost:${port}/`);
    });
  } catch (error) {
    console.error("MongoDB Connection Error:", error);
  }
}

startApp();
