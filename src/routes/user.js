import express from "express";
import { createUser, loginController } from "../controllers/userController.js";
const router = express.Router();

router.post("/signup", createUser);
router.post("/signin", loginController);

export default router;
