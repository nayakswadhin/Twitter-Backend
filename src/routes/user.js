import express from "express";
import { createUser, loginController, verifyOTP, verifySignupOTP } from "../controllers/userController.js";
const router = express.Router();

router.post("/signup", createUser);
router.post("/signin", loginController);
router.post("/verify", verifyOTP);
router.post("/verify-signup",verifySignupOTP)

export default router;
