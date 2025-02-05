import express from "express";
const router = express.Router();

import {
  googleLogin,
  googleCallback,
  login,
  register,
  getUser,
} from "../controllers/authController.js";

// 1. Google Login Endpoint
router.get("/google", googleLogin);

// 2. Google Callback Endpoint
router.get("/google/callback", googleCallback);

router.post("/login", login);

router.post("/register", register);

router.get("/me", getUser);

export default router;
