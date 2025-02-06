import express from "express";
const router = express.Router();

import {
  googleLogin,
  login,
  register,
  getUser,
} from "../controllers/authController.js";

router.post("/google", googleLogin);

router.post("/login", login);

router.post("/register", register);

router.get("/me", getUser);

export default router;
