const express = require("express");
const router = express.Router();

const {
  googleLogin,
  googleCallback,
  login,
  register,
  getUser,
} = require("../controllers/authController");

// 1. Google Login Endpoint
router.get("/google", googleLogin);

// 2. Google Callback Endpoint
router.get("/google/callback", googleCallback);

router.post("/login", login);

router.post("/register", register);

router.get("/me", getUser);

module.exports = router;
