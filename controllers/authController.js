import User from "../models/userModel.js";
import { generateToken, verifyToken } from "../utils/jwt.js";
import bcrypt from "bcryptjs";

const googleLogin = async (req, res) => {
  const { googleId, email, name } = req.body;

  if (!googleId || !email || !name) {
    return res
      .status(400)
      .json({ error: "Google ID, email, and name are required" });
  }

  try {
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ googleId, email, name });
      await user.save();
    } else if (!user.googleId) {
      user.googleId = googleId;
      await user.save();
    }

    const token = generateToken(user._id);
    res.status(200).json({ token });
  } catch {
    res.status(500).json({ error: "Google login failed" });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!user.password) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = generateToken(user._id);
    res.status(200).json({ token });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
};

const register = async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res
      .status(400)
      .json({ error: "Email, name, and password are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword, name });
    await newUser.save();

    const token = generateToken(newUser._id);
    res.status(201).json({ token });
  } catch {
    res.status(500).json({ error: "Registration failed" });
  }
};

// get user info

const getUser = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyToken(token);
    const user = await User.findById(decoded.userId).select("-password");
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ error: "User info not found" });
  }
};

export { googleLogin, login, register, getUser };
