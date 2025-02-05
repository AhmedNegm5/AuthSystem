import fetch from "node-fetch";
import User from "../models/userModel";
import { generateToken, verifyToken } from "../utils/jwt";
import querystring from "querystring";
import jwkToPem from "jwk-to-pem";
import bcrypt from "bcryptjs";

// 1. Google Login Endpoint
exports.googleLogin = (req, res) => {
  const googleAuthURL =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    querystring.stringify({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: `${process.env.BACKEND_URL}/auth/google/callback`,
      response_type: "code",
      scope: "openid profile email",
    });
  res.redirect(googleAuthURL);
};

// 2. Google Callback Endpoint
exports.googleCallback = async (req, res) => {
  const { code } = req.query;

  try {
    // Exchange code for tokens
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: querystring.stringify({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.BACKEND_URL}/auth/google/callback`,
        grant_type: "authorization_code",
      }),
    });

    const tokenData = await tokenResponse.json();
    const { id_token } = tokenData;

    // -------------------------------------------------------------
    // SECURITY:  VERIFY THE ID TOKEN!!!  (Critical!)
    // -------------------------------------------------------------
    try {
      // 1. Get Google's Public Keys (JWKS)
      const jwksResponse = await fetch(
        "https://www.googleapis.com/oauth2/v3/certs"
      );
      const jwks = await jwksResponse.json();

      // 2. Decode the ID token (without verification, initially) to get the 'kid' (Key ID)
      const decodedIdToken = jwt.decode(id_token, { complete: true });
      const kid = decodedIdToken?.header?.kid;

      // 3. Find the matching key from the JWKS based on the 'kid'
      const key = jwks.keys.find((k) => k.kid === kid);
      if (!key) {
        throw new Error("Key not found in JWKS");
      }

      // 4. Convert the key to PEM format
      const pem = jwkToPem(key); //using only the modulus part

      // 5. Verify the ID token using the PEM key
      const verifiedToken = jwt.verify(id_token, pem, {
        algorithms: ["RS256"],
      });
      const googleId = verifiedToken.sub;

      // Extract User info (email, name) from the verified token
      const email = verifiedToken.email;
      const name = verifiedToken.name;

      // *****************************************************
      // At this point the Id token from Google is trusted    *
      // You can use it to build your user's session and JWT  *
      // *****************************************************

      // Create/Update User in MongoDB
      let user = await User.findOne({ email });
      if (!user) {
        user = new User({ googleId, email, name });
        await user.save();
      } else {
        if (!user.googleId) {
          user.googleId = googleId;
          await user.save();
        }
      }

      // Create a JWT for our application
      const ourToken = generateToken(user._id);

      // Redirect to frontend with our token
      res.json({ token: ourToken });
    } catch (verificationError) {
      console.error("ID token verification error:", verificationError);
      return res.status(400).json({ error: "Invalid ID token" });
    }
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ error: "Authentication failed" });
  }
};

exports.login = async (req, res) => {
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

exports.register = async (req, res) => {
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
exports.getUser = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = verifyToken(token);
    const user = await User.findById(decoded.userId).select("-password");
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ error: "User info not found" });
  }
};
