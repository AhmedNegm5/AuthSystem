import express from "express";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";
import querystring from "querystring";
import cors from "cors";
import jwkToPem from "jwk-to-pem";
import mongoose from "mongoose";
import * as dotenv from "dotenv";
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  googleId: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  name: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

app.use(express.json());

// 1. Google Login Endpoint
app.get("/auth/google", (req, res) => {
  const googleAuthURL =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    querystring.stringify({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: `${process.env.BACKEND_URL}/auth/google/callback`,
      response_type: "code",
      scope: "openid profile email",
    });
  res.redirect(googleAuthURL);
});

// 2. Google Callback Endpoint
app.get("/auth/google/callback", async (req, res) => {
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
      let user = await User.findOne({ googleId });

      if (!user) {
        user = new User({ googleId, email, name });
        await user.save();
      } else {
        //optional, if you need to update the user information
        user.email = email;
        user.name = name;
        await user.save();
      }

      // Create a JWT for our application
      const ourToken = jwt.sign({ userId: googleId }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

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
});

// Minimal Protected Endpoint
app.get("/protected", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    res.json({ message: `Protected data for user ${decoded.userId}` });
  });
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
