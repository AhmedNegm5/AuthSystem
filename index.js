import express from "express";
import * as dotenv from "dotenv";
import connectDB from "./config/connec";
const authRoute = require("./routes/authRoute");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// MongoDB Connection
connectDB();

app.use(express.json());
app.use("/auth", authRoute);

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
