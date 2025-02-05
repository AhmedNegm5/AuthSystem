import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  googleId: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  name: { type: String },
});

const User = mongoose.model("User", userSchema);

export default User;
