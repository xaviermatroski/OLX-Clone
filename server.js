const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB Atlas
const mongoURI = "mongodb+srv://admin-olx-for-iitrpr:A6cRX3doy0aFgqdV@olx-for-iitrpr.vuprw.mongodb.net/?retryWrites=true&w=majority&appName=Olx-for-IITRPR";
mongoose
  .connect(mongoURI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Define User Schema & Model
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  registrationDate: { type: Date, default: Date.now }
});

const User = mongoose.model("login", UserSchema);

// API Route for Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      console.log("Login successful");
      res.json({ 
        message: "Login successful", 
        user: { 
          name: user.name, 
          email: user.email, 
          registrationDate: user.registrationDate 
        } 
      });
    } else {
      console.log("Invalid credentials");
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (err) {
    console.log("Server error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// API Route for Sign Up
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ 
      name, 
      email, 
      password: hashedPassword,
      registrationDate: new Date()
    });
    await newUser.save();

    res.status(201).json({ 
      message: "User created successfully", 
      user: { 
        name: newUser.name, 
        email: newUser.email, 
        registrationDate: newUser.registrationDate 
      } 
    });
  } catch (err) {
    console.log("Server error", err);
    res.status(500).json({ error: "Server error" });
  }
});

// API Route to Fetch All Users
app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
