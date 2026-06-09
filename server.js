const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, default: "" },
  userId: { type: String, required: true, unique: true },
  points: { type: Number, default: 0 },
  bottles: { type: Number, default: 0 }
}, { timestamps: true });

const transactionSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  event: { type: String, required: true }
}, { timestamps: true });

const voucherSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  code: { type: String, required: true },
  minutes: { type: Number, required: true },
  expiry: { type: Number, required: true },
  status: { type: String, enum: ["active", "expired"], default: "active" }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const Voucher = mongoose.model("Voucher", voucherSchema);

app.get("/api/health", (req, res) => {
  res.json({ ok: true, database: mongoose.connection.readyState === 1 ? "connected" : "not_connected" });
});

function safeUser(user) {
  const data = user.toObject ? user.toObject() : { ...user };
  delete data.passwordHash;
  return data;
}

app.post("/api/users/register", async (req, res, next) => {
  try {
    const { fullName, email, password, userId, points = 0, bottles = 0 } = req.body;
    if (!fullName || !email || !password || !userId) {
      return res.status(400).json({ message: "fullName, email, password, and userId are required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: "Account already exists. Please login instead." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ fullName, email, passwordHash, userId, points, bottles });
    res.status(201).json(safeUser(user));
  } catch (error) {
    next(error);
  }
});

app.post("/api/users/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "Account not found. Please create an account first." });

    // Legacy support: older demo accounts created before the separated-login revision had no password.
    // The first successful login attempt sets the password so existing MongoDB records are not lost.
    if (!user.passwordHash) {
      user.passwordHash = await bcrypt.hash(password, 10);
      await user.save();
      return res.json(safeUser(user));
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(401).json({ message: "Incorrect password" });

    res.json(safeUser(user));
  } catch (error) {
    next(error);
  }
});

app.post("/api/users/:userId/stats", async (req, res, next) => {
  try {
    const { points = 0, bottles = 0 } = req.body;
    const user = await User.findOneAndUpdate(
      { userId: req.params.userId },
      { $set: { points, bottles } },
      { new: true }
    );

    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (error) {
    next(error);
  }
});

app.post("/api/transactions", async (req, res, next) => {
  try {
    const { userId, event } = req.body;
    if (!userId || !event) return res.status(400).json({ message: "userId and event are required" });
    const transaction = await Transaction.create({ userId, event });
    res.status(201).json(transaction);
  } catch (error) {
    next(error);
  }
});

app.get("/api/transactions/:userId", async (req, res, next) => {
  try {
    const rows = await Transaction.find({ userId: req.params.userId }).sort({ createdAt: -1 }).limit(100);
    res.json(rows);
  } catch (error) {
    next(error);
  }
});

app.post("/api/vouchers", async (req, res, next) => {
  try {
    const { userId, code, minutes, expiry, status = "active" } = req.body;
    if (!userId || !code || !minutes || !expiry) {
      return res.status(400).json({ message: "userId, code, minutes, and expiry are required" });
    }

    const voucher = await Voucher.findOneAndUpdate(
      { userId, code },
      { $set: { userId, code, minutes, expiry, status } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    res.json(voucher);
  } catch (error) {
    next(error);
  }
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ message: "Server error", detail: error.message });
});

async function start() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("Missing MONGODB_URI in .env");

  await mongoose.connect(uri);
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`ARVIN API running at http://localhost:${port}`));
}

start().catch((error) => {
  console.error(error);
  process.exit(1);
});
