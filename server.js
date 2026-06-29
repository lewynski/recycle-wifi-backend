const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
const API_VERSION = "2.1.0";
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  userId: { type: String, required: true, unique: true },
  points: { type: Number, default: 0, min: 0 },
  bottles: { type: Number, default: 0, min: 0 }
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
  status: { type: String, enum: ["active", "expired", "revoked"], default: "active" }
}, { timestamps: true });
voucherSchema.index({ userId: 1, code: 1 }, { unique: true });

const eventLogSchema = new mongoose.Schema({
  level: { type: String, enum: ["EVENT", "ERROR", "WARNING"], default: "EVENT" },
  source: { type: String, default: "Android App" },
  userId: { type: String, default: "" },
  event: { type: String, required: true },
  details: { type: String, default: "" }
}, { timestamps: true });

eventLogSchema.index({ createdAt: -1 });
eventLogSchema.index({ level: 1, createdAt: -1 });

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);
const Voucher = mongoose.model("Voucher", voucherSchema);
const EventLog = mongoose.model("EventLog", eventLogSchema);

function escapeRegex(value = "") {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeNonNegative(value, fallback = 0) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(0, Math.trunc(number));
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    database: mongoose.connection.readyState === 1 ? "connected" : "not_connected",
    apiVersion: API_VERSION,
    features: {
      userSearch: true,
      accountStats: true,
      voucherManagement: true,
      eventLogs: true
    }
  });
});

app.post("/api/users/login", async (req, res, next) => {
  try {
    const { fullName, email, userId, points = 0, bottles = 0 } = req.body;
    if (!fullName || !email || !userId) {
      return res.status(400).json({ message: "fullName, email, and userId are required" });
    }

    const user = await User.findOneAndUpdate(
      { email },
      {
        $set: { fullName, email, userId },
        $setOnInsert: {
          points: normalizeNonNegative(points),
          bottles: normalizeNonNegative(bottles)
        }
      },
      { new: true, upsert: true, setDefaultsOnInsert: true, runValidators: true }
    );

    res.json(user);
  } catch (error) {
    next(error);
  }
});

async function searchUsers(req, res, next) {
  try {
    const query = String(req.query.q || req.body?.q || req.body?.query || "").trim();
    const escaped = escapeRegex(query);
    const regex = { $regex: escaped, $options: "i" };

    // Use the native collection so accounts created by older app/backend
    // versions remain searchable even when they used legacy field names.
    const filter = query
      ? {
          $or: [
            { fullName: regex },
            { name: regex },
            { displayName: regex },
            { email: regex },
            { studentId: regex },
            { userId: regex },
            { machineUserId: regex }
          ]
        }
      : {};

    const rows = await User.collection
      .find(filter, {
        projection: {
          fullName: 1,
          name: 1,
          displayName: 1,
          email: 1,
          studentId: 1,
          userId: 1,
          machineUserId: 1,
          points: 1,
          bottles: 1,
          updatedAt: 1
        }
      })
      .sort({ updatedAt: -1, _id: -1 })
      .limit(25)
      .toArray();

    const users = rows.map((user) => ({
      fullName: user.fullName || user.name || user.displayName || "User",
      email: user.email || user.studentId || "",
      // Older records may not have a machine userId. The MongoDB id is a
      // stable fallback and is also accepted by the stats endpoint below.
      userId: user.userId || user.machineUserId || String(user._id),
      points: normalizeNonNegative(user.points),
      bottles: normalizeNonNegative(user.bottles),
      updatedAt: user.updatedAt || null
    }));

    res.json(users);
  } catch (error) {
    next(error);
  }
}

// GET is used by the Android app. POST and the /api/admin alias make the
// endpoint tolerant of older proxies and future admin-client integrations.
app.get("/api/users/search", searchUsers);
app.post("/api/users/search", searchUsers);
app.get("/api/admin/users/search", searchUsers);

app.post("/api/users/:userId/stats", async (req, res, next) => {
  try {
    const accountId = String(req.params.userId || "").trim();
    const points = normalizeNonNegative(req.body.points);
    const bottles = normalizeNonNegative(req.body.bottles);
    const identity = mongoose.Types.ObjectId.isValid(accountId)
      ? { $or: [{ userId: accountId }, { _id: new mongoose.Types.ObjectId(accountId) }] }
      : { userId: accountId };

    const user = await User.findOneAndUpdate(
      identity,
      { $set: { points, bottles } },
      { new: true, runValidators: true }
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
    const duration = normalizeNonNegative(minutes);
    const expiryValue = Number(expiry);
    if (!userId || !code || duration <= 0 || !Number.isFinite(expiryValue)) {
      return res.status(400).json({ message: "userId, code, positive minutes, and expiry are required" });
    }

    const voucher = await Voucher.findOneAndUpdate(
      { userId, code },
      { $set: { userId, code, minutes: duration, expiry: expiryValue, status } },
      { new: true, upsert: true, setDefaultsOnInsert: true, runValidators: true }
    );

    res.json(voucher);
  } catch (error) {
    next(error);
  }
});

app.get("/api/vouchers", async (req, res, next) => {
  try {
    const userId = String(req.query.userId || "").trim();
    if (!userId) return res.status(400).json({ message: "userId is required" });

    await Voucher.updateMany(
      { userId, status: "active", expiry: { $lte: Date.now() } },
      { $set: { status: "expired" } }
    );

    const vouchers = await Voucher.find({ userId }).sort({ createdAt: -1 }).limit(100);
    res.json(vouchers);
  } catch (error) {
    next(error);
  }
});

app.post("/api/vouchers/:code/revoke", async (req, res, next) => {
  try {
    const userId = String(req.body.userId || "").trim();
    if (!userId) return res.status(400).json({ message: "userId is required" });

    const voucher = await Voucher.findOneAndUpdate(
      { userId, code: req.params.code, status: { $ne: "revoked" } },
      { $set: { status: "revoked" } },
      { new: true, runValidators: true }
    );

    if (!voucher) return res.status(404).json({ message: "Voucher not found" });
    res.json(voucher);
  } catch (error) {
    next(error);
  }
});

app.post("/api/logs", async (req, res, next) => {
  try {
    const { level = "EVENT", source = "Android App", userId = "", event, details = "" } = req.body;
    if (!event) return res.status(400).json({ message: "event is required" });
    const log = await EventLog.create({ level, source, userId, event, details });
    res.status(201).json(log);
  } catch (error) {
    next(error);
  }
});

app.get("/api/logs", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 250);
    const level = String(req.query.level || "").trim().toUpperCase();
    const filter = ["EVENT", "ERROR", "WARNING"].includes(level) ? { level } : {};
    const logs = await EventLog.find(filter).sort({ createdAt: -1 }).limit(limit);
    res.json(logs);
  } catch (error) {
    next(error);
  }
});

app.delete("/api/logs", async (req, res, next) => {
  try {
    const result = await EventLog.deleteMany({});
    res.json({ message: "All logs cleared", deletedCount: result.deletedCount || 0 });
  } catch (error) {
    next(error);
  }
});

app.use(async (error, req, res, next) => {
  console.error(error);
  try {
    await EventLog.create({
      level: "ERROR",
      source: "Node.js Backend",
      userId: String(req.body?.userId || req.params?.userId || ""),
      event: `${req.method} ${req.originalUrl} failed`,
      details: error.message || String(error)
    });
  } catch (logError) {
    console.error("Could not save backend error log:", logError.message);
  }
  res.status(500).json({ message: "Server error", detail: error.message });
});

async function start() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("Missing MONGODB_URI in .env");

  await mongoose.connect(uri);
  const port = process.env.PORT || 3000;
  app.listen(port, async () => {
    console.log(`ARVIN API running at http://localhost:${port}`);
    try {
      await EventLog.create({
        level: "EVENT",
        source: "Node.js Backend",
        event: "Backend service started",
        details: `Listening on port ${port}`
      });
    } catch (error) {
      console.error("Could not save startup log:", error.message);
    }
  });
}

start().catch((error) => {
  console.error(error);
  process.exit(1);
});
