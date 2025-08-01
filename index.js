import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import mysql from "mysql2";
import dotenv from "dotenv";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { dirname } from "path";

// Crypto simulation for Kyber + AES
const simulateKyberAesDecrypt = (ciphertext) => {
  try {
    const match = ciphertext.match(/^🔒\[[a-fA-F0-9]{32}\](.+)$/);
    if (!match) return null;
    const base64 = match[1];
    return decodeURIComponent(escape(Buffer.from(base64, "base64").toString()));
  } catch (err) {
    console.error("Decryption error:", err);
    return null;
  }
};

// App Setup
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
const port = process.env.PORT || 3001;

app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "*", // fallback to '*' if not defined
    credentials: true,
  })
);
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: fs.readFileSync(process.env.SSL_CA),
  },
});

db.query("SELECT 1", (err) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Connected to MySQL database.");
  }
});

// File Uploads
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use("/uploads", express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${unique}${ext}`);
  },
});
const upload = multer({ storage });

// --- registration ---
app.post("/register", (req, res) => {
  const { username, password, email, phone } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  const sql =
    "INSERT INTO users (username, password, email, phone, otp) VALUES (?, ?, ?, ?, ?)";
  db.query(sql, [username, password, email, phone, otp], (err) => {
    if (err) {
      console.error("Registration error:", err);
      if (err.code === "ER_DUP_ENTRY")
        return res
          .status(409)
          .json({ error: "Username or email already exists" });
      return res.status(500).json({ error: "Registration failed" });
    }
    return res.status(200).json({ message: "User registered", otp });
  });
});

// --- login ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const u = simulateKyberAesDecrypt(username);
  const p = simulateKyberAesDecrypt(password);

  const sql = "SELECT * FROM users";
  db.query(sql, [], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    const user = results.find(
      (row) =>
        simulateKyberAesDecrypt(row.username) === u &&
        simulateKyberAesDecrypt(row.password) === p
    );

    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    db.query(
      "UPDATE users SET otp = ? WHERE id = ?",
      [otp, user.id],
      (err2) => {
        if (err2)
          return res.status(500).json({ error: "Failed to update OTP" });
        return res
          .status(200)
          .json({ message: "OTP sent", username: user.username, otp });
      }
    );
  });
});

// --- Verify OTP ---
app.post("/verify-otp", (req, res) => {
  const { username, otp } = req.body;
  const u = simulateKyberAesDecrypt(username);

  const sql = "SELECT * FROM users";
  db.query(sql, [], (err, results) => {
    if (err) return res.status(500).json({ error: "Server error" });

    const user = results.find(
      (row) => simulateKyberAesDecrypt(row.username) === u && row.otp === otp
    );

    if (!user) return res.status(401).json({ error: "Invalid OTP" });

    db.query("UPDATE users SET otp = NULL WHERE id = ?", [user.id]);
    return res.status(200).json({ message: "OTP verified" });
  });
});

// --- resend OTP ---
app.post("/resend-otp", (req, res) => {
  const u = simulateKyberAesDecrypt(req.body.username);
  if (!u) return res.status(400).json({ error: "Username is required" });

  const newOtp = Math.floor(100000 + Math.random() * 900000).toString();

  const sql = "SELECT * FROM users";
  db.query(sql, [], (err, results) => {
    if (err) return res.status(500).json({ error: "Server error" });

    const user = results.find(
      (row) => simulateKyberAesDecrypt(row.username) === u
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    db.query(
      "UPDATE users SET otp = ? WHERE id = ?",
      [newOtp, user.id],
      (err2) => {
        if (err2)
          return res.status(500).json({ error: "Failed to update OTP" });
        res.status(200).json({ message: "OTP resent", otp: newOtp });
      }
    );
  });
});

// --- upload endpoint ---
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const fileUrl = `${process.env.API_BASE_URL}/uploads/${req.file.filename}`;
  res.json({ url: fileUrl });
});

// --- users for chat list ---
app.get("/users", (req, res) => {
  db.query("SELECT username FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch users" });
    res.status(200).json(results);
  });
});

// --- messages (private and group) ---
app.get("/messages", (req, res) => {
  const { from, to, groupId } = req.query;

  let sql, params;

  if (from === "Hacker") {
    sql = "SELECT * FROM messages ORDER BY timestamp ASC";
    params = [];
  } else if (groupId) {
    sql = "SELECT * FROM messages WHERE group_id = ? ORDER BY timestamp ASC";
    params = [groupId];
  } else if (from && to) {
    sql = `
      SELECT * FROM messages
      WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
      ORDER BY timestamp ASC
    `;
    params = [from, to, to, from];
  } else {
    return res.status(400).json({ error: "Missing from/to or groupId" });
  }

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch messages" });
    res.status(200).json(results);
  });
});

// --- send message (private or group) ---
app.post("/send", (req, res) => {
  const { from, to, message, groupId } = req.body;

  if (!from || !message)
    return res.status(400).json({ error: "Missing required fields" });

  if (groupId) {
    db.query(
      "INSERT INTO messages (sender, message, group_id) VALUES (?, ?, ?)",
      [from, message, groupId],
      (err) => {
        if (err)
          return res
            .status(500)
            .json({ error: "Failed to send group message" });
        return res.status(200).json({ message: "Group message sent" });
      }
    );
  } else if (to) {
    db.query(
      "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
      [from, to, message],
      (err) => {
        if (err)
          return res.status(500).json({ error: "Failed to send message" });
        res.status(200).json({ message: "Message sent" });
      }
    );
  } else {
    return res.status(400).json({ error: "Missing 'to' or 'groupId'" });
  }
});

// --- create group ---
app.post("/groups/create", (req, res) => {
  const { name, members, created_by } = req.body;

  db.query(
    "INSERT INTO chat_groups (name, created_by) VALUES (?, ?)",
    [name, created_by],
    (err, result) => {
      if (err) return res.status(500).json({ error: "Failed to create group" });

      const groupId = result.insertId;
      const values = members.map((member) => [groupId, member]);

      db.query(
        "INSERT INTO group_members (group_id, username) VALUES ?",
        [values],
        (err2) => {
          if (err2)
            return res.status(500).json({ error: "Failed to add members" });
          res.status(200).json({ message: "Group created", groupId });
        }
      );
    }
  );
});

// --- GET groups for a user ---
app.get("/groups", (req, res) => {
  const { member } = req.query;
  if (!member) return res.status(400).json({ error: "Missing member" });

  const sql = `
    SELECT cg.id, cg.name
    FROM chat_groups cg
    JOIN group_members gm ON cg.id = gm.group_id
    WHERE gm.username = ?
  `;

  db.query(sql, [member], (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch groups" });
    res.status(200).json(results);
  });
});

// --- start server ---
app.listen(port, () => {
  console.log(`Server running at ${process.env.API_BASE_URL}`);
});
