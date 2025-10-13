
// app.js
// INTENTIONALLY INSECURE SAMPLE FOR SAST TESTING ONLY.
// This file contains multiple bad practices on purpose.

// Dependencies
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// ===== 1) Hardcoded secrets / credentials (SAST: hardcoded secret) =====
const DB_USER = "root";                 // hardcoded credential
const DB_PASS = "supersecretpassword";  // hardcoded credential
const JWT_SECRET = "secret";            // weak, hardcoded secret

// Fake DB layer to avoid needing a real database.
const db = {
  query(sql) {
    // Intentionally naive to trigger SQLi checks.
    console.log("[FAKE DB] Executing SQL:", sql);
    return Promise.resolve([{ ok: true }]);
  },
};

// ===== 2) SQL Injection (SAST: tainted input in SQL) =====
app.get("/user", async (req, res) => {
  const name = req.query.name; 
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  try {
    const rows = await db.query(sql);
    res.json({ sql, rows });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ===== 3) Command Injection (SAST: exec with unsanitized input) =====
app.get("/run", (req, res) => {
  const cmd = req.query.cmd; 
  const allowedCommands = ["ls", "pwd", "echo"];
  if (allowedCommands.includes(cmd)) {
    exec(cmd, (err, stdout, stderr) => {
      if (err) return res.status(500).send(String(err));
      res.type("text").send(stdout || stderr);
    });
  } else {
    res.status(400).send("Invalid command");
  }
});

// ===== 4) eval() of user input (SAST: dynamic code execution) =====
app.post("/eval", (req, res) => {
  const code = req.body && req.body.code; 
  try {
    const out = eval(code);
    res.json({ result: out });
  } catch (e) {
    res.status(400).json({ error: String(e) });
  }
});

// ===== 5) Path Traversal (SAST: file read with user-controlled path) =====
app.get("/read", (req, res) => {
  const file = req.query.file; 
  const target = path.join(__dirname, "data", file);
  fs.readFile(target, "utf8", (err, content) => {
    if (err) return res.status(404).send("Not found");
    res.type("text").send(content);
  });
});

// ===== 6) Weak crypto / MD5 (SAST: weak hash) =====
app.post("/hash", (req, res) => {
  const password = (req.body && req.body.password) || "";
  const md5 = crypto.createHash("md5").update(password).digest("hex");
  res.json({ md5 });
});

// ===== 7) Predictable tokens (SAST: insecure randomness) =====
app.get("/token", (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.json({ token });
});

// ===== 8) Weak JWT signing (SAST: hardcoded/weak secret; no exp) =====
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === "admin" && password === "admin") {
    const t = jwt.sign({ user: username, role: "admin" }, JWT_SECRET);
    return res.json({ token: t });
  }
  res.status(401).json({ error: "invalid credentials" });
});

// ===== 9) Information leakage (SAST: verbose error responses) =====
app.get("/debug", (req, res) => {
  try {
    JSON.parse("not-json");
  } catch (e) {
    res.status(500).send(e.stack);
  }
});

// ===== 10) Insecure HTTPS handling (SAST: disable TLS verification) =====
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; 

// Minimal server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Insecure sample app listening on http://localhost:${PORT}`);
  console.log("⚠️ This server is intentionally vulnerable. Do NOT expose it.");
});
