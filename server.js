const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = 3000;
const JWT_SECRET = "voicecall_jwt_secret_key_2024";
const DB_FILE = path.join(__dirname, "users.json");

function loadDB() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify([]));
  return JSON.parse(fs.readFileSync(DB_FILE));
}
function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
  const users = loadDB();
  if (users.find((u) => u.email === email.toLowerCase()))
    return res.status(409).json({ error: "Email already registered" });
  const hashed = await bcrypt.hash(password, 12);
  const user = { id: Date.now().toString(), email: email.toLowerCase(), password: hashed, createdAt: new Date().toISOString() };
  users.push(user);
  saveDB(users);
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  const users = loadDB();
  const user = users.find((u) => u.email === email.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.get("/api/users", authMiddleware, (req, res) => {
  const users = loadDB();
  res.json(users.map((u) => ({ id: u.id, email: u.email })).filter((u) => u.id !== req.user.id));
});

app.get("/api/me", authMiddleware, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email });
});

const onlineUsers = {};
const emailToSocket = {};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication error"));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  const { email } = socket.user;
  onlineUsers[socket.id] = email;
  emailToSocket[email] = socket.id;
  io.emit("online-users", Object.values(onlineUsers));

  socket.on("call-user", ({ targetEmail, offer }) => {
    const targetSocket = emailToSocket[targetEmail];
    if (!targetSocket) return socket.emit("call-failed", { reason: "User is offline" });
    io.to(targetSocket).emit("incoming-call", { from: email, offer });
  });

  socket.on("call-answer", ({ targetEmail, answer }) => {
    const targetSocket = emailToSocket[targetEmail];
    if (targetSocket) io.to(targetSocket).emit("call-answered", { from: email, answer });
  });

  socket.on("ice-candidate", ({ targetEmail, candidate }) => {
    const targetSocket = emailToSocket[targetEmail];
    if (targetSocket) io.to(targetSocket).emit("ice-candidate", { from: email, candidate });
  });

  socket.on("call-reject", ({ targetEmail }) => {
    const targetSocket = emailToSocket[targetEmail];
    if (targetSocket) io.to(targetSocket).emit("call-rejected", { from: email });
  });

  socket.on("call-end", ({ targetEmail }) => {
    const targetSocket = emailToSocket[targetEmail];
    if (targetSocket) io.to(targetSocket).emit("call-ended", { from: email });
  });

  socket.on("disconnect", () => {
    delete onlineUsers[socket.id];
    delete emailToSocket[email];
    io.emit("online-users", Object.values(onlineUsers));
  });
});

server.listen(PORT, () => console.log(`\n VoiceCall server running at http://localhost:${PORT}\n`));
