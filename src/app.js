require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const pool = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");

const ipBlock = require("./middleware/ipBlock");
const rateLimiter = require("./middleware/rateLimit");

const app = express();

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.use(ipBlock);     // DB 차단 먼저
app.use(rateLimiter); // 그 다음 rate limit


app.get("/health", (req, res) => {
  res.json({ ok: true, message: "secure-auth server running" });
});

app.use("/auth", authRoutes);

app.get("/db/ping", async (req, res) => {
  const [rows] = await pool.query("SELECT 1 AS ok");
  res.json({ db: "ok", result: rows[0] });
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});

app.use("/user", userRoutes);


const adminRoutes = require("./routes/adminRoutes");
app.use("/admin", adminRoutes);

app.set("trust proxy", true);