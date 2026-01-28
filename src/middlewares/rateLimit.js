const rateLimit = require("express-rate-limit");
const pool = require("../db");

module.exports = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,

  handler: async (req, res) => {
    const ip = req.ip;

    try {
      await pool.query(
        `INSERT IGNORE INTO banned_ips (ip_address, reason)
         VALUES (?, ?)`,
        [ip, "RATE_LIMIT_EXCEEDED"]
      );
    } catch (err) {
      console.error("IP ban insert error:", err);
    }

    return res.status(429).json({
      ok: false,
      message: "Too many attempts. IP temporarily blocked."
    });
  }
});