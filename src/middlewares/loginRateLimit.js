const rateLimit = require("express-rate-limit");
const pool = require("../db");

const loginRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,

  handler: async (req, res) => {
    try {
      const ip = req.ip;
      await pool.query(
        `INSERT INTO banned_ips (ip_address, reason, banned_until)
         VALUES (?, 'RATE_LIMIT', DATE_ADD(NOW(), INTERVAL 10 MINUTE))
         ON DUPLICATE KEY UPDATE
           reason = 'RATE_LIMIT',
           banned_until = DATE_ADD(NOW(), INTERVAL 10 MINUTE)`,
        [ip]
      );

      // 로그도 남기고 싶으면 여기에 auth_logs INSERT 추가해도 됨
    } catch (e) {
      console.error(e);
    }

    return res
      .status(429)
      .json({ ok: false, message: "Too many login attempts. Try again later." });
  }
});

module.exports = loginRateLimiter;