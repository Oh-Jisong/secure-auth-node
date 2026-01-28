const pool = require("../db");

module.exports = async function ipBlock(req, res, next) {
  const ip = req.ip;

  const [rows] = await pool.query(
    "SELECT id FROM banned_ips WHERE ip_address = ? LIMIT 1",
    [ip]
  );

  if (rows.length > 0) {
    return res.status(403).json({
      ok: false,
      message: "Your IP has been blocked"
    });
  }

  next();
};